# ============================================================
# session_manager.py
# All session creation, validation, and termination logic
# Keeps views.py clean
# ============================================================

import hashlib
from django.utils import timezone
from datetime import timedelta

from .models import (
    UserProfile, SecureSession, SessionActivityLog
)
from .crypto import (
    generate_session_token,
    sign_session_token,
    verify_session_token,
    generate_session_fingerprint,
    deserialize_ecc_private_key,
    deserialize_ecc_public_key,
    wrap_private_key,      
    unwrap_private_key,    
)

# Session timeout — 30 minutes of inactivity
SESSION_TIMEOUT_MINUTES = 30


def hash_token(token: str) -> str:
    # Hash the raw session token before storing in DB
    # Same reason we hash passwords:
    # if DB is breached, tokens are useless
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def get_device_label(user_agent: str) -> str:
    # Extract a human readable device label from user agent string
    ua = user_agent.lower()
    if 'mobile' in ua or 'android' in ua:
        device = 'Mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        device = 'Tablet'
    else:
        device = 'Desktop'

    if 'chrome' in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua:
        browser = 'Safari'
    elif 'edge' in ua:
        browser = 'Edge'
    else:
        browser = 'Browser'

    return f"{device} / {browser}"


def create_secure_session(user: UserProfile, request) -> str:
    # Create a new secure session for a user after successful 2FA
    # Returns the raw session token to store in Django session
    #
    # Steps:
    # 1. Terminate any existing active sessions (prevent concurrent)
    # 2. Generate random token
    # 3. Sign token with user's ECC private key
    # 4. Store token hash + signature in DB
    # 5. Return raw token for Django session storage

    ip         = request.META.get('REMOTE_ADDR', '')
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    fingerprint = generate_session_fingerprint(ip, user_agent)

    # ------------------------------------------------
    # Terminate all existing active sessions for this user
    # Prevents someone from being logged in from 2 places
    # ------------------------------------------------
    existing = SecureSession.objects.filter(
        user=user, is_active=True
    )
    if existing.exists():
        # Log concurrent session termination
        SessionActivityLog.objects.create(
            user       = user,
            event      = 'concurrent',
            ip_address = ip,
            user_agent = user_agent,
            note       = f'Previous session terminated on new login'
        )
        existing.update(is_active=False)

    # ------------------------------------------------
    # Generate new session token
    # ------------------------------------------------
    raw_token = generate_session_token()
    # e.g. "a3f8c2d1e9b7..." — 64 hex chars

    # ------------------------------------------------
    # Sign token with user's ECC private key
    # Private key is in session (decrypted during login)
    # ------------------------------------------------
    ecc_priv_str = request.session.get('ecc_private_key', '')
    signature_str = ''

    if ecc_priv_str:
        ecc_priv      = deserialize_ecc_private_key(ecc_priv_str)
        signature_str = sign_session_token(raw_token, ecc_priv)

    # ------------------------------------------------
    # Store hashed token + signature in DB
    # ------------------------------------------------
    SecureSession.objects.create(
        user            = user,
        token_hash      = hash_token(raw_token),
        token_signature = signature_str,
        fingerprint     = fingerprint,
        ip_address      = ip,
        user_agent      = user_agent,
        device_label    = get_device_label(user_agent),
        expires_at      = timezone.now() + timedelta(
                              minutes=SESSION_TIMEOUT_MINUTES
                          ),
        is_active       = True,
    )

    # ------------------------------------------------
    # Log the login event
    # ------------------------------------------------
    SessionActivityLog.objects.create(
        user       = user,
        event      = 'login',
        ip_address = ip,
        user_agent = user_agent,
        note       = f'Login from {get_device_label(user_agent)}'
    )

    return raw_token


def validate_session(request) -> tuple:
    # Validate the current request's session
    # Returns (user, secure_session) if valid
    # Returns (None, None) if invalid/expired
    #
    # Checks:
    # 1. Token exists in Django session
    # 2. Token hash exists in DB
    # 3. Session not expired
    # 4. Session is active
    # 5. Fingerprint matches (anti-hijacking)
    # 6. ECC signature is valid

    raw_token = request.session.get('session_token')
    if not raw_token:
        return None, None

    token_hash = hash_token(raw_token)

    try:
        secure_session = SecureSession.objects.select_related(
            'user'
        ).get(token_hash=token_hash, is_active=True)
    except SecureSession.DoesNotExist:
        return None, None

    user = secure_session.user

    # ------------------------------------------------
    # Check expiry
    # ------------------------------------------------
    if timezone.now() > secure_session.expires_at:
        secure_session.is_active = False
        secure_session.save()
        SessionActivityLog.objects.create(
            user       = user,
            event      = 'expired',
            ip_address = request.META.get('REMOTE_ADDR', ''),
            note       = 'Session expired due to inactivity'
        )
        return None, None

    # ------------------------------------------------
    # Check fingerprint — detect session hijacking
    # ------------------------------------------------
    ip         = request.META.get('REMOTE_ADDR', '')
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    current_fp = generate_session_fingerprint(ip, user_agent)

    if current_fp != secure_session.fingerprint:
        # Fingerprint mismatch — possible session hijacking
        secure_session.is_active = False
        secure_session.save()
        SessionActivityLog.objects.create(
            user       = user,
            event      = 'hijack',
            ip_address = ip,
            user_agent = user_agent,
            note       = (
                f'Fingerprint mismatch. '
                f'Expected: {secure_session.fingerprint[:16]}... '
                f'Got: {current_fp[:16]}...'
            )
        )
        return None, None

    # ------------------------------------------------
    # Verify ECC signature if present
    # ------------------------------------------------
    if secure_session.token_signature:
        try:
            ecc_pub = deserialize_ecc_public_key(user.ecc_public_key)
            sig_valid = verify_session_token(
                raw_token,
                secure_session.token_signature,
                ecc_pub
            )
            if not sig_valid:
                # Invalid signature — token may be forged
                secure_session.is_active = False
                secure_session.save()
                SessionActivityLog.objects.create(
                    user       = user,
                    event      = 'invalid_token',
                    ip_address = ip,
                    note       = 'ECC signature verification failed'
                )
                return None, None
        except Exception:
            pass
        # If ECC verification fails with exception we still
        # allow session — signature is a bonus security layer

    # ------------------------------------------------
    # All checks passed — refresh expiry (sliding window)
    # ------------------------------------------------
    secure_session.last_activity = timezone.now()
    secure_session.expires_at    = timezone.now() + timedelta(
        minutes=SESSION_TIMEOUT_MINUTES
    )
    secure_session.save(update_fields=['last_activity', 'expires_at'])

    return user, secure_session


def terminate_session(request):
    # Terminate the current session cleanly
    raw_token = request.session.get('session_token')

    if raw_token:
        token_hash = hash_token(raw_token)
        try:
            secure_session = SecureSession.objects.get(
                token_hash=token_hash
            )
            user = secure_session.user
            secure_session.is_active = False
            secure_session.save()

            SessionActivityLog.objects.create(
                user       = user,
                event      = 'logout',
                ip_address = request.META.get('REMOTE_ADDR', ''),
                note       = 'User logged out'
            )
        except SecureSession.DoesNotExist:
            pass

    # Clear entire Django session
    request.session.flush()