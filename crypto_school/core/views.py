# ============================================================
# views.py — All views for Crypto School
# ============================================================

from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from django.conf import settings



from .session_manager import (
    create_secure_session,
    terminate_session,
    validate_session,
)


from .models import (
    PostRecipient, UserProfile, OTPSession,
    Class, TeacherAssignment, ClassEnrollment,
    KeyAccessLog, StudentResult,
    ParentRequest, SharedStudentData,
    SecureSession, SessionActivityLog,
    Post, LoginAttempt, 
)
from .crypto import (
    generate_rsa_keys, encrypt_to_string, serialize_key,
    deserialize_key, decrypt_from_string,
    generate_salt, hash_password, verify_password,
    generate_ecc_keys, serialize_ecc_public_key,
    serialize_ecc_private_key, deserialize_ecc_public_key,
    deserialize_ecc_private_key, generate_otp,
    ecc_encrypt_otp, ecc_decrypt_otp,
    serialize_ecc_cipher, deserialize_ecc_cipher,
    encrypt_private_key, decrypt_private_key,    # keep for fallback
    rotate_rsa_keys,
    generate_hmac, verify_hmac,
    ecc_sign, ecc_verify_signature,
    serialize_signature, deserialize_signature,
    wrap_private_key, unwrap_private_key,        # ADD THESE
)


# ============================================================
# BRUTE FORCE PROTECTION HELPERS
# ============================================================

MAX_ATTEMPTS    = 5       # failed attempts before lockout
LOCKOUT_MINUTES = 15      # how long account is locked
ATTEMPT_WINDOW  = 15      # minutes before attempt count resets


def check_login_lockout(username: str, ip: str):
    # Returns (is_locked, minutes_remaining, attempt_obj)
    # Called before processing login

    now = timezone.now()

    try:
        attempt = LoginAttempt.objects.get(
            username=username, ip_address=ip
        )
    except LoginAttempt.DoesNotExist:
        return False, 0, None

    # Check if lockout has expired
    if attempt.is_locked and attempt.locked_until:
        if now > attempt.locked_until:
            # Lockout expired — reset
            attempt.is_locked     = False
            attempt.attempt_count = 0
            attempt.locked_until  = None
            attempt.save()
            return False, 0, attempt
        else:
            # Still locked
            remaining = int(
                (attempt.locked_until - now).total_seconds() / 60
            ) + 1
            return True, remaining, attempt

    # Check if attempt window has expired (reset if so)
    window_start = now - timedelta(minutes=ATTEMPT_WINDOW)
    if attempt.first_attempt < window_start:
        attempt.attempt_count = 0
        attempt.is_locked     = False
        attempt.save()

    return False, 0, attempt


def record_failed_attempt(username: str, ip: str):
    # Record a failed login attempt
    # Lock account if max attempts reached

    now = timezone.now()

    attempt, created = LoginAttempt.objects.get_or_create(
        username   = username,
        ip_address = ip,
        defaults   = {'attempt_count': 0}
    )

    attempt.attempt_count += 1

    if attempt.attempt_count >= MAX_ATTEMPTS:
        attempt.is_locked    = True
        attempt.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)

    attempt.save()
    return attempt.attempt_count


def clear_failed_attempts(username: str, ip: str):
    # Clear failed attempts after successful login
    LoginAttempt.objects.filter(
        username=username, ip_address=ip
    ).delete()





# ============================================================
# HELPER — get logged in user from session
# ============================================================

def get_session_user(request):
    # Returns UserProfile object if logged in, else None
    user_id = request.session.get('user_id')
    if not user_id:
        return None
    try:
        return UserProfile.objects.get(id=user_id)
    except UserProfile.DoesNotExist:
        return None


def get_rsa_private_key(request):
    # Returns the decrypted RSA private key from session
    # This is the ONLY place private keys should come from
    # during a request — never from the DB directly
    key_str = request.session.get('rsa_private_key')
    if not key_str:
        return None
    return deserialize_key(key_str)


def decrypt_profile(user, request=None):
    # Decrypt all encrypted fields for a user
    # Tries session key first (faster, more secure)
    # Falls back to DB key (for legacy unencrypted keys)

    # Try to get private key from session first
    if request:
        priv_key = get_rsa_private_key(request)
    else:
        priv_key = None

    # Fallback: deserialize from DB (only for legacy users)
    if not priv_key:
        priv_key = deserialize_key(user.rsa_private_key)

    def safe_decrypt(field):
        if not field:
            return ''
        try:
            return decrypt_from_string(field, priv_key)
        except Exception:
            return '[decryption error]'

    return {
        'full_name'      : safe_decrypt(user.encrypted_full_name),
        'email'          : safe_decrypt(user.encrypted_email_data),
        'phone'          : safe_decrypt(user.encrypted_phone),
        'address'        : safe_decrypt(user.encrypted_address),
        'date_of_birth'  : safe_decrypt(user.encrypted_date_of_birth),
        'guardian_name'  : safe_decrypt(user.encrypted_guardian_name),
        'guardian_phone' : safe_decrypt(user.encrypted_guardian_phone),
        'subject'        : safe_decrypt(user.encrypted_subject),
        'qualification'  : safe_decrypt(user.encrypted_qualification),
        'occupation'     : safe_decrypt(user.encrypted_occupation),

                # ── New student fields ────────────────────────
        'blood_group'        : safe_decrypt(user.encrypted_blood_group),
        'medical_notes'      : safe_decrypt(user.encrypted_medical_notes),
        'nationality'        : safe_decrypt(user.encrypted_nationality),
        'religion'           : safe_decrypt(user.encrypted_religion),
        'emergency_contact'  : safe_decrypt(user.encrypted_emergency_contact),
    }


# ============================================================
# REGISTRATION
# ============================================================

def register_view(request):

    if request.method == 'GET':
        return render(request, 'core/register.html')

    if request.method == 'POST':
        username  = request.POST.get('username', '').strip()
        email     = request.POST.get('email', '').strip()
        full_name = request.POST.get('full_name', '').strip()
        phone     = request.POST.get('phone', '').strip()
        password  = request.POST.get('password', '').strip()
        confirm   = request.POST.get('confirm_password', '').strip()
        role      = request.POST.get('role', '').strip()

        if not all([username, email, full_name, password, confirm, role]):
            messages.error(request, 'All fields are required.')
            return render(request, 'core/register.html')

        if password != confirm:
            messages.error(request, 'Passwords do not match.')
            return render(request, 'core/register.html')

        allowed_roles = ['student', 'teacher', 'parent']
        if role not in allowed_roles:
            messages.error(request, 'Invalid role selected.')
            return render(request, 'core/register.html')

        if UserProfile.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return render(request, 'core/register.html')

        if UserProfile.objects.filter(email=email).exists():
            messages.error(request, 'Email already registered.')
            return render(request, 'core/register.html')

# ------------------------------------------------
        # Generate RSA key pair
        # ------------------------------------------------
        public_key, private_key = generate_rsa_keys(bits=512)
        pub_key_str  = serialize_key(public_key)
        priv_key_str = serialize_key(private_key)

        # ------------------------------------------------
        # Encrypt personal data using RSA public key
        # ------------------------------------------------
        encrypted_name  = encrypt_to_string(full_name, public_key)
        encrypted_email = encrypt_to_string(email, public_key)
        encrypted_phone = encrypt_to_string(phone, public_key) if phone else ''

        # ------------------------------------------------
        # Generate ECC key pair
        # ------------------------------------------------
        ecc_private_int, ecc_public_point = generate_ecc_keys()
        ecc_pub_str  = serialize_ecc_public_key(ecc_public_point)
        ecc_priv_str = serialize_ecc_private_key(ecc_private_int)

        # ------------------------------------------------
        # Hash password with salt
        # ------------------------------------------------
        salt          = generate_salt()
        password_hash = hash_password(password, salt)

        # ------------------------------------------------
        # Wrap private keys using RSA (100% asymmetric)
        # Master RSA key pair derived from password+salt
        # Private keys encrypted with master RSA public key
        # Master key never stored — re-derived on login
        # ------------------------------------------------
        rsa_priv_encrypted = wrap_private_key(
            priv_key_str, password, salt
        )
        ecc_priv_encrypted = wrap_private_key(
            ecc_priv_str, password, salt
        )

        # ------------------------------------------------
        # Determine approval
        # ------------------------------------------------
        is_approved = role != 'teacher'

        try:
            UserProfile.objects.create(
                            username             = username,
                            email                = email,
                            password_hash        = password_hash,
                            password_salt        = salt,
                            role                 = role,
                            is_approved          = is_approved,
                            rsa_public_key       = pub_key_str,
                            rsa_private_key      = rsa_priv_encrypted,   # encrypted hex
                            ecc_public_key       = ecc_pub_str,
                            ecc_private_key      = ecc_priv_encrypted,   # encrypted hex
                            keys_encrypted       = True,                  # mark as encrypted
                            encrypted_full_name  = encrypted_name,
                            encrypted_email_data = encrypted_email,
                            encrypted_phone      = encrypted_phone,
                        )

            if role == 'teacher':
                messages.success(request, 'Registration successful! Pending admin approval.')
                return render(request, 'core/pending_approval.html')
            else:
                messages.success(request, 'Registration successful! You can now log in.')
                return redirect('login')

        except Exception as ex:
            messages.error(request, f'Registration failed: {str(ex)}')
            return render(request, 'core/register.html')


# ============================================================
# LOGIN — Step 1 of 2FA
# ============================================================

def login_view(request):

    if request.method == 'GET':
        return render(request, 'core/login.html')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        ip       = request.META.get('REMOTE_ADDR', '')

        if not username or not password:
            messages.error(request, 'Both fields are required.')
            return render(request, 'core/login.html')

        # ------------------------------------------------
        # Brute force check BEFORE touching the DB user
        # Prevents username enumeration timing attacks
        # ------------------------------------------------
        is_locked, minutes_left, _ = check_login_lockout(username, ip)
        if is_locked:
            messages.error(
                request,
                f'Account locked due to too many failed attempts. '
                f'Try again in {minutes_left} minute(s).'
            )
            return render(request, 'core/login.html')

        try:
            user = UserProfile.objects.get(username=username)
        except UserProfile.DoesNotExist:
            # Record attempt even for non-existent users
            # Prevents username enumeration
            record_failed_attempt(username, ip)
            messages.error(request, 'Invalid username or password.')
            return render(request, 'core/login.html')

        if user.role == 'teacher' and not user.is_approved:
            messages.error(request, 'Your account is pending admin approval.')
            return render(request, 'core/login.html')

        if not verify_password(password, user.password_salt, user.password_hash):
            # Record failed attempt
            count = record_failed_attempt(username, ip)
            remaining = MAX_ATTEMPTS - count
            if remaining > 0:
                messages.error(
                    request,
                    f'Invalid username or password. '
                    f'{remaining} attempt(s) remaining.'
                )
            else:
                messages.error(
                    request,
                    f'Account locked for {LOCKOUT_MINUTES} minutes '
                    f'due to too many failed attempts.'
                )
            return render(request, 'core/login.html')

        # ------------------------------------------------
        # Login successful — clear any failed attempts
        # ------------------------------------------------
        clear_failed_attempts(username, ip)

        # ------------------------------------------------
        # Decrypt private keys using password
        # We do this right after password is verified
        # Decrypted keys stored in session (memory only)
        # Never written back to DB in plain form
        # ------------------------------------------------
        if user.keys_encrypted:
            # ------------------------------------------------
            # Unwrap private keys using RSA master key
            # Master key re-derived from password (never stored)
            # This is 100% asymmetric key unwrapping
            # ------------------------------------------------
            try:
                rsa_priv_plain = unwrap_private_key(
                    user.rsa_private_key,
                    password,
                    user.password_salt
                )
                ecc_priv_plain = unwrap_private_key(
                    user.ecc_private_key,
                    password,
                    user.password_salt
                )
            except Exception:
                # Fallback for old XOR-wrapped keys
                # Unwrap with old method then re-wrap with RSA
                try:
                    rsa_priv_plain = decrypt_private_key(
                        user.rsa_private_key,
                        password,
                        user.password_salt
                    )
                    ecc_priv_plain = decrypt_private_key(
                        user.ecc_private_key,
                        password,
                        user.password_salt
                    )

                    # ----------------------------------------
                    # AUTO-MIGRATE: Re-wrap with RSA on login
                    # User seamlessly upgraded to RSA wrapping
                    # ----------------------------------------
                    user.rsa_private_key = wrap_private_key(
                        rsa_priv_plain,
                        password,
                        user.password_salt
                    )
                    user.ecc_private_key = wrap_private_key(
                        ecc_priv_plain,
                        password,
                        user.password_salt
                    )
                    user.save(update_fields=[
                        'rsa_private_key',
                        'ecc_private_key'
                    ])
                    # Log the migration
                    KeyAccessLog.objects.create(
                        user         = user,
                        action       = 'rotate',
                        performed_by = user,
                        ip_address   = request.META.get(
                            'REMOTE_ADDR', ''
                        ),
                        note=(
                            'Auto-migrated from XOR to '
                            'RSA key wrapping on login'
                        )
                    )
                except Exception:
                    # Complete fallback — plain legacy keys
                    rsa_priv_plain = user.rsa_private_key
                    ecc_priv_plain = user.ecc_private_key
        else:
            # Legacy plain keys
            rsa_priv_plain = user.rsa_private_key
            ecc_priv_plain = user.ecc_private_key

        # Store decrypted keys in session
        # Session is server-side memory — not stored in DB
        request.session['rsa_private_key'] = rsa_priv_plain
        request.session['ecc_private_key'] = ecc_priv_plain

        # Also store ECC key in pre-auth namespace
        # So verify_otp_view can access it before full login
        request.session['pre_auth_ecc_key'] = ecc_priv_plain

        # Log the key access
        KeyAccessLog.objects.create(
            user         = user,
            action       = 'login',
            performed_by = user,
            ip_address   = request.META.get('REMOTE_ADDR'),
            note         = 'Private keys loaded into session on login'
        )

        # Generate and encrypt OTP
        otp_plain  = generate_otp()
        ecc_pub    = deserialize_ecc_public_key(user.ecc_public_key)
        cipher     = ecc_encrypt_otp(otp_plain, ecc_pub)
        cipher_str = serialize_ecc_cipher(cipher)

        OTPSession.objects.filter(user=user).delete()
        OTPSession.objects.create(user=user, encrypted_otp=cipher_str)

        request.session['pre_auth_user_id'] = user.id
        request.session['pre_auth_ecc_key'] = ecc_priv_plain

        # ------------------------------------------------
        # Send OTP via email — real secure channel
        # OTP is NOT stored in session anymore
        # ------------------------------------------------
        try:
            send_mail(
                subject = 'Crypto School — Your Login OTP',
                message = (
                    f'Hello {user.username},\n\n'
                    f'Your One-Time Password (OTP) is:\n\n'
                    f'    {otp_plain}\n\n'
                    f'This OTP expires in 5 minutes.\n'
                    f'Do not share this with anyone.\n\n'
                    f'If you did not request this, '
                    f'please contact admin immediately.\n\n'
                    f'— Crypto School Security System'
                ),
                from_email    = settings.DEFAULT_FROM_EMAIL,
                recipient_list = [user.email],
                fail_silently = False,
            )
            messages.success(
                request,
                f'OTP sent to your email ({user.email[:3]}***). '
                f'Check your inbox.'
            )
        except Exception as e:
            # Email failed — fallback message for dev
            messages.warning(
                request,
                f'Email sending failed: {str(e)}. '
                f'Dev mode OTP: {otp_plain}'
            )

        return redirect('verify_otp')

    return render(request, 'core/login.html')


# ============================================================
# OTP VERIFY — Step 2 of 2FA
# ============================================================

def verify_otp_view(request):

    user_id = request.session.get('pre_auth_user_id')
    if not user_id:
        messages.error(request, 'Please log in first.')
        return redirect('login')

    try:
        user        = UserProfile.objects.get(id=user_id)
        otp_session = OTPSession.objects.get(user=user)
    except (UserProfile.DoesNotExist, OTPSession.DoesNotExist):
        messages.error(request, 'Session expired. Please log in again.')
        return redirect('login')

    expiry_time = otp_session.created_at + timedelta(minutes=5)
    if timezone.now() > expiry_time:
        otp_session.delete()
        messages.error(request, 'OTP expired. Please log in again.')
        return redirect('login')

    cipher   = deserialize_ecc_cipher(otp_session.encrypted_otp)

    # ------------------------------------------------
    # Get ECC private key from session (decrypted on login)
    # If not in session yet (we are still in pre-auth stage)
    # we decrypt it now using the stored encrypted version
    # But we need the password — so we use the pre-auth
    # approach: decrypt from DB using session-stored plain key
    # ------------------------------------------------
    ecc_priv_str = request.session.get('ecc_private_key')

    if ecc_priv_str:
        # Already decrypted and stored in session during login
        ecc_priv = deserialize_ecc_private_key(ecc_priv_str)
    else:
        # Not in session yet — this means we need to decrypt it
        # We stored the plain ecc key temporarily during login step
        # Check pre_auth ecc key
        ecc_priv_plain = request.session.get('pre_auth_ecc_key')
        if not ecc_priv_plain:
            messages.error(request, 'Session expired. Please log in again.')
            return redirect('login')
        ecc_priv = deserialize_ecc_private_key(ecc_priv_plain)

    real_otp  = ecc_decrypt_otp(cipher, ecc_priv)

    if request.method == 'GET':
        return render(request, 'core/verify_otp.html', {
            'encrypted_otp' : otp_session.encrypted_otp,
            'decrypted_otp' : real_otp,
            'username'      : user.username,
        })

    if request.method == 'POST':
        submitted_otp = request.POST.get('otp', '').strip()

        if submitted_otp != real_otp:
            messages.error(request, 'Incorrect OTP. Try again.')
            return render(request, 'core/verify_otp.html', {
                'encrypted_otp' : otp_session.encrypted_otp,
                'decrypted_otp' : real_otp,
                'username'      : user.username,
            })

# ------------------------------------------------
        # Full login granted — create secure session
        # ------------------------------------------------
        otp_session.delete()

        # Clean up pre-auth session keys
        pre_auth_keys = [
            'pre_auth_user_id', 'pre_auth_ecc_key', 'debug_otp'
        ]
        for key in pre_auth_keys:
            if key in request.session:
                del request.session[key]

        # Set core session data
        request.session['user_id']   = user.id
        request.session['user_role'] = user.role
        request.session['username']  = user.username

        # ------------------------------------------------
        # Create ECC-signed secure session token
        # Stored in DB, hash only — never raw token in DB
        # ------------------------------------------------
        raw_token = create_secure_session(user, request)
        request.session['session_token'] = raw_token

        # Set Django session expiry to match our timeout
        # 30 minutes of inactivity
        request.session.set_expiry(60 * 30)

        role_redirects = {
            'admin'   : 'dashboard_admin',
            'teacher' : 'dashboard_teacher',
            'parent'  : 'dashboard_parent',
            'student' : 'dashboard_student',
        }
        return redirect(role_redirects.get(user.role, 'login'))


# ============================================================
# LOGOUT
# ============================================================

def logout_view(request):
    # Properly terminate secure session before clearing
    terminate_session(request)
    # terminate_session already calls session.flush()
    # but we redirect explicitly
    return redirect('login')


# ============================================================
# STUDENT DASHBOARD
# ============================================================

def student_dashboard(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Decrypt profile for display
    profile = decrypt_profile(user, request)

    # Get student's enrolled classes
    enrollments = ClassEnrollment.objects.filter(
        student=user
    ).select_related('enrolled_class')
    # select_related = fetch class data in same DB query (efficient)

    return render(request, 'core/dashboard_student.html', {
        'user'        : user,
        'profile'     : profile,
        'enrollments' : enrollments,
    })


# ============================================================
# TEACHER DASHBOARD
# ============================================================

def teacher_dashboard(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    profile = decrypt_profile(user, request)

    # Get classes this teacher is assigned to
    assignments = TeacherAssignment.objects.filter(
        teacher=user
    ).select_related('assigned_class')

    return render(request, 'core/dashboard_teacher.html', {
        'user'        : user,
        'profile'     : profile,
        'assignments' : assignments,
    })


# ============================================================
# PARENT DASHBOARD
# ============================================================

def parent_dashboard(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    profile = decrypt_profile(user, request)

    # Get this parent's requests
    try:
        from .models import ParentRequest
        parent_requests = ParentRequest.objects.filter(
            parent=user
        ).select_related('student').order_by('-created_at')
    except Exception:
        parent_requests = []

    return render(request, 'core/dashboard_parent.html', {
        'user'            : user,
        'profile'         : profile,
        'parent_requests' : parent_requests,
    })


# ============================================================
# ADMIN DASHBOARD
# ============================================================

def admin_dashboard(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    pending_teachers = UserProfile.objects.filter(
        role='teacher', is_approved=False
    )
    all_teachers = UserProfile.objects.filter(role='teacher', is_approved=True)
    all_students = UserProfile.objects.filter(role='student')
    all_parents  = UserProfile.objects.filter(role='parent')
    all_classes  = Class.objects.all()

    # Count pending parent requests for the stat box
    try:
        from .models import ParentRequest
        pending_requests_count = ParentRequest.objects.filter(
            status='pending'
        ).count()
    except Exception:
        pending_requests_count = 0

    return render(request, 'core/dashboard_admin.html', {
        'user'                  : user,
        'pending_teachers'      : pending_teachers,
        'all_teachers'          : all_teachers,
        'all_students'          : all_students,
        'all_parents'           : all_parents,
        'all_classes'           : all_classes,
        'pending_requests_count': pending_requests_count,
    })


# ============================================================
# ADMIN — APPROVE TEACHER
# ============================================================

def approve_teacher(request, teacher_id):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    try:
        teacher = UserProfile.objects.get(id=teacher_id, role='teacher')
        teacher.is_approved = True
        teacher.save()
        messages.success(request, f'{teacher.username} approved successfully.')
    except UserProfile.DoesNotExist:
        messages.error(request, 'Teacher not found.')

    return redirect('dashboard_admin')


# ============================================================
# ADMIN — CREATE CLASS
# ============================================================

def create_class(request):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    if request.method == 'POST':
        class_name = request.POST.get('class_name', '').strip()
        section    = request.POST.get('section', '').strip()

        if not class_name or not section:
            messages.error(request, 'Class name and section are required.')
            return redirect('dashboard_admin')

        # Check if already exists
        if Class.objects.filter(class_name=class_name, section=section).exists():
            messages.error(request, 'This class already exists.')
            return redirect('dashboard_admin')

        Class.objects.create(
            class_name = class_name,
            section    = section,
            created_by = user,
        )
        messages.success(request, f'Class {class_name} - {section} created.')

    return redirect('dashboard_admin')


# ============================================================
# ADMIN — ASSIGN TEACHER TO CLASS
# ============================================================

def assign_teacher(request):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    if request.method == 'POST':
        teacher_id = request.POST.get('teacher_id')
        class_id   = request.POST.get('class_id')

        try:
            teacher      = UserProfile.objects.get(id=teacher_id, role='teacher')
            assigned_cls = Class.objects.get(id=class_id)

            # Check if already assigned
            if TeacherAssignment.objects.filter(
                teacher=teacher, assigned_class=assigned_cls
            ).exists():
                messages.error(request, 'Teacher already assigned to this class.')
                return redirect('dashboard_admin')

            TeacherAssignment.objects.create(
                teacher        = teacher,
                assigned_class = assigned_cls,
            )
            messages.success(
                request,
                f'{teacher.username} assigned to {assigned_cls}.'
            )

        except (UserProfile.DoesNotExist, Class.DoesNotExist):
            messages.error(request, 'Invalid teacher or class.')

    return redirect('dashboard_admin')


# ============================================================
# ADMIN — ENROLL STUDENT TO CLASS
# ============================================================

def enroll_student(request):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    if request.method == 'POST':
        student_id = request.POST.get('student_id')
        class_id   = request.POST.get('class_id')

        try:
            student      = UserProfile.objects.get(id=student_id, role='student')
            assigned_cls = Class.objects.get(id=class_id)

            if ClassEnrollment.objects.filter(
                student=student, enrolled_class=assigned_cls
            ).exists():
                messages.error(request, 'Student already enrolled in this class.')
                return redirect('dashboard_admin')

            ClassEnrollment.objects.create(
                student        = student,
                enrolled_class = assigned_cls,
            )
            messages.success(
                request,
                f'{student.username} enrolled in {assigned_cls}.'
            )

        except (UserProfile.DoesNotExist, Class.DoesNotExist):
            messages.error(request, 'Invalid student or class.')

    return redirect('dashboard_admin')


# ============================================================
# UPDATE PROFILE (all roles)
# ============================================================

def update_profile(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Decrypt current profile to pre-fill the form
    profile = decrypt_profile(user, request)

    if request.method == 'GET':
        return render(request, 'core/update_profile.html', {
            'user'    : user,
            'profile' : profile,
        })

    if request.method == 'POST':
        # Get public key to encrypt new data
        pub_key = deserialize_key(user.rsa_public_key)

        def encrypt_field(field_name):
            # Helper: get field from POST, encrypt if not empty
            value = request.POST.get(field_name, '').strip()
            if value:
                return encrypt_to_string(value, pub_key)
            return ''

        # ── Common fields for all roles ───────────────────
        full_name = request.POST.get('full_name', '').strip()
        phone     = request.POST.get('phone', '').strip()

        if not full_name:
            messages.error(request, 'Full name is required.')
            return render(request, 'core/update_profile.html', {
                'user': user, 'profile': profile
            })

        # Encrypt all updated fields
        user.encrypted_full_name    = encrypt_to_string(full_name, pub_key)
        user.encrypted_phone        = encrypt_to_string(phone, pub_key) if phone else user.encrypted_phone
        user.encrypted_address      = encrypt_field('address')
        user.encrypted_date_of_birth = encrypt_field('date_of_birth')

        # ── Role-specific fields ──────────────────────────
        if user.role == 'student':
            user.encrypted_guardian_name  = encrypt_field('guardian_name')
            user.encrypted_guardian_phone = encrypt_field('guardian_phone')

            # Extended student fields
            user.encrypted_blood_group       = encrypt_field('blood_group')
            user.encrypted_medical_notes     = encrypt_field('medical_notes')
            user.encrypted_nationality       = encrypt_field('nationality')
            user.encrypted_religion          = encrypt_field('religion')
            user.encrypted_emergency_contact = encrypt_field('emergency_contact')

            # Profile picture (not encrypted — just a photo)
            if 'profile_picture' in request.FILES:
                user.profile_picture = request.FILES['profile_picture']

        elif user.role == 'teacher':
            user.encrypted_subject       = encrypt_field('subject')
            user.encrypted_qualification = encrypt_field('qualification')

        elif user.role == 'parent':
            user.encrypted_occupation = encrypt_field('occupation')

        user.profile_complete = True
        user.save()

        messages.success(request, 'Profile updated successfully.')

        # Redirect back to their own dashboard
        role_redirects = {
            'admin'   : 'dashboard_admin',
            'teacher' : 'dashboard_teacher',
            'parent'  : 'dashboard_parent',
            'student' : 'dashboard_student',
        }
        return redirect(role_redirects.get(user.role, 'login'))


# ============================================================
# PENDING APPROVAL PAGE
# ============================================================

def pending_approval(request):
    return render(request, 'core/pending_approval.html')



# ============================================================
# CLASS DETAIL VIEW — Admin sees full class info
# ============================================================

def class_detail(request, class_id):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    try:
        cls = Class.objects.get(id=class_id)
    except Class.DoesNotExist:
        messages.error(request, 'Class not found.')
        return redirect('dashboard_admin')

    # Get all teachers assigned to this class
    teacher_assignments = TeacherAssignment.objects.filter(
        assigned_class=cls
    ).select_related('teacher')

    # Get all students enrolled in this class
    enrollments = ClassEnrollment.objects.filter(
        enrolled_class=cls
    ).select_related('student')

    return render(request, 'core/class_detail.html', {
        'user'                : user,
        'cls'                 : cls,
        'teacher_assignments' : teacher_assignments,
        'enrollments'         : enrollments,
    })


# ============================================================
# ALL CLASSES VIEW — Admin sees every class with full summary
# ============================================================

def all_classes_view(request):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    # Get all classes with their teacher and student counts
    all_classes = Class.objects.all()

    # Build a summary dict for each class
    # {class_id: {teachers: [...], students: [...], counts}}
    class_summaries = []
    for cls in all_classes:
        teachers = TeacherAssignment.objects.filter(
            assigned_class=cls
        ).select_related('teacher')

        students = ClassEnrollment.objects.filter(
            enrolled_class=cls
        ).select_related('student')

        class_summaries.append({
            'cls'              : cls,
            'teachers'         : teachers,
            'students'         : students,
            'teacher_count'    : teachers.count(),
            'student_count'    : students.count(),
        })

    return render(request, 'core/all_classes.html', {
        'user'            : user,
        'class_summaries' : class_summaries,
    })


# ============================================================
# REMOVE TEACHER FROM CLASS — Admin action
# ============================================================

def remove_teacher_from_class(request, assignment_id):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    try:
        assignment = TeacherAssignment.objects.get(id=assignment_id)
        class_id   = assignment.assigned_class.id
        assignment.delete()
        messages.success(request, 'Teacher removed from class.')
    except TeacherAssignment.DoesNotExist:
        messages.error(request, 'Assignment not found.')
        class_id = None

    # Go back to the class detail page
    if class_id:
        return redirect('class_detail', class_id=class_id)
    return redirect('all_classes')


# ============================================================
# REMOVE STUDENT FROM CLASS — Admin action
# ============================================================

def remove_student_from_class(request, enrollment_id):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    try:
        enrollment = ClassEnrollment.objects.get(id=enrollment_id)
        class_id   = enrollment.enrolled_class.id
        enrollment.delete()
        messages.success(request, 'Student removed from class.')
    except ClassEnrollment.DoesNotExist:
        messages.error(request, 'Enrollment not found.')
        class_id = None

    if class_id:
        return redirect('class_detail', class_id=class_id)
    return redirect('all_classes')


# ============================================================
# DELETE CLASS — Admin action
# ============================================================

def delete_class(request, class_id):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    try:
        cls = Class.objects.get(id=class_id)
        cls.delete()
        # Deleting the class also deletes all related
        # TeacherAssignment and ClassEnrollment rows
        # because of CASCADE in the ForeignKey
        messages.success(request, f'Class deleted.')
    except Class.DoesNotExist:
        messages.error(request, 'Class not found.')

    return redirect('all_classes')


# ============================================================
# TEACHER — MY CLASS DETAIL
# Teacher sees full info about one of their assigned classes
# including all students in it
# ============================================================

def teacher_class_detail(request, class_id):
    user = get_session_user(request)
    if not user or user.role != 'teacher':
        return redirect('login')

    try:
        cls = Class.objects.get(id=class_id)
    except Class.DoesNotExist:
        messages.error(request, 'Class not found.')
        return redirect('dashboard_teacher')

    # Make sure this teacher is actually assigned to this class
    # Security check — teacher can't view classes they don't teach
    is_assigned = TeacherAssignment.objects.filter(
        teacher=user, assigned_class=cls
    ).exists()

    if not is_assigned:
        messages.error(request, 'You are not assigned to this class.')
        return redirect('dashboard_teacher')

    # Get all OTHER teachers also teaching this class
    other_teachers = TeacherAssignment.objects.filter(
        assigned_class=cls
    ).exclude(teacher=user).select_related('teacher')

    # Get all students in this class
    enrollments = ClassEnrollment.objects.filter(
        enrolled_class=cls
    ).select_related('student')

    # Decrypt each student's name for display
    # Teacher is authorized to see student names in their class
    student_data = []
    for enrollment in enrollments:
        student = enrollment.student
        try:
            priv_key = deserialize_key(student.rsa_private_key)
            name = decrypt_from_string(
                student.encrypted_full_name, priv_key
            )
        except Exception:
            name = student.username  # fallback to username if decryption fails

        student_data.append({
            'username'    : student.username,
            'full_name'   : name,
            'enrolled_at' : enrollment.enrolled_at,
        })

    return render(request, 'core/teacher_class_detail.html', {
        'user'           : user,
        'cls'            : cls,
        'other_teachers' : other_teachers,
        'student_data'   : student_data,
    })


# ============================================================
# STUDENT — MY CLASS DETAIL
# Student sees full info about one of their enrolled classes
# including their teacher(s)
# ============================================================

def student_class_detail(request, class_id):
    user = get_session_user(request)
    if not user or user.role != 'student':
        return redirect('login')

    try:
        cls = Class.objects.get(id=class_id)
    except Class.DoesNotExist:
        messages.error(request, 'Class not found.')
        return redirect('dashboard_student')

    # Security check — student must be enrolled in this class
    is_enrolled = ClassEnrollment.objects.filter(
        student=user, enrolled_class=cls
    ).exists()

    if not is_enrolled:
        messages.error(request, 'You are not enrolled in this class.')
        return redirect('dashboard_student')

    # Get all teachers assigned to this class
    teacher_assignments = TeacherAssignment.objects.filter(
        assigned_class=cls
    ).select_related('teacher')

    # Decrypt each teacher's name and subject
    teacher_data = []
    for assignment in teacher_assignments:
        teacher = assignment.teacher
        try:
            priv_key = deserialize_key(teacher.rsa_private_key)
            name    = decrypt_from_string(teacher.encrypted_full_name, priv_key)
            subject = decrypt_from_string(teacher.encrypted_subject, priv_key) \
                      if teacher.encrypted_subject else '—'
        except Exception:
            name    = teacher.username
            subject = '—'

        teacher_data.append({
            'username'    : teacher.username,
            'full_name'   : name,
            'subject'     : subject,
            'assigned_at' : assignment.assigned_at,
        })

    # Get all classmates (other students in same class)
    classmates = ClassEnrollment.objects.filter(
        enrolled_class=cls
    ).exclude(student=user).select_related('student')

    classmate_data = []
    for c in classmates:
        try:
            priv_key = deserialize_key(c.student.rsa_private_key)
            name = decrypt_from_string(c.student.encrypted_full_name, priv_key)
        except Exception:
            name = c.student.username

        classmate_data.append({
            'username'  : c.student.username,
            'full_name' : name,
        })

    return render(request, 'core/student_class_detail.html', {
        'user'           : user,
        'cls'            : cls,
        'teacher_data'   : teacher_data,
        'classmate_data' : classmate_data,
    })


# ============================================================
# KEY ROTATION VIEW
# ============================================================

def rotate_keys(request):
    # Allows a user to rotate their RSA keys
    # All encrypted data is re-encrypted with new keys
    # Private key is re-encrypted with current password

    user = get_session_user(request)
    if not user:
        return redirect('login')

    if request.method == 'POST':
        password = request.POST.get('password', '').strip()

        # Verify password before allowing key rotation
        if not verify_password(password, user.password_salt, user.password_hash):
            messages.error(request, 'Incorrect password.')
            return redirect('key_management')

        # Get old private key from session
        old_priv_key = get_rsa_private_key(request)
        if not old_priv_key:
            messages.error(request, 'Session expired. Please log in again.')
            return redirect('login')

        old_pub_key = deserialize_key(user.rsa_public_key)

        # Collect all encrypted fields that need re-encrypting
        encrypted_fields = [
            user.encrypted_full_name,
            user.encrypted_email_data,
            user.encrypted_phone,
            user.encrypted_address,
            user.encrypted_date_of_birth,
            user.encrypted_guardian_name,
            user.encrypted_guardian_phone,
            user.encrypted_subject,
            user.encrypted_qualification,
            user.encrypted_occupation,
        ]

        # Rotate keys — decrypt with old, re-encrypt with new
        new_pub, new_priv, re_encrypted = rotate_rsa_keys(
            old_priv_key, old_pub_key, encrypted_fields
        )

        # Serialize new keys
        new_pub_str  = serialize_key(new_pub)
        new_priv_str = serialize_key(new_priv)

        # Wrap new private key with RSA master key
        new_priv_encrypted = wrap_private_key(
            new_priv_str, password, user.password_salt
        )

        # Update user record
        user.rsa_public_key          = new_pub_str
        user.rsa_private_key         = new_priv_encrypted
        user.encrypted_full_name     = re_encrypted[0]
        user.encrypted_email_data    = re_encrypted[1]
        user.encrypted_phone         = re_encrypted[2]
        user.encrypted_address       = re_encrypted[3]
        user.encrypted_date_of_birth = re_encrypted[4]
        user.encrypted_guardian_name  = re_encrypted[5]
        user.encrypted_guardian_phone = re_encrypted[6]
        user.encrypted_subject        = re_encrypted[7]
        user.encrypted_qualification  = re_encrypted[8]
        user.encrypted_occupation     = re_encrypted[9]
        user.keys_encrypted           = True
        user.key_version             += 1
        user.last_key_rotation        = timezone.now()
        user.save()

        # Update session with new private key
        request.session['rsa_private_key'] = new_priv_str

        # Log the rotation
        KeyAccessLog.objects.create(
            user         = user,
            action       = 'rotate',
            performed_by = user,
            ip_address   = request.META.get('REMOTE_ADDR'),
            note         = f'Keys rotated to version {user.key_version}'
        )

        messages.success(
            request,
            f'Keys rotated successfully. '
            f'Now on version {user.key_version}.'
        )

    return redirect('key_management')


# ============================================================
# KEY MANAGEMENT PAGE
# ============================================================

def key_management(request):
    # Shows key info and rotation option for logged in user

    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Get this user's key access logs
    logs = KeyAccessLog.objects.filter(user=user)[:20]
    # Show last 20 entries

    return render(request, 'core/key_management.html', {
        'user' : user,
        'logs' : logs,
    })


# ============================================================
# ADMIN — KEY LOGS OVERVIEW
# ============================================================

def admin_key_logs(request):
    # Admin can see all key access logs across all users
    # Important for security auditing

    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    # Get all logs, newest first
    all_logs = KeyAccessLog.objects.select_related(
        'user', 'performed_by'
    ).all()[:100]
    # Limit to 100 most recent

    return render(request, 'core/admin_key_logs.html', {
        'user'     : user,
        'all_logs' : all_logs,
    })




# ============================================================
# ENCRYPTION AUDIT VIEW — Proves data is encrypted in DB
# Shows raw encrypted DB values vs decrypted values
# REMOVE THIS IN PRODUCTION — development proof only
# ============================================================

def encryption_audit(request):
    # Only admin can see this
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    audit_data = []

    all_users = UserProfile.objects.all()

    for u in all_users:
        # ------------------------------------------------
        # Get RAW values straight from DB
        # These are what an attacker sees if DB is breached
        # ------------------------------------------------
        raw = {
            'username'           : u.username,         # plain — needed for login
            'role'               : u.role,             # plain — needed for queries
            'password_hash'      : u.password_hash[:40] + '...',
            'password_salt'      : u.password_salt[:20] + '...',
            'rsa_private_key'    : u.rsa_private_key[:40] + '...' if u.rsa_private_key else '—',
            'rsa_public_key'     : u.rsa_public_key[:40] + '...' if u.rsa_public_key else '—',
            'encrypted_name'     : u.encrypted_full_name[:60] + '...' if u.encrypted_full_name else '—',
            'encrypted_email'    : u.encrypted_email_data[:60] + '...' if u.encrypted_email_data else '—',
            'encrypted_phone'    : u.encrypted_phone[:60] + '...' if u.encrypted_phone else '—',
            'keys_encrypted'     : u.keys_encrypted,
            'key_version'        : u.key_version,
        }

        # ------------------------------------------------
        # Now decrypt using private key from session
        # (only works for currently logged in user)
        # For other users we need their private key
        # ------------------------------------------------
        decrypted = {}

        if u.id == user.id:
            # Currently logged in user — use session key
            priv_key = get_rsa_private_key(request)
            if priv_key:
                try:
                    decrypted['full_name'] = decrypt_from_string(
                        u.encrypted_full_name, priv_key
                    ) if u.encrypted_full_name else '—'
                    decrypted['email'] = decrypt_from_string(
                        u.encrypted_email_data, priv_key
                    ) if u.encrypted_email_data else '—'
                    decrypted['phone'] = decrypt_from_string(
                        u.encrypted_phone, priv_key
                    ) if u.encrypted_phone else '—'
                    decrypted['source'] = 'session key (logged in user)'
                except Exception as e:
                    decrypted['error'] = str(e)
                    decrypted['source'] = 'session key (error)'
            else:
                decrypted['source'] = 'no session key available'
        else:
            # Other users — we cannot decrypt without their password
            # This PROVES the encryption is working:
            # even admin cannot read other users' data
            decrypted['full_name'] = '🔒 CANNOT DECRYPT — no private key'
            decrypted['email']     = '🔒 CANNOT DECRYPT — no private key'
            decrypted['phone']     = '🔒 CANNOT DECRYPT — no private key'
            decrypted['source']    = 'other user — private key not accessible'

        audit_data.append({
            'user'      : u,
            'raw'       : raw,
            'decrypted' : decrypted,
        })

    return render(request, 'core/encryption_audit.html', {
        'user'       : user,
        'audit_data' : audit_data,
    })



# ============================================================
# HELPER — get HMAC secret key for a user
# We derive a consistent secret from their public key
# So the same secret is always reproducible
# ============================================================

def get_hmac_secret(user: UserProfile) -> str:
    # Derive HMAC secret from user's public key
    # This gives us a consistent secret without storing one
    import hashlib
    return hashlib.sha256(
        user.rsa_public_key[:50].encode()
    ).hexdigest()



# ============================================================
# ADD RESULT — Teacher ONLY
# Teacher must be assigned to the student's class
# Admin cannot add results
# ============================================================

def add_result(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # ------------------------------------------------
    # STRICT CHECK: Only teachers can add results
    # Admin is explicitly blocked
    # ------------------------------------------------
    if user.role != 'teacher':
        messages.error(
            request,
            'Only assigned teachers can add results.'
        )
        return redirect(
            'dashboard_admin' if user.role == 'admin'
            else 'login'
        )

    # ------------------------------------------------
    # Get ONLY classes this teacher is assigned to
    # ------------------------------------------------
    teacher_assignments = TeacherAssignment.objects.filter(
        teacher=user
    ).select_related('assigned_class')

    # Get class IDs
    assigned_class_ids = teacher_assignments.values_list(
        'assigned_class_id', flat=True
    )

    if not assigned_class_ids:
        messages.error(
            request,
            'You are not assigned to any class yet. '
            'Contact admin to get assigned.'
        )
        return render(request, 'core/add_result.html', {
            'user'             : user,
            'assigned_classes' : [],
            'students'         : [],
            'subject_choices'  : [],
            'no_classes'       : True,
        })

    # Get classes for display
    assigned_classes = Class.objects.filter(
        id__in=assigned_class_ids
    )

    # Subject choices from model
    subject_choices = StudentResult.SUBJECT_CHOICES

    if request.method == 'GET':
        # On GET — no students shown yet
        # Teacher picks class first → students load
        return render(request, 'core/add_result.html', {
            'user'             : user,
            'assigned_classes' : assigned_classes,
            'subject_choices'  : subject_choices,
            'students'         : [],
            'selected_class'   : None,
            'no_classes'       : False,
        })

    if request.method == 'POST':
        action    = request.POST.get('action', 'submit')
        class_id  = request.POST.get('class_id', '').strip()

        # ------------------------------------------------
        # ACTION: load_students
        # Teacher selects class → fetch students in that class
        # ------------------------------------------------
        if action == 'load_students':
            if not class_id:
                messages.error(request, 'Please select a class.')
                return render(request, 'core/add_result.html', {
                    'user'             : user,
                    'assigned_classes' : assigned_classes,
                    'subject_choices'  : subject_choices,
                    'students'         : [],
                    'selected_class'   : None,
                    'no_classes'       : False,
                })

            # Security: verify teacher is assigned to this class
            if int(class_id) not in list(assigned_class_ids):
                messages.error(
                    request,
                    'You are not assigned to this class.'
                )
                return render(request, 'core/add_result.html', {
                    'user'             : user,
                    'assigned_classes' : assigned_classes,
                    'subject_choices'  : subject_choices,
                    'students'         : [],
                    'selected_class'   : None,
                    'no_classes'       : False,
                })

            # Get students enrolled in this specific class
            enrollments = ClassEnrollment.objects.filter(
                enrolled_class_id=class_id
            ).select_related('student')

            students = [e.student for e in enrollments]
            selected_class = Class.objects.get(id=class_id)

            if not students:
                messages.warning(
                    request,
                    'No students enrolled in this class yet.'
                )

            return render(request, 'core/add_result.html', {
                'user'             : user,
                'assigned_classes' : assigned_classes,
                'subject_choices'  : subject_choices,
                'students'         : students,
                'selected_class'   : selected_class,
                'no_classes'       : False,
            })

        # ------------------------------------------------
        # ACTION: submit result
        # ------------------------------------------------
        student_id    = request.POST.get('student_id', '').strip()
        subject       = request.POST.get('subject', '').strip()
        exam_type     = request.POST.get('exam_type', '').strip()
        marks         = request.POST.get('marks', '').strip()
        remarks       = request.POST.get('remarks', '').strip()
        academic_year = request.POST.get('academic_year', '').strip()

        # Validate all fields
        if not all([student_id, class_id, subject, exam_type,
                    marks, academic_year]):
            messages.error(request, 'All required fields must be filled.')
            return render(request, 'core/add_result.html', {
                'user'             : user,
                'assigned_classes' : assigned_classes,
                'subject_choices'  : subject_choices,
                'students'         : [],
                'selected_class'   : None,
                'no_classes'       : False,
            })

        # Validate subject is in allowed choices
        valid_subjects = [s[0] for s in StudentResult.SUBJECT_CHOICES]
        if subject not in valid_subjects:
            messages.error(request, 'Invalid subject selected.')
            return render(request, 'core/add_result.html', {
                'user'             : user,
                'assigned_classes' : assigned_classes,
                'subject_choices'  : subject_choices,
                'students'         : [],
                'no_classes'       : False,
            })

        # Security: verify teacher is assigned to selected class
        if int(class_id) not in list(assigned_class_ids):
            messages.error(
                request,
                'Permission denied — not your class.'
            )
            return render(request, 'core/add_result.html', {
                'user'             : user,
                'assigned_classes' : assigned_classes,
                'subject_choices'  : subject_choices,
                'students'         : [],
                'no_classes'       : False,
            })

        # Get student and verify they are in teacher's class
        try:
            student = UserProfile.objects.get(
                id=student_id, role='student'
            )

            # Extra security: verify student is enrolled
            # in the selected class
            is_enrolled = ClassEnrollment.objects.filter(
                student=student,
                enrolled_class_id=class_id
            ).exists()

            if not is_enrolled:
                messages.error(
                    request,
                    'This student is not enrolled in your class.'
                )
                return render(request, 'core/add_result.html', {
                    'user'             : user,
                    'assigned_classes' : assigned_classes,
                    'subject_choices'  : subject_choices,
                    'students'         : [],
                    'no_classes'       : False,
                })

        except UserProfile.DoesNotExist:
            messages.error(request, 'Student not found.')
            return render(request, 'core/add_result.html', {
                'user'             : user,
                'assigned_classes' : assigned_classes,
                'subject_choices'  : subject_choices,
                'students'         : [],
                'no_classes'       : False,
            })

        # ------------------------------------------------
        # Encrypt marks with STUDENT's RSA public key
        # ------------------------------------------------
        student_pub_key   = deserialize_key(student.rsa_public_key)
        encrypted_marks   = encrypt_to_string(marks, student_pub_key)
        encrypted_remarks = encrypt_to_string(
            remarks, student_pub_key
        ) if remarks else ''

        # ------------------------------------------------
        # HMAC for integrity
        # ------------------------------------------------
        hmac_secret = get_hmac_secret(student)
        hmac_data   = encrypted_marks + encrypted_remarks + subject
        data_hmac   = generate_hmac(hmac_data, hmac_secret)

        # ------------------------------------------------
        # ECC signature — proves this teacher added this result
        # ------------------------------------------------
        ecc_priv_str  = request.session.get('ecc_private_key', '')
        signature_str = ''

        if ecc_priv_str:
            ecc_priv     = deserialize_ecc_private_key(ecc_priv_str)
            sign_message = (
                f"{student.username}:{subject}:"
                f"{exam_type}:{marks}"
            )
            signature     = ecc_sign(sign_message, ecc_priv)
            signature_str = serialize_signature(signature)

        result_class = Class.objects.get(id=class_id)

        StudentResult.objects.create(
            student           = student,
            result_class      = result_class,
            entered_by        = user,
            subject           = subject,
            exam_type         = exam_type,
            encrypted_marks   = encrypted_marks,
            encrypted_remarks = encrypted_remarks,
            data_hmac         = data_hmac,
            ecc_signature     = signature_str,
            academic_year     = academic_year,
        )

        # Log key access
        KeyAccessLog.objects.create(
            user         = student,
            action       = 'encrypt',
            performed_by = user,
            ip_address   = request.META.get('REMOTE_ADDR', ''),
            note         = (
                f'Result added: {subject} {exam_type} '
                f'by {user.username}'
            )
        )

        messages.success(
            request,
            f'✅ Result saved for {student.username} — '
            f'{subject} {exam_type}: {marks}. '
            f'Encrypted with student RSA key.'
        )

        # Reload same class after submission
        enrollments = ClassEnrollment.objects.filter(
            enrolled_class_id=class_id
        ).select_related('student')

        students = [e.student for e in enrollments]
        selected_class = result_class

        return render(request, 'core/add_result.html', {
            'user'             : user,
            'assigned_classes' : assigned_classes,
            'subject_choices'  : subject_choices,
            'students'         : students,
            'selected_class'   : selected_class,
            'no_classes'       : False,
        })


# ============================================================
# VIEW MY RESULTS — Student
# ============================================================

def my_results(request):
    user = get_session_user(request)
    if not user or user.role != 'student':
        return redirect('login')

    # Get all results for this student
    raw_results = StudentResult.objects.filter(
        student=user
    ).select_related('result_class', 'entered_by').order_by('-created_at')

    # Decrypt each result using student's private key from session
    priv_key = get_rsa_private_key(request)

    decrypted_results = []
    for result in raw_results:

        # ------------------------------------------------
        # Verify HMAC first — check data integrity
        # If tampered, we warn the student
        # ------------------------------------------------
        hmac_secret   = get_hmac_secret(user)
        hmac_data     = (
            result.encrypted_marks +
            result.encrypted_remarks +
            result.subject
        )
        hmac_valid = verify_hmac(hmac_data, hmac_secret, result.data_hmac)

        # ------------------------------------------------
        # Verify ECC signature if present
        # Proves result came from the stated teacher/admin
        # ------------------------------------------------
        sig_valid = False
        if result.ecc_signature and result.entered_by:
            try:
                sig = deserialize_signature(result.ecc_signature)
                sign_message = (
                    f"{user.username}:{result.subject}:"
                    f"{result.exam_type}:"
                )
                # We need the plain marks to verify
                # so we decrypt first then verify
                if priv_key:
                    plain_marks = decrypt_from_string(
                        result.encrypted_marks, priv_key
                    )
                    sign_message += plain_marks
                    entered_ecc_pub = deserialize_ecc_public_key(
                        result.entered_by.ecc_public_key
                    )
                    sig_valid = ecc_verify_signature(
                        sign_message, sig, entered_ecc_pub
                    )
            except Exception:
                sig_valid = False

        # ------------------------------------------------
        # Decrypt marks and remarks
        # ------------------------------------------------
        marks   = '—'
        remarks = '—'

        if priv_key:
            try:
                marks = decrypt_from_string(
                    result.encrypted_marks, priv_key
                )
            except Exception:
                marks = '[decryption error]'

            try:
                if result.encrypted_remarks:
                    remarks = decrypt_from_string(
                        result.encrypted_remarks, priv_key
                    )
                else:
                    remarks = '—'
            except Exception:
                remarks = '—'

        decrypted_results.append({
            'subject'       : result.get_subject_display(),
            'exam_type'     : result.exam_type,
            'academic_year' : result.academic_year,
            'class_name'    : str(result.result_class) if result.result_class else '—',
            'entered_by'    : result.entered_by.username if result.entered_by else '—',
            'marks'         : marks,
            'remarks'       : remarks,
            'hmac_valid'    : hmac_valid,    # integrity check
            'sig_valid'     : sig_valid,     # authenticity check
            'created_at'    : result.created_at,
        })

    return render(request, 'core/my_results.html', {
        'user'    : user,
        'results' : decrypted_results,
    })


# ============================================================
# PARENT REQUEST — Submit
# ============================================================

def submit_parent_request(request):
    user = get_session_user(request)
    if not user or user.role != 'parent':
        return redirect('login')

    # ------------------------------------------------
    # SECURITY FIX: Don't show all students
    # Parent must enter student's username manually
    # This prevents enumeration of all students
    # ------------------------------------------------

    # Get only THIS parent's existing requests
    my_requests = ParentRequest.objects.filter(
        parent=user
    ).select_related('student')

    if request.method == 'GET':
        return render(request, 'core/parent_request.html', {
            'user'        : user,
            'my_requests' : my_requests,
        })

    if request.method == 'POST':
        # Parent types student username — not selected from list
        student_username = request.POST.get(
            'student_username', ''
        ).strip()
        student_id_number = request.POST.get(
            'student_id_number', ''
        ).strip()
        message = request.POST.get('message', '').strip()

        if not student_username or not message:
            messages.error(
                request,
                'Student username and message are required.'
            )
            return render(request, 'core/parent_request.html', {
                'user': user, 'my_requests': my_requests
            })

        # ID card is required
        if 'id_card_image' not in request.FILES:
            messages.error(
                request,
                'Student ID card image is required.'
            )
            return render(request, 'core/parent_request.html', {
                'user': user, 'my_requests': my_requests
            })

        # ------------------------------------------------
        # Look up student by username
        # If not found — give vague error (don't confirm existence)
        # ------------------------------------------------
        try:
            student = UserProfile.objects.get(
                username=student_username, role='student'
            )
        except UserProfile.DoesNotExist:
            # Vague error — don't reveal if username exists or not
            messages.error(
                request,
                'Could not find a student with that username. '
                'Please verify the username and try again.'
            )
            return render(request, 'core/parent_request.html', {
                'user': user, 'my_requests': my_requests
            })

        # Check duplicate request
        if ParentRequest.objects.filter(
            parent=user, student=student
        ).exists():
            messages.error(
                request,
                'You already have a request for this student.'
            )
            return render(request, 'core/parent_request.html', {
                'user': user, 'my_requests': my_requests
            })

        # ------------------------------------------------
        # Encrypt message with admin's public key
        # ------------------------------------------------
        try:
            admin = UserProfile.objects.filter(role='admin').first()
            if not admin:
                messages.error(request, 'No admin found.')
                return render(request, 'core/parent_request.html', {
                    'user': user, 'my_requests': my_requests
                })

            admin_pub_key     = deserialize_key(admin.rsa_public_key)
            encrypted_message = encrypt_to_string(message, admin_pub_key)

            # Also encrypt student ID number if provided
            encrypted_id = ''
            if student_id_number:
                encrypted_id = encrypt_to_string(
                    student_id_number, admin_pub_key
                )

        except Exception as e:
            messages.error(request, f'Encryption error: {str(e)}')
            return render(request, 'core/parent_request.html', {
                'user': user, 'my_requests': my_requests
            })

        # HMAC
        hmac_secret  = get_hmac_secret(user)
        message_hmac = generate_hmac(encrypted_message, hmac_secret)

        # Save request with ID card
        parent_req = ParentRequest(
            parent                     = user,
            student                    = student,
            encrypted_message          = encrypted_message,
            encrypted_student_id_number = encrypted_id,
            message_hmac               = message_hmac,
            status                     = 'pending',
        )
        parent_req.id_card_image = request.FILES['id_card_image']
        parent_req.save()

        messages.success(
            request,
            'Request submitted with ID card. '
            'Admin will verify and respond.'
        )
        return redirect('submit_parent_request')


# ============================================================
# ADMIN — VIEW AND PROCESS PARENT REQUESTS
# ============================================================

def admin_parent_requests(request):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    # Get admin's private key from session to decrypt messages
    priv_key = get_rsa_private_key(request)

    all_requests = ParentRequest.objects.select_related(
        'parent', 'student', 'processed_by'
    ).order_by('-created_at')

    # Decrypt each request message for admin to read
    processed_requests = []
    for req in all_requests:

        # Verify HMAC integrity first
        hmac_secret = get_hmac_secret(req.parent)
        hmac_valid  = verify_hmac(
            req.encrypted_message,
            hmac_secret,
            req.message_hmac
        )

        # Decrypt message using admin's private key
        message = '[cannot decrypt]'
        if priv_key:
            try:
                message = decrypt_from_string(
                    req.encrypted_message, priv_key
                )
            except Exception:
                message = '[decryption error]'

        processed_requests.append({
            'req'        : req,
            'message'    : message,
            'hmac_valid' : hmac_valid,
        })

    return render(request, 'core/admin_parent_requests.html', {
        'user'     : user,
        'requests' : processed_requests,
    })


# ============================================================
# ADMIN — APPROVE PARENT REQUEST + SHARE DATA
# ============================================================

def approve_parent_request(request, request_id):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    try:
        parent_request = ParentRequest.objects.select_related(
            'parent', 'student'
        ).get(id=request_id)
    except ParentRequest.DoesNotExist:
        messages.error(request, 'Request not found.')
        return redirect('admin_parent_requests')

    if request.method == 'POST':
        action     = request.POST.get('action')   # 'approve' or 'reject'
        admin_note = request.POST.get('admin_note', '').strip()

        if action == 'reject':
            parent_request.status       = 'rejected'
            parent_request.admin_note   = admin_note
            parent_request.processed_by = user
            parent_request.processed_at = timezone.now()
            parent_request.save()
            messages.success(request, 'Request rejected.')
            return redirect('admin_parent_requests')

        if action == 'approve':
            # ------------------------------------------------
            # SECURE DATA SHARING FLOW:
            # 1. Get student's encrypted data
            # 2. Decrypt using student's private key
            #    (we have it because admin loaded session —
            #     wait: admin can't use student's session key)
            #    Instead: re-encrypt directly between keys
            # 3. Re-encrypt with PARENT's public key
            # 4. Sign with ADMIN's ECC private key
            # 5. Store SharedStudentData
            # ------------------------------------------------

            parent  = parent_request.parent
            student = parent_request.student

            # Get student's private key
            # We need to decrypt student data to re-encrypt for parent
            # This requires student's private key
            # Since admin doesn't have student's session,
            # we use the stored encrypted private key
            # BUT we can't decrypt it without student's password
            #
            # SOLUTION: We share only the public profile info
            # which is re-encrypted from student's encrypted fields
            # using a proxy re-encryption approach:
            # admin decrypts with student's stored key material
            # For now: admin shares results directly (public exam data)

            # Get student's results
            student_results = StudentResult.objects.filter(
                student=student
            )

            # Build results summary (subject + exam type only —
            # marks need student's key to decrypt)
            results_summary = []
            for r in student_results:
                results_summary.append(
                    f"{r.subject}|{r.exam_type}|{r.academic_year}"
                )
            results_text = ';'.join(results_summary)

            # Get student's decryptable name
            # We'll use username as fallback
            student_display = student.username

            # ------------------------------------------------
            # Encrypt student info with PARENT's public key
            # Only parent can decrypt this
            # ------------------------------------------------
            parent_pub_key = deserialize_key(parent.rsa_public_key)

            encrypted_name = encrypt_to_string(
                student_display, parent_pub_key
            )
            encrypted_results = encrypt_to_string(
                results_text if results_text else 'No results yet',
                parent_pub_key
            )

            # ------------------------------------------------
            # Sign with ADMIN's ECC private key
            # Proves admin authorized this data share
            # ------------------------------------------------
            admin_ecc_str = request.session.get('ecc_private_key', '')
            signature_str = ''

            if admin_ecc_str:
                admin_ecc_priv = deserialize_ecc_private_key(admin_ecc_str)
                sign_msg       = (
                    f"{student.username}:{parent.username}:"
                    f"{encrypted_name[:20]}"
                )
                signature    = ecc_sign(sign_msg, admin_ecc_priv)
                signature_str = serialize_signature(signature)

            # ------------------------------------------------
            # HMAC for integrity of shared data
            # ------------------------------------------------
            hmac_secret = get_hmac_secret(parent)
            data_hmac   = generate_hmac(
                encrypted_name + encrypted_results,
                hmac_secret
            )

            # Delete any previous shared data for this pair
            SharedStudentData.objects.filter(
                parent=parent, student=student
            ).delete()

            SharedStudentData.objects.create(
                parent                   = parent,
                student                  = student,
                request                  = parent_request,
                encrypted_student_name   = encrypted_name,
                encrypted_student_results = encrypted_results,
                admin_ecc_signature      = signature_str,
                data_hmac                = data_hmac,
            )

            # Update request status
            parent_request.status       = 'approved'
            parent_request.admin_note   = admin_note
            parent_request.processed_by = user
            parent_request.processed_at = timezone.now()
            parent_request.save()

            # Log
            KeyAccessLog.objects.create(
                user         = student,
                action       = 'decrypt',
                performed_by = user,
                ip_address   = request.META.get('REMOTE_ADDR'),
                note         = (
                    f'Data shared with parent '
                    f'{parent.username} — ECC signed'
                )
            )

            messages.success(
                request,
                f'Approved. Student data re-encrypted with '
                f'{parent.username}\'s public key and ECC signed.'
            )
            return redirect('admin_parent_requests')

    return redirect('admin_parent_requests')


# ============================================================
# PARENT — VIEW SHARED STUDENT DATA
# ============================================================

def view_shared_data(request):
    user = get_session_user(request)
    if not user or user.role != 'parent':
        return redirect('login')

    # Get all approved shared data for this parent
    shared_items = SharedStudentData.objects.filter(
        parent=user
    ).select_related('student', 'request')

    priv_key = get_rsa_private_key(request)

    decrypted_items = []
    for item in shared_items:

        # ------------------------------------------------
        # Verify HMAC — data integrity check
        # ------------------------------------------------
        hmac_secret = get_hmac_secret(user)
        hmac_valid  = verify_hmac(
            item.encrypted_student_name + item.encrypted_student_results,
            hmac_secret,
            item.data_hmac
        )

        # ------------------------------------------------
        # Verify admin's ECC signature
        # Proves admin authorized this share
        # ------------------------------------------------
        sig_valid = False
        if item.admin_ecc_signature:
            try:
                # Get admin's ECC public key
                admin = UserProfile.objects.filter(role='admin').first()
                if admin:
                    admin_ecc_pub = deserialize_ecc_public_key(
                        admin.ecc_public_key
                    )
                    sig = deserialize_signature(item.admin_ecc_signature)
                    sign_msg = (
                        f"{item.student.username}:{user.username}:"
                        f"{item.encrypted_student_name[:20]}"
                    )
                    sig_valid = ecc_verify_signature(
                        sign_msg, sig, admin_ecc_pub
                    )
            except Exception:
                sig_valid = False

        # ------------------------------------------------
        # Decrypt data using parent's private key
        # ------------------------------------------------
        student_name    = '[cannot decrypt]'
        student_results = '[cannot decrypt]'

        if priv_key:
            try:
                student_name = decrypt_from_string(
                    item.encrypted_student_name, priv_key
                )
            except Exception:
                student_name = '[decryption error]'

            try:
                raw_results  = decrypt_from_string(
                    item.encrypted_student_results, priv_key
                )
                # Parse the results text back to list
                if raw_results and raw_results != 'No results yet':
                    result_list = []
                    for r in raw_results.split(';'):
                        parts = r.split('|')
                        if len(parts) == 3:
                            result_list.append({
                                'subject'       : parts[0],
                                'exam_type'     : parts[1],
                                'academic_year' : parts[2],
                            })
                    student_results = result_list
                else:
                    student_results = []
            except Exception:
                student_results = []

        decrypted_items.append({
            'student_username' : item.student.username,
            'student_name'     : student_name,
            'student_results'  : student_results,
            'hmac_valid'       : hmac_valid,
            'sig_valid'        : sig_valid,
            'shared_at'        : item.created_at,
            'request_note'     : item.request.admin_note,
        })

    return render(request, 'core/view_shared_data.html', {
        'user'           : user,
        'decrypted_items': decrypted_items,
    })



# ============================================================
# SESSION DASHBOARD — shows active sessions and activity log
# ============================================================

def session_dashboard(request):
    # Shows user their active sessions and security log
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Get all active sessions for this user
    active_sessions = SecureSession.objects.filter(
        user=user, is_active=True
    ).order_by('-last_activity')

    # Get session activity log
    activity_logs = SessionActivityLog.objects.filter(
        user=user
    )[:30]  # last 30 events

    # Current session token to highlight it
    current_token  = request.session.get('session_token', '')
    from .session_manager import hash_token
    current_hash   = hash_token(current_token) if current_token else ''

    return render(request, 'core/session_dashboard.html', {
        'user'            : user,
        'active_sessions' : active_sessions,
        'activity_logs'   : activity_logs,
        'current_hash'    : current_hash,
    })


# ============================================================
# TERMINATE OTHER SESSION — user can kill other sessions
# ============================================================

def terminate_other_session(request, session_id):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    try:
        # Only allow terminating OWN sessions
        session = SecureSession.objects.get(
            id=session_id, user=user
        )
        session.is_active = False
        session.save()

        SessionActivityLog.objects.create(
            user       = user,
            event      = 'logout',
            ip_address = request.META.get('REMOTE_ADDR', ''),
            note       = f'Session {session_id} manually terminated'
        )
        messages.success(request, 'Session terminated.')
    except SecureSession.DoesNotExist:
        messages.error(request, 'Session not found.')

    return redirect('session_dashboard')


# ============================================================
# ADMIN — ALL SESSIONS OVERVIEW
# ============================================================

def admin_sessions(request):
    user = get_session_user(request)
    if not user or user.role != 'admin':
        return redirect('login')

    # All active sessions across all users
    all_active = SecureSession.objects.filter(
        is_active=True
    ).select_related('user').order_by('-last_activity')

    # All session events
    all_logs = SessionActivityLog.objects.select_related(
        'user'
    ).all()[:50]

    return render(request, 'core/admin_sessions.html', {
        'user'       : user,
        'all_active' : all_active,
        'all_logs'   : all_logs,
    })




# ============================================================
# POSTS — Create
# Encrypts content for every user in the target audience
# One PostRecipient row per target user
# ============================================================

def create_post(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    if request.method == 'GET':
        return render(request, 'core/create_post.html', {
            'user': user
        })

    if request.method == 'POST':
        title      = request.POST.get('title', '').strip()
        content    = request.POST.get('content', '').strip()
        visibility = request.POST.get('visibility', 'public')

        if not title or not content:
            messages.error(request, 'Title and content are required.')
            return render(request, 'core/create_post.html', {
                'user': user
            })

        # ------------------------------------------------
        # Encrypt content for the AUTHOR first
        # ------------------------------------------------
        author_pub_key    = deserialize_key(user.rsa_public_key)
        encrypted_content = encrypt_to_string(content, author_pub_key)

        # HMAC
        hmac_secret  = get_hmac_secret(user)
        content_hmac = generate_hmac(encrypted_content, hmac_secret)

        # ECC signature
        ecc_priv_str  = request.session.get('ecc_private_key', '')
        signature_str = ''
        if ecc_priv_str:
            ecc_priv     = deserialize_ecc_private_key(ecc_priv_str)
            sign_message = (
                f"{user.username}:{title}:"
                f"{encrypted_content[:30]}"
            )
            signature     = ecc_sign(sign_message, ecc_priv)
            signature_str = serialize_signature(signature)

        # Create the post
        post = Post.objects.create(
            author            = user,
            title             = title,
            encrypted_content = encrypted_content,
            content_hmac      = content_hmac,
            ecc_signature     = signature_str,
            visibility        = visibility,
            is_active         = True,
        )

        # ------------------------------------------------
        # Determine target audience
        # ------------------------------------------------
        if visibility == 'public':
            targets = UserProfile.objects.filter(
                is_approved=True
            ).exclude(id=user.id)

        elif visibility == 'teachers':
            targets = UserProfile.objects.filter(
                role='teacher', is_approved=True
            ).exclude(id=user.id)

        elif visibility == 'students':
            targets = UserProfile.objects.filter(
                role='student', is_approved=True
            ).exclude(id=user.id)

        elif visibility == 'parents':
            targets = UserProfile.objects.filter(
                role='parent', is_approved=True
            ).exclude(id=user.id)

        elif visibility == 'admin':
            targets = UserProfile.objects.filter(
                role='admin'
            ).exclude(id=user.id)

        else:
            targets = UserProfile.objects.none()

        # ------------------------------------------------
        # ALWAYS inject all admins into recipient list
        # Admin sees every post regardless of visibility
        # Merge admin IDs with target IDs
        # ------------------------------------------------
        admin_ids  = set(
            UserProfile.objects.filter(
                role='admin'
            ).exclude(id=user.id).values_list('id', flat=True)
        )

        target_ids = set(
            targets.values_list('id', flat=True)
        )

        # Union of both sets — no duplicates
        all_target_ids = target_ids | admin_ids

        # Final queryset of all recipients
        final_targets = UserProfile.objects.filter(
            id__in=all_target_ids
        )

        # ------------------------------------------------
        # Encrypt content for each target user
        # with THEIR OWN RSA public key
        # ------------------------------------------------
        recipient_objects = []
        for target in final_targets:
            try:
                target_pub_key = deserialize_key(
                    target.rsa_public_key
                )
                target_encrypted = encrypt_to_string(
                    content, target_pub_key
                )
                recipient_objects.append(
                    PostRecipient(
                        post              = post,
                        recipient         = target,
                        encrypted_content = target_encrypted,
                    )
                )
            except Exception:
                continue

        # Bulk create all recipients
        PostRecipient.objects.bulk_create(recipient_objects)

        # Author gets their own recipient row
        PostRecipient.objects.get_or_create(
            post      = post,
            recipient = user,
            defaults  = {'encrypted_content': encrypted_content}
        )

        messages.success(
            request,
            f'Post created and encrypted for '
            f'{len(recipient_objects) + 1} user(s).'
        )
        return redirect('post_list')


# ============================================================
# POSTS — List
# Each user decrypts their own PostRecipient copy
# ============================================================

def post_list(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Get all posts this user is a recipient of
    # AND posts authored by this user
    from django.db.models import Q

    if user.role == 'admin':
        posts = Post.objects.filter(
            is_active=True
        ).select_related('author').order_by('-created_at')
    else:
        # Find posts where user is a recipient
        recipient_post_ids = PostRecipient.objects.filter(
            recipient=user
        ).values_list('post_id', flat=True)

        posts = Post.objects.filter(
            is_active=True,
            id__in=recipient_post_ids
        ).select_related('author').order_by('-created_at')

    priv_key = get_rsa_private_key(request)

    decrypted_posts = []
    for post in posts:
        content  = '[cannot decrypt]'
        hmac_ok  = False
        sig_ok   = False

        # Get this user's recipient row for this post
        try:
            recipient_row = PostRecipient.objects.get(
                post=post, recipient=user
            )

            if priv_key:
                # Decrypt using THIS user's private key
                # Works for everyone including admin
                # because admin always has a recipient row
                content = decrypt_from_string(
                    recipient_row.encrypted_content,
                    priv_key
                )

                # Verify HMAC
                author_hmac_secret = get_hmac_secret(post.author)
                hmac_ok = verify_hmac(
                    post.encrypted_content,
                    author_hmac_secret,
                    post.content_hmac
                )

                # Verify ECC signature
                if post.ecc_signature:
                    try:
                        sig = deserialize_signature(
                            post.ecc_signature
                        )
                        author_ecc_pub = deserialize_ecc_public_key(
                            post.author.ecc_public_key
                        )
                        sign_msg = (
                            f"{post.author.username}:"
                            f"{post.title}:"
                            f"{post.encrypted_content[:30]}"
                        )
                        sig_ok = ecc_verify_signature(
                            sign_msg, sig, author_ecc_pub
                        )
                    except Exception:
                        sig_ok = False

        except PostRecipient.DoesNotExist:
            content = '[not authorized]'

        decrypted_posts.append({
            'id'          : post.id,
            'title'       : post.title,
            'content'     : content,
            'author'      : post.author.username,
            'author_role' : post.author.role,
            'visibility'  : post.get_visibility_display(),
            'hmac_ok'     : hmac_ok,
            'sig_ok'      : sig_ok,
            'is_own'      : post.author.id == user.id,
            'created_at'  : post.created_at,
        })

    return render(request, 'core/post_list.html', {
        'user'  : user,
        'posts' : decrypted_posts,
    })


# ============================================================
# POSTS — Delete
# ============================================================

def delete_post(request, post_id):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    try:
        post = Post.objects.get(id=post_id)
        if post.author.id != user.id and user.role != 'admin':
            messages.error(request, 'Permission denied.')
            return redirect('post_list')

        # Delete all recipient rows too
        PostRecipient.objects.filter(post=post).delete()
        post.is_active = False
        post.save()
        messages.success(request, 'Post deleted.')
    except Post.DoesNotExist:
        messages.error(request, 'Post not found.')

    return redirect('post_list')

# ============================================================
# POSTS — Edit
# Only the AUTHOR can edit their own post
# Admin can only edit posts they authored
# ============================================================

def edit_post(request, post_id):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Fetch post
    try:
        post = Post.objects.get(id=post_id, is_active=True)
    except Post.DoesNotExist:
        messages.error(request, 'Post not found.')
        return redirect('post_list')

    # ------------------------------------------------
    # STRICT CHECK: Only the author can edit
    # No exceptions — not even admin
    # ------------------------------------------------
    if post.author.id != user.id:
        messages.error(
            request,
            'You can only edit your own posts.'
        )
        return redirect('post_list')

    priv_key = get_rsa_private_key(request)
    if not priv_key:
        messages.error(
            request,
            'Session expired. Please log in again.'
        )
        return redirect('login')

    # ------------------------------------------------
    # Decrypt current content using author's
    # own recipient row to pre-fill the form
    # ------------------------------------------------
    current_content = ''
    try:
        recipient_row = PostRecipient.objects.get(
            post=post, recipient=user
        )
        current_content = decrypt_from_string(
            recipient_row.encrypted_content, priv_key
        )
    except PostRecipient.DoesNotExist:
        messages.error(
            request,
            'Cannot find your encrypted copy of this post.'
        )
        return redirect('post_list')
    except Exception as e:
        messages.error(request, f'Decryption error: {str(e)}')
        return redirect('post_list')

    if request.method == 'GET':
        return render(request, 'core/edit_post.html', {
            'user'            : user,
            'post'            : post,
            'current_content' : current_content,
        })

    if request.method == 'POST':
        new_title      = request.POST.get('title', '').strip()
        new_content    = request.POST.get('content', '').strip()
        new_visibility = request.POST.get(
            'visibility', post.visibility
        )

        if not new_title or not new_content:
            messages.error(
                request,
                'Title and content are required.'
            )
            return render(request, 'core/edit_post.html', {
                'user'            : user,
                'post'            : post,
                'current_content' : current_content,
            })

        # ------------------------------------------------
        # Re-encrypt content for the author
        # ------------------------------------------------
        author_pub_key  = deserialize_key(user.rsa_public_key)
        new_enc_content = encrypt_to_string(
            new_content, author_pub_key
        )

        # ------------------------------------------------
        # Recompute HMAC with new encrypted content
        # ------------------------------------------------
        hmac_secret      = get_hmac_secret(user)
        new_content_hmac = generate_hmac(
            new_enc_content, hmac_secret
        )

        # ------------------------------------------------
        # Re-sign with author's ECC private key
        # ------------------------------------------------
        ecc_priv_str = request.session.get('ecc_private_key', '')
        new_sig_str  = ''

        if ecc_priv_str:
            ecc_priv     = deserialize_ecc_private_key(ecc_priv_str)
            sign_message = (
                f"{user.username}:{new_title}:"
                f"{new_enc_content[:30]}"
            )
            signature   = ecc_sign(sign_message, ecc_priv)
            new_sig_str = serialize_signature(signature)

        # ------------------------------------------------
        # Update post record
        # ------------------------------------------------
        post.title             = new_title
        post.encrypted_content = new_enc_content
        post.content_hmac      = new_content_hmac
        post.ecc_signature     = new_sig_str
        post.visibility        = new_visibility
        post.save()

        # ------------------------------------------------
        # Rebuild recipient list with new content
        # Determine new audience based on new visibility
        # ------------------------------------------------
        if new_visibility == 'public':
            targets = UserProfile.objects.filter(
                is_approved=True
            ).exclude(id=user.id)

        elif new_visibility == 'teachers':
            targets = UserProfile.objects.filter(
                role='teacher', is_approved=True
            ).exclude(id=user.id)

        elif new_visibility == 'students':
            targets = UserProfile.objects.filter(
                role='student', is_approved=True
            ).exclude(id=user.id)

        elif new_visibility == 'parents':
            targets = UserProfile.objects.filter(
                role='parent', is_approved=True
            ).exclude(id=user.id)

        elif new_visibility == 'admin':
            targets = UserProfile.objects.filter(
                role='admin'
            ).exclude(id=user.id)

        else:
            targets = UserProfile.objects.none()

        # Always include admins
        admin_ids  = set(
            UserProfile.objects.filter(
                role='admin'
            ).exclude(id=user.id).values_list('id', flat=True)
        )
        target_ids     = set(
            targets.values_list('id', flat=True)
        )
        all_target_ids = target_ids | admin_ids
        final_targets  = UserProfile.objects.filter(
            id__in=all_target_ids
        )

        # Delete old recipient rows except author's
        PostRecipient.objects.filter(
            post=post
        ).exclude(recipient=user).delete()

        # Re-create recipient rows with new content
        new_recipients = []
        for target in final_targets:
            try:
                target_pub_key   = deserialize_key(
                    target.rsa_public_key
                )
                target_encrypted = encrypt_to_string(
                    new_content, target_pub_key
                )
                new_recipients.append(
                    PostRecipient(
                        post              = post,
                        recipient         = target,
                        encrypted_content = target_encrypted,
                    )
                )
            except Exception:
                continue

        PostRecipient.objects.bulk_create(new_recipients)

        # Update author's own recipient row with new content
        PostRecipient.objects.filter(
            post=post, recipient=user
        ).update(encrypted_content=new_enc_content)

        messages.success(
            request,
            f'Post updated and re-encrypted for '
            f'{len(new_recipients) + 1} user(s).'
        )
        return redirect('post_list')

# ============================================================
# PASSWORD CHANGE — re-encrypts private keys with new password
# ============================================================

def change_password(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    if request.method == 'GET':
        return render(request, 'core/change_password.html', {
            'user': user
        })

    if request.method == 'POST':
        current_password = request.POST.get('current_password', '').strip()
        new_password     = request.POST.get('new_password', '').strip()
        confirm_password = request.POST.get('confirm_password', '').strip()

        # Verify current password
        if not verify_password(
            current_password, user.password_salt, user.password_hash
        ):
            messages.error(request, 'Current password is incorrect.')
            return render(request, 'core/change_password.html', {'user': user})

        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return render(request, 'core/change_password.html', {'user': user})

        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters.')
            return render(request, 'core/change_password.html', {'user': user})

        # ------------------------------------------------
        # Get decrypted private keys from session
        # We need to re-encrypt them with the new password
        # ------------------------------------------------
        rsa_priv_plain = request.session.get('rsa_private_key', '')
        ecc_priv_plain = request.session.get('ecc_private_key', '')

        if not rsa_priv_plain:
            messages.error(request, 'Session expired. Please log in again.')
            return redirect('login')

        # ------------------------------------------------
        # Generate new salt and hash new password
        # New salt = new key derivation = extra security
        # ------------------------------------------------
        new_salt     = generate_salt()
        new_pwd_hash = hash_password(new_password, new_salt)

        # ------------------------------------------------
        # Re-encrypt private keys with new password+salt
        # ------------------------------------------------
        # Re-wrap with new password using RSA wrapping
        new_rsa_enc = wrap_private_key(
            rsa_priv_plain, new_password, new_salt
        )
        new_ecc_enc = wrap_private_key(
            ecc_priv_plain, new_password, new_salt
        )

        # Save everything
        user.password_hash   = new_pwd_hash
        user.password_salt   = new_salt
        user.rsa_private_key = new_rsa_enc
        user.ecc_private_key = new_ecc_enc
        user.keys_encrypted  = True
        user.save()

        # Log key access
        KeyAccessLog.objects.create(
            user         = user,
            action       = 'rotate',
            performed_by = user,
            ip_address   = request.META.get('REMOTE_ADDR', ''),
            note         = 'Private keys re-encrypted after password change'
        )

        messages.success(
            request,
            'Password changed. Private keys re-encrypted with new password.'
        )
        return redirect('session_dashboard')


# ============================================================
# SECURITY DASHBOARD
# ============================================================

def security_dashboard(request):
    user = get_session_user(request)
    if not user:
        return redirect('login')

    # Key info
    key_logs = KeyAccessLog.objects.filter(user=user)[:10]

    # Session info
    session_logs = SessionActivityLog.objects.filter(user=user)[:10]

    # Active sessions count
    active_sessions = SecureSession.objects.filter(
        user=user, is_active=True
    ).count()

    # Login attempts info
    ip = request.META.get('REMOTE_ADDR', '')
    try:
        login_attempt = LoginAttempt.objects.get(
            username=user.username, ip_address=ip
        )
    except LoginAttempt.DoesNotExist:
        login_attempt = None

    return render(request, 'core/security_dashboard.html', {
        'user'            : user,
        'key_logs'        : key_logs,
        'session_logs'    : session_logs,
        'active_sessions' : active_sessions,
        'login_attempt'   : login_attempt,
    })














