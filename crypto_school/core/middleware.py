# ============================================================
# middleware.py — Role Based Access Control
# Runs on every request before the view executes
# ============================================================

from django.shortcuts import redirect
from django.urls import reverse
from django.utils import timezone


# ============================================================
# URL ACCESS RULES
# Define which roles can access which URL names
# ============================================================

# URLs anyone can access without logging in
PUBLIC_URLS = [
    '/register/',
    '/login/',
    '/verify-otp/',
    '/pending/',
    '/',
]

# URL name prefixes → allowed roles
# Key   = URL prefix
# Value = list of roles allowed
ROLE_URL_MAP = {
    '/dashboard/student/'  : ['student'],
    '/dashboard/teacher/'  : ['teacher'],
    '/dashboard/parent/'   : ['parent'],
    '/dashboard/admin/'    : ['admin'],


    
    '/profile/'            : ['student', 'teacher', 'parent', 'admin'],
    '/classes/'            : ['admin', 'teacher', 'student'],
    '/admin-panel/'        : ['admin'],
    '/my-class/teacher/'   : ['teacher'],
    '/my-class/student/'   : ['student'],

    '/keys/'               : ['student', 'teacher', 'parent', 'admin'],
    '/keys/logs/'          : ['admin'],   # only admin sees all logs

    '/results/add/'              : ['teacher'],
    '/results/my/'               : ['student'],
    '/parent/request/'           : ['parent'],
    '/parent/shared/'            : ['parent'],

    '/session/'                  : ['student', 'teacher', 'parent', 'admin'],
    '/posts/'                    : ['student', 'teacher', 'parent', 'admin'],
    '/security/'                 : ['student', 'teacher', 'parent', 'admin'],

    '/audit/'  : ['admin'],

}

# ============================================================
# MIDDLEWARE CLASS
# ============================================================

class RBACMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path

        # Allow Django admin and static files
        if path.startswith('/admin/') or path.startswith('/static/'):
            return self.get_response(request)

        # Allow public URLs
        if path in PUBLIC_URLS:
            return self.get_response(request)

        # ------------------------------------------------
        # SECURE SESSION VALIDATION
        # Validate on every protected request
        # ------------------------------------------------
        session_token = request.session.get('session_token')
        user_id       = request.session.get('user_id')
        user_role     = request.session.get('user_role')

        if not session_token or not user_id:
            return redirect('/login/')

        # ------------------------------------------------
        # Validate session using session manager
        # This checks: expiry, fingerprint, ECC signature
        # ------------------------------------------------
        from .session_manager import validate_session
        user, secure_session = validate_session(request)

        if not user:
            # Session invalid — clear and redirect to login
            request.session.flush()
            return redirect('/login/')

        # ------------------------------------------------
        # RBAC — role based URL access control
        # ------------------------------------------------
        for url_prefix, allowed_roles in ROLE_URL_MAP.items():
            if path.startswith(url_prefix):
                if user_role not in allowed_roles:
                    return redirect(self._get_dashboard(user_role))

        return self.get_response(request)

    def _get_dashboard(self, role):
        dashboards = {
            'admin'   : '/dashboard/admin/',
            'teacher' : '/dashboard/teacher/',
            'parent'  : '/dashboard/parent/',
            'student' : '/dashboard/student/',
        }
        return dashboards.get(role, '/login/')