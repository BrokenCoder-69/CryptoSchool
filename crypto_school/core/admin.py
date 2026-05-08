# ============================================================
# admin.py — Register all models with Django admin panel
# ============================================================

from django.contrib import admin
from .models import (
    UserProfile, OTPSession, Class,
    TeacherAssignment, ClassEnrollment,
    KeyAccessLog, StudentResult,
    ParentRequest, SharedStudentData
)


# ============================================================
# CUSTOM ADMIN DISPLAYS
# Makes the admin panel actually useful with proper columns
# ============================================================

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    # Columns shown in the list view
    list_display = [
        'username', 'email', 'role',
        'is_approved', 'keys_encrypted',
        'key_version', 'profile_complete', 'created_at'
    ]
    # Filters on the right sidebar
    list_filter  = ['role', 'is_approved', 'keys_encrypted']
    # Search box
    search_fields = ['username', 'email']
    # Default sort
    ordering = ['-created_at']
    # Make these fields read only — never edit crypto fields manually
    readonly_fields = [
        'rsa_public_key', 'rsa_private_key',
        'ecc_public_key', 'ecc_private_key',
        'password_hash', 'password_salt',
        'encrypted_full_name', 'encrypted_email_data',
        'encrypted_phone', 'encrypted_address',
        'encrypted_date_of_birth', 'encrypted_guardian_name',
        'encrypted_guardian_phone', 'encrypted_subject',
        'encrypted_qualification', 'encrypted_occupation',
        'created_at', 'updated_at',
    ]


@admin.register(OTPSession)
class OTPSessionAdmin(admin.ModelAdmin):
    list_display  = ['user', 'created_at']
    list_filter   = ['created_at']
    ordering      = ['-created_at']
    readonly_fields = ['encrypted_otp', 'created_at']


@admin.register(Class)
class ClassAdmin(admin.ModelAdmin):
    list_display  = ['class_name', 'section', 'created_by', 'created_at']
    search_fields = ['class_name', 'section']
    ordering      = ['class_name', 'section']


@admin.register(TeacherAssignment)
class TeacherAssignmentAdmin(admin.ModelAdmin):
    list_display  = ['teacher', 'assigned_class', 'assigned_at']
    list_filter   = ['assigned_class']
    ordering      = ['-assigned_at']


@admin.register(ClassEnrollment)
class ClassEnrollmentAdmin(admin.ModelAdmin):
    list_display  = ['student', 'enrolled_class', 'enrolled_at']
    list_filter   = ['enrolled_class']
    ordering      = ['-enrolled_at']


@admin.register(KeyAccessLog)
class KeyAccessLogAdmin(admin.ModelAdmin):
    list_display  = [
        'user', 'action', 'performed_by',
        'ip_address', 'timestamp'
    ]
    list_filter   = ['action']
    search_fields = ['user__username', 'note']
    ordering      = ['-timestamp']
    readonly_fields = [
        'user', 'action', 'performed_by',
        'ip_address', 'note', 'timestamp'
    ]


@admin.register(StudentResult)
class StudentResultAdmin(admin.ModelAdmin):
    list_display  = [
        'student', 'subject', 'exam_type',
        'academic_year', 'entered_by', 'created_at'
    ]
    list_filter   = ['exam_type', 'academic_year', 'subject']
    search_fields = ['student__username', 'subject']
    ordering      = ['-created_at']
    # Never show raw encrypted marks in admin
    readonly_fields = [
        'encrypted_marks', 'encrypted_remarks',
        'data_hmac', 'ecc_signature', 'created_at', 'updated_at'
    ]


@admin.register(ParentRequest)
class ParentRequestAdmin(admin.ModelAdmin):
    list_display  = [
        'parent', 'student', 'status',
        'processed_by', 'created_at'
    ]
    list_filter   = ['status']
    search_fields = ['parent__username', 'student__username']
    ordering      = ['-created_at']
    readonly_fields = [
        'encrypted_message', 'message_hmac', 'created_at'
    ]


@admin.register(SharedStudentData)
class SharedStudentDataAdmin(admin.ModelAdmin):
    list_display  = ['parent', 'student', 'created_at']
    ordering      = ['-created_at']
    readonly_fields = [
        'encrypted_student_name',
        'encrypted_student_results',
        'admin_ecc_signature',
        'data_hmac', 'created_at'
    ]



# Add to imports:
from .models import (
    UserProfile, OTPSession, Class,
    TeacherAssignment, ClassEnrollment,
    KeyAccessLog, StudentResult,
    ParentRequest, SharedStudentData,
    SecureSession, SessionActivityLog    # ADD THESE
)

# Add at the bottom:
@admin.register(SecureSession)
class SecureSessionAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'ip_address', 'device_label',
        'is_active', 'last_activity', 'expires_at'
    ]
    list_filter  = ['is_active']
    ordering     = ['-last_activity']
    readonly_fields = [
        'token_hash', 'token_signature',
        'fingerprint', 'created_at', 'last_activity'
    ]


@admin.register(SessionActivityLog)
class SessionActivityLogAdmin(admin.ModelAdmin):
    list_display = [
        'user', 'event', 'ip_address', 'note', 'timestamp'
    ]
    list_filter  = ['event']
    ordering     = ['-timestamp']
    readonly_fields = [
        'user', 'event', 'ip_address',
        'user_agent', 'note', 'timestamp'
    ]





# Add to imports
from .models import (
    UserProfile, OTPSession, Class,
    TeacherAssignment, ClassEnrollment,
    KeyAccessLog, StudentResult,
    ParentRequest, SharedStudentData,
    SecureSession, SessionActivityLog,
    Post, LoginAttempt,                  # ADD
)

# Add at bottom
@admin.register(Post)
class PostAdmin(admin.ModelAdmin):
    list_display  = [
        'title', 'author', 'visibility',
        'is_active', 'created_at'
    ]
    list_filter   = ['visibility', 'is_active']
    search_fields = ['title', 'author__username']
    ordering      = ['-created_at']
    readonly_fields = [
        'encrypted_content', 'content_hmac',
        'ecc_signature', 'created_at', 'updated_at'
    ]


@admin.register(LoginAttempt)
class LoginAttemptAdmin(admin.ModelAdmin):
    list_display  = [
        'username', 'ip_address', 'attempt_count',
        'is_locked', 'locked_until'
    ]
    list_filter   = ['is_locked']
    ordering      = ['-first_attempt']

from .models import (
    UserProfile, OTPSession, Class,
    TeacherAssignment, ClassEnrollment,
    KeyAccessLog, StudentResult,
    ParentRequest, SharedStudentData,
    SecureSession, SessionActivityLog,
    Post, PostRecipient, LoginAttempt,    # ADD PostRecipient
)

# Add at bottom of admin.py
@admin.register(PostRecipient)
class PostRecipientAdmin(admin.ModelAdmin):
    list_display  = ['post', 'recipient']
    search_fields = ['post__title', 'recipient__username']
    readonly_fields = ['encrypted_content']




















# Username: superadmin
# Email: superadmin@cryptoschool.com
# Password: 123456