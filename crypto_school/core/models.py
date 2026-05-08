# ============================================================
# models.py — All database models for Crypto School
# ============================================================

from django.db import models


# ============================================================
# USER PROFILE
# ============================================================

class UserProfile(models.Model):

    ROLE_CHOICES = [
        ('admin',   'Admin'),
        ('teacher', 'Teacher'),
        ('parent',  'Parent'),
        ('student', 'Student'),
    ]

    # ── Login credentials ────────────────────────────────
    username      = models.CharField(max_length=150, unique=True)
    email         = models.EmailField(unique=True)
    password_hash = models.TextField()
    password_salt = models.CharField(max_length=64)

    # ── Role & approval ──────────────────────────────────
    role        = models.CharField(max_length=20, choices=ROLE_CHOICES)
    is_approved = models.BooleanField(default=False)

    # ── RSA Keys ─────────────────────────────────────────
    rsa_public_key = models.TextField()

    # Private key is now stored ENCRYPTED using master key
    # derived from user's password — plain text never stored
    rsa_private_key = models.TextField()
    # ^ field name stays the same but content is now encrypted hex

    # Flag to track if this user's keys are encrypted
    # False = old plain text keys (legacy), True = encrypted
    keys_encrypted = models.BooleanField(default=False)

    # ── ECC Keys ─────────────────────────────────────────
    ecc_public_key  = models.TextField(default='')
    ecc_private_key = models.TextField(default='')
    # ^ ECC private key also encrypted same way

    # ── Key rotation tracking ─────────────────────────────
    key_version    = models.IntegerField(default=1)
    # Increments every time keys are rotated
    # Helps track which version of keys encrypted which data

    last_key_rotation = models.DateTimeField(null=True, blank=True)
    # Records when keys were last rotated

    # ── Encrypted basic data (set at registration) ───────
    encrypted_full_name  = models.TextField()
    encrypted_email_data = models.TextField()
    encrypted_phone      = models.TextField(blank=True, default='')

    # ── Encrypted extended profile (updated later) ───────
    # These are filled in via the Update Profile page
    encrypted_address       = models.TextField(blank=True, default='')
    encrypted_date_of_birth = models.TextField(blank=True, default='')

    # Student-specific encrypted fields
    encrypted_guardian_name  = models.TextField(blank=True, default='')
    encrypted_guardian_phone = models.TextField(blank=True, default='')

# ── Extended student fields ───────────────────────────
    encrypted_blood_group    = models.TextField(blank=True, default='')
    encrypted_medical_notes  = models.TextField(blank=True, default='')
    encrypted_nationality    = models.TextField(blank=True, default='')
    encrypted_religion       = models.TextField(blank=True, default='')
    encrypted_emergency_contact = models.TextField(blank=True, default='')

    # Profile picture stored as file path
    # Not encrypted — profile pic is not sensitive
    profile_picture = models.ImageField(
        upload_to='profile_pics/',
        null=True, blank=True
    )




    # Teacher-specific encrypted fields
    encrypted_subject     = models.TextField(blank=True, default='')
    encrypted_qualification = models.TextField(blank=True, default='')

    # Parent-specific encrypted fields
    encrypted_occupation = models.TextField(blank=True, default='')

    # ── Profile completion flag ───────────────────────────
    # True once user has filled in extended profile
    profile_complete = models.BooleanField(default=False)

    # ── Metadata ─────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.username} ({self.role})"

    class Meta:
        db_table = 'user_profiles'


# ============================================================
# OTP SESSION
# ============================================================

class OTPSession(models.Model):
    # Temporarily stores encrypted OTP during 2FA login
    user          = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    encrypted_otp = models.TextField()
    created_at    = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"OTP for {self.user.username}"

    class Meta:
        db_table = 'otp_sessions'


# ============================================================
# CLASS
# ============================================================

class Class(models.Model):
    # Represents a school class e.g. "Grade 10 - A"

    class_name = models.CharField(max_length=100)
    # e.g. "Grade 10"

    section = models.CharField(max_length=10)
    # e.g. "A", "B"

    created_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_classes'
        # admin who created this class
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.class_name} - {self.section}"

    class Meta:
        db_table = 'classes'
        # Prevent duplicate class+section combinations
        unique_together = ('class_name', 'section')


# ============================================================
# TEACHER ASSIGNMENT
# ============================================================

class TeacherAssignment(models.Model):
    # Links a teacher to a class
    # One teacher can teach multiple classes
    # One class can have multiple teachers

    teacher = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='teaching_assignments'
    )
    assigned_class = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='teacher_assignments'
    )
    assigned_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.teacher.username} → {self.assigned_class}"

    class Meta:
        db_table = 'teacher_assignments'
        unique_together = ('teacher', 'assigned_class')
        # prevent assigning same teacher to same class twice


# ============================================================
# CLASS ENROLLMENT (Student → Class)
# ============================================================

class ClassEnrollment(models.Model):
    # Links a student to a class

    student = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    enrolled_class = models.ForeignKey(
        Class,
        on_delete=models.CASCADE,
        related_name='enrollments'
    )
    enrolled_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.student.username} → {self.enrolled_class}"

    class Meta:
        db_table = 'class_enrollments'
        unique_together = ('student', 'enrolled_class')
        # prevent enrolling same student twice in same class


        # ============================================================
# KEY ACCESS LOG
# ============================================================

class KeyAccessLog(models.Model):
    # Records every time a private key is accessed or used
    # Important for security auditing

    ACTION_CHOICES = [
        ('decrypt',  'Data Decrypted'),
        ('rotate',   'Key Rotated'),
        ('export',   'Key Exported'),
        ('login',    'Key Loaded on Login'),
    ]

    # Whose key was accessed
    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='key_access_logs'
    )

    # What action was performed
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)

    # Who performed the action
    # (usually same as user, but admin might access too)
    performed_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='performed_key_actions'
    )

    # Extra context about why/what
    note = models.CharField(max_length=255, blank=True, default='')

    # IP address of requester
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} on {self.user.username} at {self.timestamp}"

    class Meta:
        db_table  = 'key_access_logs'
        ordering  = ['-timestamp']  # newest first






# ============================================================
# STUDENT RESULT
# ============================================================

class StudentResult(models.Model):
    # Stores encrypted academic results for a student
    # Encrypted with student's RSA public key
    # Only student (or authorized parent) can decrypt

    student = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='results'
    )

    # Which class this result belongs to
    result_class = models.ForeignKey(
        Class,
        on_delete=models.SET_NULL,
        null=True,
        related_name='results'
    )

    # Who entered this result (teacher or admin)
    entered_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='entered_results'
    )

# Subject as enum — no free text, prevents inconsistency
    SUBJECT_CHOICES = [
        ('mathematics',       'Mathematics'),
        ('physics',           'Physics'),
        ('chemistry',         'Chemistry'),
        ('biology',           'Biology'),
        ('english',           'English'),
        ('literature',        'Literature'),
        ('history',           'History'),
        ('geography',         'Geography'),
        ('computer_science',  'Computer Science'),
        ('economics',         'Economics'),
        ('accounting',        'Accounting'),
        ('business_studies',  'Business Studies'),
        ('art',               'Art'),
        ('music',             'Music'),
        ('physical_education','Physical Education'),
        ('islamic_studies',   'Islamic Studies'),
        ('bangla',            'Bangla'),
        ('philosophy',        'Philosophy'),
        ('psychology',        'Psychology'),
        ('statistics',        'Statistics'),
    ]

    subject = models.CharField(
        max_length=50,
        choices=SUBJECT_CHOICES,
        default='english'
    )

    # Exam type e.g. "Midterm", "Final", "Quiz 1"
    exam_type = models.CharField(max_length=50)

    # ── Encrypted result data ─────────────────────────
    # Grade/marks encrypted with STUDENT's RSA public key
    # Format after decryption: "85" or "A+" etc.
    encrypted_marks = models.TextField()

    # Remarks encrypted with student's public key
    encrypted_remarks = models.TextField(blank=True, default='')

    # ── Integrity verification ────────────────────────
    # HMAC of the encrypted data
    # Detects if anyone tampered with the stored ciphertext
    data_hmac = models.CharField(max_length=64)

    # ── ECC Signature ─────────────────────────────────
    # Teacher/admin signs the result with their ECC private key
    # Proves result came from them and was not altered
    ecc_signature = models.TextField(blank=True, default='')

    # Academic year e.g. "2024-2025"
    academic_year = models.CharField(max_length=20)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return (
            f"{self.student.username} | "
            f"{self.subject} | {self.exam_type}"
        )

    class Meta:
        db_table = 'student_results'


# ============================================================
# PARENT REQUEST
# ============================================================

class ParentRequest(models.Model):
    # Parent requests access to a student's information
    # Request itself is encrypted with admin's RSA public key

    STATUS_CHOICES = [
        ('pending',  'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]

    parent  = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='sent_requests'
    )

    # The student the parent claims to be related to
    student = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='parent_requests'
    )

    # ── ID Card Upload ────────────────────────────────
    # Parent must upload student's ID card image
    # Stored as file — admin reviews it
    id_card_image = models.ImageField(
        upload_to='id_cards/',
        null=True, blank=True
    )

    # Student ID number claimed by parent
    # Encrypted with admin's public key
    encrypted_student_id_number = models.TextField(
        blank=True, default=''
    )

    # ── Encrypted request content ─────────────────────
    # Parent's message/reason encrypted with admin's public key
    # Only admin can read the request details
    encrypted_message = models.TextField()

    # HMAC for integrity — proves message not tampered
    message_hmac = models.CharField(max_length=64)

    # ── Status ────────────────────────────────────────
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )

    # Admin's note when approving/rejecting
    admin_note = models.TextField(blank=True, default='')

    # Which admin processed this request
    processed_by = models.ForeignKey(
        UserProfile,
        on_delete=models.SET_NULL,
        null=True, blank=True,
        related_name='processed_requests'
    )

    created_at   = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return (
            f"{self.parent.username} → "
            f"{self.student.username} [{self.status}]"
        )

    class Meta:
        db_table = 'parent_requests'
        # One pending request per parent-student pair at a time
        unique_together = ('parent', 'student')


# ============================================================
# SHARED STUDENT DATA
# ============================================================

class SharedStudentData(models.Model):
    # After admin approves parent request:
    # Student's data is re-encrypted with parent's public key
    # Signed with admin's ECC key
    # Parent decrypts with their own private key

    parent  = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='received_data'
    )
    student = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='shared_data'
    )
    request = models.OneToOneField(
        ParentRequest,
        on_delete=models.CASCADE,
        related_name='shared_data'
    )

    # Student profile data re-encrypted with PARENT's public key
    encrypted_student_name    = models.TextField()
    encrypted_student_results = models.TextField()
    # ^ JSON list of results, encrypted as one block

    # ECC signature by admin — proves admin authorized this share
    # and data was not altered after signing
    admin_ecc_signature = models.TextField()

    # HMAC for integrity
    data_hmac = models.CharField(max_length=64)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return (
            f"Shared: {self.student.username} "
            f"→ {self.parent.username}"
        )

    class Meta:
        db_table = 'shared_student_data'




# ============================================================
# SECURE SESSION
# ============================================================

class SecureSession(models.Model):
    # Tracks all active sessions with ECC signed tokens
    # One record per active login session

    user = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='secure_sessions'
    )

    # The signed session token
    # Stored as hash — never store raw token in DB
    # Same principle as password hashing
    token_hash = models.CharField(max_length=64, unique=True)

    # ECC signature of the token
    # Verified on every request to ensure token legitimacy
    token_signature = models.TextField()

    # Browser/IP fingerprint
    # If this changes mid-session → possible hijacking
    fingerprint = models.CharField(max_length=64)

    # Session metadata
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default='')

    # Timing
    created_at    = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now_add=True)
    # ^ updated on every request

    # Session expiry — 30 minutes of inactivity
    expires_at = models.DateTimeField()

    # Whether this session has been explicitly invalidated
    is_active = models.BooleanField(default=True)

    # Which device/browser label (for display)
    device_label = models.CharField(max_length=100, blank=True, default='')

    def __str__(self):
        return f"Session: {self.user.username} | {self.ip_address}"

    class Meta:
        db_table = 'secure_sessions'
        ordering = ['-last_activity']


# ============================================================
# SESSION ACTIVITY LOG
# ============================================================

class SessionActivityLog(models.Model):
    # Records key session events for security auditing

    EVENT_CHOICES = [
        ('login',        'Login'),
        ('logout',       'Logout'),
        ('expired',      'Session Expired'),
        ('hijack',       'Hijack Attempt Detected'),
        ('invalid_token','Invalid Token'),
        ('concurrent',   'Concurrent Session Terminated'),
    ]

    user       = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='session_logs'
    )
    event      = models.CharField(max_length=20, choices=EVENT_CHOICES)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, default='')
    note       = models.CharField(max_length=255, blank=True, default='')
    timestamp  = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.event} — {self.user.username} at {self.timestamp}"

    class Meta:
        db_table = 'session_activity_logs'
        ordering = ['-timestamp']



# ============================================================
# POST
# ============================================================

class Post(models.Model):
    # Users can create posts/announcements
    # All content encrypted with author's RSA public key
    # Signed with author's ECC private key

    VISIBILITY_CHOICES = [
        ('public',   'Everyone'),       # all logged in users
        ('teachers', 'Teachers Only'),
        ('students', 'Students Only'),
        ('parents',  'Parents Only'),
        ('admin',    'Admin Only'),
    ]

    author = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='posts'
    )

    # Title stored plain — needed for listing/searching
    # Not sensitive by itself
    title = models.CharField(max_length=200)

    # Content encrypted with author's RSA public key
    encrypted_content = models.TextField()

    # HMAC for integrity verification
    content_hmac = models.CharField(max_length=64)

    # ECC signature — proves this author wrote this post
    ecc_signature = models.TextField(blank=True, default='')

    # Who can see this post
    visibility = models.CharField(
        max_length=20,
        choices=VISIBILITY_CHOICES,
        default='public'
    )

    # Whether post is active
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} by {self.author.username}"

    class Meta:
        db_table = 'posts'
        ordering = ['-created_at']

class PostRecipient(models.Model):
    # One row per user who can read the post
    # Content encrypted with THAT user's RSA public key
    # This is how we share encrypted content with multiple users
    # without using symmetric keys

    post = models.ForeignKey(
        Post,
        on_delete=models.CASCADE,
        related_name='recipients'
    )

    # The user who can decrypt this copy
    recipient = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name='received_posts'
    )

    # Content encrypted with THIS recipient's RSA public key
    encrypted_content = models.TextField()

    class Meta:
        db_table        = 'post_recipients'
        unique_together = ('post', 'recipient')

    def __str__(self):
        return f"{self.post.title} → {self.recipient.username}"
# ============================================================
# LOGIN ATTEMPT (Brute Force Protection)
# ============================================================

class LoginAttempt(models.Model):
    # Tracks failed login attempts per username/IP
    # Account locked after 5 failed attempts

    username   = models.CharField(max_length=150)
    ip_address = models.GenericIPAddressField(null=True, blank=True)

    # Number of failed attempts in current window
    attempt_count = models.IntegerField(default=0)

    # When the lockout window started
    first_attempt = models.DateTimeField(auto_now_add=True)

    # When the account was locked
    locked_until = models.DateTimeField(null=True, blank=True)

    # Whether currently locked
    is_locked = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.username} — {self.attempt_count} attempts"

    class Meta:
        db_table = 'login_attempts'
        # Track by both username and IP
        unique_together = ('username', 'ip_address')


























