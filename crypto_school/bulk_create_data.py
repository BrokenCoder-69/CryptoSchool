#!/usr/bin/env python
"""
Bulk data creation script for Crypto School
Run with: python manage.py shell < bulk_create_data.py
"""

import random
import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'crypto_school.settings')
django.setup()

from core.models import (
    UserProfile, Class, TeacherAssignment, ClassEnrollment, StudentResult
)
from core.crypto import (
    generate_rsa_keys, encrypt_to_string, serialize_key,
    generate_salt, hash_password, generate_ecc_keys,
    serialize_ecc_public_key, serialize_ecc_private_key,
    encrypt_private_key, deserialize_key, generate_hmac
)

# ============================================================
# ANIME CHARACTER NAMES & DATA
# ============================================================

STUDENT_NAMES = [
    "Naruto", "Sasuke", "Sakura", "Hinata", "Neji", "TenTen", "Lee",
    "Shikamaru", "Ino", "Choji", "Kiba", "Shino", "Gaara", "Temari",
    "Kankuro", "Sai", "Yamato", "Konohamaru", "Moegi", "Udon",
    "Ichigo", "Rukia", "Orihime", "Chad", "Uryu", "Renji", "Byakuya",
    "Toshiro", "Rangiku", "Ikkaku", "Yumichika", "Kenpachi", "Unohana",
    "Shunsui", "Jushiro", "Mayuri", "Nemu", "Izuru", "Momo", "Shuhei",
    "Luffy", "Zoro", "Nami", "Usopp", "Sanji", "Chopper", "Robin",
    "Franky", "Brook", "Jinbe", "Vivi", "Carrot", "Yamato", "Boa",
    "Trafalgar", "Bepo", "Penguin", "Shachi", "Coby", "Helmeppo",
    "Eren", "Mikasa", "Armin", "Levi", "Hange", "Erwin", "Petra",
    "Oluo", "Gunther", "Eld", "Connie", "Sasha", "Historia", "Ymir",
    "Reiner", "Bertholdt", "Annie", "Zeke", "Porco", "Pieck",
    "Izuku", "Bakugo", "Todoroki", "Uraraka", "Iida", "Asui", "Tokoyami",
    "Kirishima", "Kaminari", "Momo", "Fumikage", "Jirou", "Ojiro",
    "Aoyama", "Sero", "Hagakure", "Ashido", "Mineta", "Shoji", "Kouda",
]

TEACHER_NAMES = [
    "Kakashi", "Iruka", "Jiraiya", "Tsunade", "Orochimaru", "Minato", "Kushina", 
    "Hiruzen", "Asuma", "Kurenai", "Kisame", "Itachi", "Nagato", "Konan", "Obito",
    "Shanks", "Whitebeard", "Rayleigh", "Garp", "Sengoku", "Aizen", "Urahara",
    "Yoruichi", "Isshin", "Ryuken", "AllMight", "Eraserhead", "PresentMic", "Vlad", "Midnight"
]

PARENT_NAMES = [
    "Minato", "Kushina", "Fugaku", "Mikoto", "Hiashi", "Inoichi", "Shikaku", 
    "Choza", "Tsume", "Hizashi", "Isshin", "Masaki", "Ryuken", "Karin", 
    "InkoMidoriya", "Endeavor", "Rei", "AllMight_Sr", "Toshinori", "Nana"
]

SUBJECTS = [
    "Mathematics", "Physics", "Chemistry", "Biology", "History", "Geography", 
    "English", "Literature", "Computer Science", "Art", "Music", "Physical Education",
    "Economics", "Philosophy", "Psychology"
]

EXAM_TYPES = ["Quiz", "Midterm", "Final", "Assignment", "Project"]
ACADEMIC_YEARS = ["2023-2024", "2024-2025"]
GRADES = ["45", "50", "55", "60", "62", "65", "68", "70", "72", "75", "78", "80", "82", "85", "88", "90", "92", "95", "97", "100"]
REMARKS_LIST = ["Excellent performance", "Good effort", "Needs improvement", "Outstanding work", "Keep it up", "Well done", "Satisfactory", "Needs more practice", "Brilliant", "Shows great potential", "Consistent performer", "Hardworking student", "Creative thinker", "Team player"]

CLASS_DATA = [
    ("Grade 6",  ["A", "B"]),
    ("Grade 7",  ["A", "B"]),
    ("Grade 8",  ["A", "B"]),
    ("Grade 9",  ["A", "B"]),
    ("Grade 10", ["A", "B"]),
    ("Grade 11", ["A", "B"]),
    ("Grade 12", ["A", "B"]),
]

DEFAULT_PASSWORD = "Test@1234"


def create_user(username, email, full_name, role, extra_fields=None, password=DEFAULT_PASSWORD):
    """Create a user with encrypted keys and data"""
    if UserProfile.objects.filter(username=username).exists():
        return None
    if UserProfile.objects.filter(email=email).exists():
        return None

    pub_key, priv_key = generate_rsa_keys(bits=512)
    pub_str  = serialize_key(pub_key)
    priv_str = serialize_key(priv_key)

    ecc_priv_int, ecc_pub_point = generate_ecc_keys()
    ecc_pub_str  = serialize_ecc_public_key(ecc_pub_point)
    ecc_priv_str = serialize_ecc_private_key(ecc_priv_int)

    salt     = generate_salt()
    pwd_hash = hash_password(password, salt)

    rsa_enc = encrypt_private_key(priv_str, password, salt)
    ecc_enc = encrypt_private_key(ecc_priv_str, password, salt)

    enc_name  = encrypt_to_string(full_name, pub_key)
    enc_email = encrypt_to_string(email, pub_key)

    is_approved = role != 'teacher'

    user = UserProfile(
        username             = username,
        email                = email,
        password_hash        = pwd_hash,
        password_salt        = salt,
        role                 = role,
        is_approved          = is_approved,
        rsa_public_key       = pub_str,
        rsa_private_key      = rsa_enc,
        ecc_public_key       = ecc_pub_str,
        ecc_private_key      = ecc_enc,
        keys_encrypted       = True,
        encrypted_full_name  = enc_name,
        encrypted_email_data = enc_email,
        encrypted_phone      = '',
        profile_complete     = False,
    )

    if extra_fields:
        for field, value in extra_fields.items():
            encrypted = encrypt_to_string(value, pub_key)
            setattr(user, field, encrypted)
        user.profile_complete = True

    user.save()
    return user


# ============================================================
# MAIN EXECUTION
# ============================================================

print("=" * 60)
print("CRYPTO SCHOOL — BULK DATA CREATION")
print("=" * 60)

# Step 1: Get Admin
print("\n[1/7] Fetching admin...")
admin = UserProfile.objects.filter(role='admin').first()
if not admin:
    print("  ⚠ No admin found. Please create admin first.")
    exit()
else:
    print(f"  ✅ Admin: {admin.username}")

# Step 2: Create Classes
print("\n[2/7] Creating classes...")
created_classes = []
for class_name, sections in CLASS_DATA:
    for section in sections:
        cls, created = Class.objects.get_or_create(
            class_name = class_name,
            section    = section,
            defaults   = {'created_by': admin}
        )
        created_classes.append(cls)
        status = "created" if created else "exists"
        print(f"  {'✅' if created else '—'} {cls} [{status}]")
print(f"  Total classes: {len(created_classes)}")

# Step 3: Create 30 Teachers
print("\n[3/7] Creating 30 teachers...")
teachers = []
qualifications = [
    "PhD Mathematics", "MSc Physics", "MBA", "MEd",
    "BSc Computer Science", "MA Literature", "MSc Chemistry",
    "PhD Biology", "MA History", "MSc Economics"
]

for i, name in enumerate(TEACHER_NAMES[:30]):
    username = name.lower().replace(" ", "_")
    email    = f"{username}@teacher.cryptoschool.com"
    subject  = SUBJECTS[i % len(SUBJECTS)]
    qual     = qualifications[i % len(qualifications)]

    user = create_user(
        username   = username,
        email      = email,
        full_name  = name,
        role       = 'teacher',
        extra_fields = {
            'encrypted_subject'       : subject,
            'encrypted_qualification' : qual,
            'encrypted_phone'         : f"+880170000{i:04d}",
            'encrypted_address'       : f"{i+1} Anime Street, Konoha",
        }
    )

    if user:
        user.is_approved = True
        user.save()
        teachers.append(user)
        print(f"  ✅ {name} | {subject}")
    else:
        existing = UserProfile.objects.filter(username=username).first()
        if existing:
            teachers.append(existing)
            print(f"  — {name} already exists")

print(f"  Total teachers ready: {len(teachers)}")

# Step 4: Create 100 Students
print("\n[4/7] Creating 100 students...")
students = []
all_student_names = STUDENT_NAMES[:100]
while len(all_student_names) < 100:
    all_student_names.append(f"Student{len(all_student_names)+1}")

for i, name in enumerate(all_student_names):
    username = name.lower().replace(" ", "_") + f"_{i}"
    email    = f"{username}@student.cryptoschool.com"

    user = create_user(
        username = username,
        email    = email,
        full_name = name,
        role     = 'student',
        extra_fields = {
            'encrypted_phone'         : f"+880180000{i:04d}",
            'encrypted_address'       : f"{i+1} Hidden Leaf Village",
            'encrypted_date_of_birth' : f"200{i%10}-0{(i%12)+1:02d}-{(i%28)+1:02d}",
            'encrypted_guardian_name' : f"Guardian of {name}",
            'encrypted_guardian_phone': f"+880190000{i:04d}",
        }
    )

    if user:
        students.append(user)
        if i % 10 == 0:
            print(f"  ✅ Created {i+1}/100: {name}")
    else:
        existing = UserProfile.objects.filter(username=username).first()
        if existing:
            students.append(existing)

print(f"  Total students ready: {len(students)}")

# Step 5: Create 20 Parents
print("\n[5/7] Creating 20 parents...")
parents = []

for i, name in enumerate(PARENT_NAMES[:20]):
    username = name.lower().replace(" ", "_") + "_parent"
    email    = f"{username}@parent.cryptoschool.com"

    user = create_user(
        username = username,
        email    = email,
        full_name = name,
        role     = 'parent',
        extra_fields = {
            'encrypted_phone'      : f"+880160000{i:04d}",
            'encrypted_address'    : f"{i+1} Parent Avenue, Konoha",
            'encrypted_occupation' : random.choice([
                "Doctor", "Engineer", "Teacher", "Lawyer",
                "Business Owner", "Shinobi", "Hokage", "Scientist"
            ]),
        }
    )

    if user:
        parents.append(user)
        print(f"  ✅ {name}")
    else:
        existing = UserProfile.objects.filter(username=username).first()
        if existing:
            parents.append(existing)

print(f"  Total parents ready: {len(parents)}")

# Step 6: Assign Teachers + Enroll Students
print("\n[6/7] Assigning teachers and enrolling students...")

teacher_idx = 0
for cls in created_classes:
    for _ in range(2):
        if teacher_idx >= len(teachers):
            teacher_idx = 0
        teacher = teachers[teacher_idx]
        TeacherAssignment.objects.get_or_create(
            teacher        = teacher,
            assigned_class = cls,
        )
        teacher_idx += 1

print(f"  ✅ Teachers assigned to all classes")

students_per_class = len(students) // len(created_classes)
student_idx = 0

for cls in created_classes:
    count = 0
    while count < students_per_class and student_idx < len(students):
        student = students[student_idx]
        ClassEnrollment.objects.get_or_create(
            student        = student,
            enrolled_class = cls,
        )
        student_idx += 1
        count += 1

while student_idx < len(students):
    ClassEnrollment.objects.get_or_create(
        student        = students[student_idx],
        enrolled_class = created_classes[-1],
    )
    student_idx += 1

print(f"  ✅ Students enrolled in all classes")

# Step 7: Add Results for Every Student
print("\n[7/7] Adding encrypted results for all students...")

result_count = 0
for idx, student in enumerate(students):
    student_pub_key = deserialize_key(student.rsa_public_key)

    enrollment = ClassEnrollment.objects.filter(student=student).first()
    result_class = enrollment.enrolled_class if enrollment else None

    if result_class:
        assignment = TeacherAssignment.objects.filter(assigned_class=result_class).first()
        teacher = assignment.teacher if assignment else (teachers[0] if teachers else None)
    else:
        teacher = teachers[0] if teachers else None

    for j in range(3):
        subject   = SUBJECTS[j % len(SUBJECTS)]
        exam_type = EXAM_TYPES[j % len(EXAM_TYPES)]
        marks     = random.choice(GRADES)
        remarks   = random.choice(REMARKS_LIST)
        acad_year = random.choice(ACADEMIC_YEARS)

        enc_marks   = encrypt_to_string(marks, student_pub_key)
        enc_remarks = encrypt_to_string(remarks, student_pub_key)

        import hashlib
        hmac_secret = hashlib.sha256(
            student.rsa_public_key[:50].encode()
        ).hexdigest()

        data_hmac = generate_hmac(
            enc_marks + enc_remarks + subject,
            hmac_secret
        )

        StudentResult.objects.create(
            student           = student,
            result_class      = result_class,
            entered_by        = teacher,
            subject           = subject,
            exam_type         = exam_type,
            encrypted_marks   = enc_marks,
            encrypted_remarks = enc_remarks,
            data_hmac         = data_hmac,
            ecc_signature     = '',
            academic_year     = acad_year,
        )
        result_count += 1

    if idx % 20 == 0:
        print(f"  ✅ Results added for {idx+1}/100 students")

print(f"  ✅ Total results created: {result_count}")

# Summary
print("\n" + "=" * 60)
print("SUMMARY")
print("=" * 60)
print(f"  👨‍💼 Admins   : {UserProfile.objects.filter(role='admin').count()}")
print(f"  👨‍🏫 Teachers : {UserProfile.objects.filter(role='teacher').count()}")
print(f"  🎓 Students : {UserProfile.objects.filter(role='student').count()}")
print(f"  👨‍👩‍👧 Parents  : {UserProfile.objects.filter(role='parent').count()}")
print(f"  📚 Classes  : {Class.objects.count()}")
print(f"  🔗 Teacher assignments : {TeacherAssignment.objects.count()}")
print(f"  🔗 Student enrollments : {ClassEnrollment.objects.count()}")
print(f"  📊 Results  : {StudentResult.objects.count()}")
print("=" * 60)
print(f"\n  Default password for ALL users: {DEFAULT_PASSWORD}")
print(f"  e.g. login as: kakashi / {DEFAULT_PASSWORD}")
print("=" * 60)
