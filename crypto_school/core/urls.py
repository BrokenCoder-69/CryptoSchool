from django.urls import path
from django.shortcuts import redirect
from . import views

urlpatterns = [
    # ── Root ─────────────────────────────────────────────
    path('', lambda request: redirect('login')),

    # ── Auth ─────────────────────────────────────────────
    path('register/',   views.register_view,   name='register'),
    path('login/',      views.login_view,       name='login'),
    path('logout/',     views.logout_view,      name='logout'),
    path('verify-otp/', views.verify_otp_view,  name='verify_otp'),
    path('pending/',    views.pending_approval, name='pending_approval'),

    # ── Dashboards ────────────────────────────────────────
    path('dashboard/student/', views.student_dashboard,  name='dashboard_student'),
    path('dashboard/teacher/', views.teacher_dashboard,  name='dashboard_teacher'),
    path('dashboard/parent/',  views.parent_dashboard,   name='dashboard_parent'),
    path('dashboard/admin/',   views.admin_dashboard,    name='dashboard_admin'),

    # ── Profile ───────────────────────────────────────────
    path('profile/update/', views.update_profile, name='update_profile'),






# ── Results ───────────────────────────────────────────
    path('results/add/',      views.add_result,   name='add_result'),
    path('results/my/',       views.my_results,   name='my_results'),

    # ── Parent request ────────────────────────────────────
    path('parent/request/',
         views.submit_parent_request,  name='submit_parent_request'),
    path('parent/shared/',
         views.view_shared_data,       name='view_shared_data'),

    # ── Admin — parent requests ───────────────────────────
    path('admin-panel/parent-requests/',
         views.admin_parent_requests,  name='admin_parent_requests'),
    path('admin-panel/parent-requests/<int:request_id>/action/',
         views.approve_parent_request, name='approve_parent_request'),




# ── Session management ────────────────────────────────
    path('session/',
         views.session_dashboard,       name='session_dashboard'),
    path('session/terminate/<int:session_id>/',
         views.terminate_other_session, name='terminate_session'),
    path('admin-panel/sessions/',
         views.admin_sessions,          name='admin_sessions'),



# ── Posts ─────────────────────────────────────────────
    path('posts/',              views.post_list,    name='post_list'),
    path('posts/create/',       views.create_post,  name='create_post'),
    path('posts/delete/<int:post_id>/',
         views.delete_post, name='delete_post'),
     path('posts/edit/<int:post_id>/',
         views.edit_post, name='edit_post'),

    # ── Security ──────────────────────────────────────────
    path('security/',           views.security_dashboard, name='security_dashboard'),
    path('security/change-password/',
         views.change_password, name='change_password'),








    


    # ── Key Management ────────────────────────────────────
    path('keys/',         views.key_management, name='key_management'),
    path('keys/rotate/',  views.rotate_keys,    name='rotate_keys'),
    path('keys/logs/',    views.admin_key_logs,  name='admin_key_logs'),



# ── Dev audit (remove in production) ─────────────────
    path('audit/encryption/', views.encryption_audit, name='encryption_audit'),
























    # ── Admin actions ─────────────────────────────────────
    path('admin-panel/approve-teacher/<int:teacher_id>/',
         views.approve_teacher, name='approve_teacher'),

    path('admin-panel/create-class/',
         views.create_class, name='create_class'),

    path('admin-panel/assign-teacher/',
         views.assign_teacher, name='assign_teacher'),

    path('admin-panel/enroll-student/',
         views.enroll_student, name='enroll_student'),

    # ── Class management ──────────────────────────────────
    path('classes/',
         views.all_classes_view, name='all_classes'),

    path('classes/<int:class_id>/',
         views.class_detail, name='class_detail'),

    path('classes/<int:class_id>/delete/',
         views.delete_class, name='delete_class'),

    path('classes/remove-teacher/<int:assignment_id>/',
         views.remove_teacher_from_class, name='remove_teacher_from_class'),

    path('classes/remove-student/<int:enrollment_id>/',
         views.remove_student_from_class, name='remove_student_from_class'),

    # ── Teacher class detail ──────────────────────────────
    path('my-class/teacher/<int:class_id>/',
         views.teacher_class_detail, name='teacher_class_detail'),

    # ── Student class detail ──────────────────────────────
    path('my-class/student/<int:class_id>/',
         views.student_class_detail, name='student_class_detail'),
]