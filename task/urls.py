# urls.py (app)
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    SignupView, AuthTokenView, PasswordRecoveryRequestView,
    UpdatePasswordView, AdminApprovalView, 
    PasswordRecoveryConfirmView, InactiveUsers,
    TaskViewSet,AssignmentViewSet, ActiveUsers,
    NotificationViewSet,CommentViewSet, TaskFileViewSet,
    MembersOnly,AdminManagerDashboard, MarkTaskStatusAPIView,
    NotificationMarkReadAPIView, NotificationMarkAllReadAPIView,
    MemberDashboard,UserProfileUpdateView,ReportsAPIView,

)



router = DefaultRouter()
router.register(r"tasks", TaskViewSet, basename="task")
router.register(r"assignments", AssignmentViewSet, basename="assignment")
router.register(r"notifications", NotificationViewSet, basename="notification")
router.register(r"comments", CommentViewSet, basename="comment")
router.register(r"task-files", TaskFileViewSet, basename="taskfile")

urlpatterns = [
    path("", include(router.urls)),
    # current user
    path("profile/me/", UserProfileUpdateView.as_view(), name="user-profile-me"),
    # admin or self by id
    path("profile/<int:pk>/", UserProfileUpdateView.as_view(), name="user-profile-detail"),
    
    path("auth/signup/", SignupView.as_view(), name="auth-signup"),
    path("auth/login/", AuthTokenView.as_view(), name="token_obtain_pair"),
    path("status/<uuid:pk>/", MarkTaskStatusAPIView.as_view(), name="task_status"),
    # Notifications
    path("notification/<uuid:pk>/mark-read/", NotificationMarkReadAPIView.as_view(), name="notification-mark-read"),
    path("notification/mark-all-read/", NotificationMarkAllReadAPIView.as_view(), name="notifications-mark-all-read"),
    
    path("auth/change-password/", UpdatePasswordView.as_view(), name="update-password"),
    path("auth/approve/", AdminApprovalView.as_view(), name="auth-approve"),
    path("auth/members/", MembersOnly.as_view(), name="members"),
    path("auth/inactive-users/", InactiveUsers.as_view(), name="inactive-users"),
    path("auth/active-users/", ActiveUsers.as_view(), name="active-users"),
    path("auth/recover-password/", PasswordRecoveryRequestView.as_view(), name="recover-password"),
    path("auth/confirm-password-recovery/", PasswordRecoveryConfirmView.as_view(), name="confirm-password-recovery"),
    # Dashboards & reports
    path("admin-dashboard/", AdminManagerDashboard.as_view(), name="admin-dashboard"),
    path("member-dashboard/", MemberDashboard.as_view(), name="member-dashboard"),
    path("reports/", ReportsAPIView.as_view(), name="task_reports"),
]
