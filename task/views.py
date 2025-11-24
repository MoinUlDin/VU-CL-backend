# views.py
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.shortcuts import get_object_or_404
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from rest_framework.parsers import MultiPartParser, FormParser
from .models import Task, Assignment, Notification, Comment, TaskFile, CustomUser
from rest_framework import status
from django.db.models import Count, Q
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import viewsets, status, filters
from rest_framework.response import Response
from rest_framework.views import APIView
from django.utils import timezone
from django.db import transaction
from datetime import datetime, timedelta, date
from io import StringIO
from django.utils import timezone
from django.http import HttpResponse
from rest_framework.decorators import action
from .permissions import  RolePermission, IsTaskAssigneeOrManagerOrAdmin, IsAdminOrReadOnly
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404
from .serializers import (
    SignupSerializer, AuthTokenSerializer,
    ChangePasswordSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, InactiveUserSerializer,
    TaskSerializer, AssignmentSerializer, NotificationSerializer,
    CommentSerializer, TaskFileSerializer, UserProfileSerializer
)
from django.core.exceptions import PermissionDenied
from rest_framework import generics
from rest_framework.request import Request
from task.utils.notifications import create_notification, ensure_daily_notifications
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
import logging, csv
logger = logging.getLogger(__name__)
User = get_user_model()

token_generator = PasswordResetTokenGenerator()


class UserProfileUpdateView(generics.RetrieveUpdateAPIView):
    """
    Retrieve / update a user's profile.
    - GET /users/me/  -> returns current user
    - PATCH /users/me/ -> update current user
    - Admins may call /users/<pk>/ to update another user
    """
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        """
        If URL provides a pk and it's different than the logged-in user,
        only allow if the requesting user is an Admin.
        If no pk provided, return the current user.
        """
        user = self.request.user
        pk = self.kwargs.get("pk", None)

        if pk is None:
            return user

        # allow current user to access own record
        if str(user.pk) == str(pk):
            return user

        # allow admins to access others
        if getattr(user, "role", None) == User.Roles.ADMIN:
            return get_object_or_404(User, pk=pk)

        raise PermissionDenied("You do not have permission to access this resource.")

    def perform_update(self, serializer):
        """
        Handle picture removal if client explicitly clears picture.
        - If client sends "picture": null (JSON) or sets picture empty in multipart,
          delete existing file and set field to None.
        """
        request: Request = self.request
        # When using JSON payload with {"picture": null}, request.data['picture'] will be None
        if "picture" in request.data and request.data.get("picture") in [None, "", "null"]:
            # delete stored file (if any) to avoid stale files
            instance = serializer.instance
            if instance and instance.picture:
                instance.picture.delete(save=False)
            serializer.save(picture=None)
            return

        # otherwise normal save (file upload handled by serializer)
        serializer.save()


class SignupView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = SignupSerializer

    def post(self, request):
        serializer = SignupSerializer(data=request.data)
        if not serializer.is_valid():
            print("❌ Serializer errors:", serializer.errors)  # <-- print in console
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        admins = User.objects.filter(role=User.Roles.ADMIN)
        admin_emails = [a.email for a in admins if a.email]
        if admin_emails:
            subject = "New user registration awaiting approval"
            body = (
                f"A new user has registered:\n\n"
                f"Username: {user.username}\n"
                f"Name: {user.get_full_name()}\n"
                f"Employee #: {user.employee_number}\n\n"
                f"Approve or reject via admin API."
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, admin_emails, fail_silently=True)
        
        # Create DB notifications for each admin (helper handles exceptions)
        # using notification type "UPDATE" (one of your defined Types)
        title = "New user awaiting approval"
        message = f"User {user.get_full_name()} UserName: ({user.username}) has registered and requires approval."
        total_created = 0

        # If you want to only notify active admins, add is_active=True filter above
        for admin in admins:
            success, count = create_notification(
                title=title,
                message=message,
                type="UPDATE",     # matches Notification.Types.UPDATE
                recipient=admin,
                for_managers=False,
                meta={"user_id": user.id},
            )
            if success:
                total_created += count

        # optional: log/result (not required for client response)
        print(f"Notifications created for admins: {total_created}")

        return Response(
            {"detail": "Registration successful. Awaiting admin approval."},
            status=status.HTTP_201_CREATED,
        )


class AdminApprovalView(APIView):
    permission_classes = [IsAuthenticated] 
    permission_classes = [IsAuthenticated, RolePermission]
    serializer_class = AuthTokenSerializer
    def post(self, request):
        if getattr(request.user, "role", None) != User.Roles.ADMIN:
            return Response({"detail": "Admin only."}, status=status.HTTP_403_FORBIDDEN)

        user_id = request.data.get("user_id")
        action = request.data.get("action", "approve").lower()
        if not user_id:
            return Response({"detail": "user_id is required."}, status=status.HTTP_400_BAD_REQUEST)

        user = get_object_or_404(User, pk=user_id)

        if action == "approve":
            user.is_active = True
            user.save()

            subject = "Your account has been approved by admin"
            body = (
                f"Hello {user.get_full_name()},\n\n"
                "Your account has been approved by the administrator. You can now log in."
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)

            return Response({"detail": "User approved and notified."})
        elif action == "reject":
            user.is_active = False
            user.save()
            subject = "Your account registration was not approved"
            body = (
                f"Hello {user.get_full_name()},\n\n"
                "Your registration was not approved by the administrator. If you think this is a mistake, contact support."
            )
            send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=True)
            return Response({"detail": "User rejected and notified."})
        else:
            return Response({"detail": "Unknown action. Use 'approve' or 'reject'."}, status=status.HTTP_400_BAD_REQUEST)


class AuthTokenView(TokenObtainPairView):
    serializer_class = AuthTokenSerializer
    authentication_classes = []
    permission_classes = [AllowAny]


class UpdatePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user

        old_password = serializer.validated_data["old_password"]
        new_password = serializer.validated_data["new_password"]

        if not user.check_password(old_password):
            return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password changed successfully."})


class PasswordRecoveryConfirmView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetConfirmSerializer

    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        uidb64 = serializer.validated_data["uid"]
        token = serializer.validated_data["token"]
        new_password = serializer.validated_data["new_password"]

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"detail": "Invalid uid"}, status=status.HTTP_400_BAD_REQUEST)

        if not token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(new_password)
        user.save()
        return Response({"detail": "Password has been reset successfully."})
    
class InactiveUsers(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    serializer_class = InactiveUserSerializer

    def get(self, request):
        inactive_users = User.objects.filter(is_active=False)
        serializer = InactiveUserSerializer(inactive_users, many=True)

        data = {
            "count": inactive_users.count(),
            "requests": serializer.data,
        }
        return Response(data)
    
class ActiveUsers(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    serializer_class = InactiveUserSerializer

    def get(self, request):
        active_users = User.objects.filter(is_active=True).exclude(role='Admin')
        serializer = InactiveUserSerializer(active_users, many=True)

        data = {
            "count": active_users.count(),
            "requests": serializer.data,
        }
        return Response(data)
    
class MembersOnly(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    serializer_class = InactiveUserSerializer
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER]

    def get(self, request):
        inactive_users = User.objects.filter(is_active=True, role='Member')
        serializer = InactiveUserSerializer(inactive_users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class PasswordRecoveryRequestView(APIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        givenEmail = serializer.validated_data["email"]
        try:
            user = User.objects.get(email=givenEmail)
        except User.DoesNotExist:
            return Response({"detail": "If an account with that email exists, a reset link has been sent."})

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        frontend_url = getattr(settings, "FRONTEND_URL", None)
        if frontend_url:
            reset_link = f"{frontend_url}/reset-password/?uid={uid}&token={token}"
        else:
            reset_link = f"uid={uid}&token={token}"

        subject = "Password reset requested"
        body = (
            f"Hello {user.get_full_name()},\n\n"
            f"Hello {user.first_name} {user.last_name},\n\n"
            f"We received a reset password request. Use the link below to set a new password:\n\n"
            f"{reset_link}\n\n"
            "If you did not request this, you can ignore this email."
        )
        send_mail(subject, body, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)
        return Response({"detail": "If an account with that email exists, a reset link has been sent."})


# TASK VIEWSET
class TaskViewSet(viewsets.ModelViewSet):
    """
    Task endpoints:
    - Admin & Manager: full access
    - Member: only sees tasks assigned to them and can update those tasks
    """
    queryset = Task.objects.all().order_by("-created_at")
    serializer_class = TaskSerializer
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ["title", "description"]
    ordering_fields = ["due_date", "priority", "created_at"]
    filterset_fields = ["status", "priority", "created_by", "due_date"]
    permission_classes = [IsAuthenticated, RolePermission, IsTaskAssigneeOrManagerOrAdmin]
    # RolePermission will allow Admin, and will check allowed_roles below for non-admins
    allowed_roles = [User.Roles.MANAGER, User.Roles.MEMBER]

    def get_queryset(self):
        user = self.request.user
        if getattr(user, "role", None) == User.Roles.ADMIN:
            return Task.objects.all().order_by("-created_at")
        if getattr(user, "role", None) == User.Roles.MANAGER:
            # Managers see all tasks (modify if you want to restrict by department)
            return Task.objects.all().order_by("-created_at")
        # Members: only tasks where they are assigned
        return Task.objects.filter(assignments__user=user).distinct().order_by("-created_at")

    def perform_create(self, serializer):
        """
        Save task with created_by set, then notify all active Admin users.
        Notification errors are caught and logged — they won't fail task creation.
        """
        request_user = self.request.user
        # Save task
        task = serializer.save(created_by=request_user)

        # Prepare notification payload
        actor_name = (
            request_user.get_full_name()
            if hasattr(request_user, "get_full_name") and request_user.get_full_name()
            else getattr(request_user, "username", str(request_user.id))
        )
        title = f"New task created: {task.title or 'Untitled'}"
        message = f"Task '{task.title or task.id}' was created by {actor_name}."
        meta = {"task_id": str(task.id)}

        # Notify active admins (one notification per admin)
        try:
            admins = User.objects.filter(role=User.Roles.ADMIN, is_active=True)
            admin_count = 0
            for admin in admins:
                try:
                    ok, cnt = create_notification(
                        title=title,
                        message=message,
                        type="UPDATE",       # or Notification.Types.ASSIGNMENT / other type if preferred
                        recipient=admin,
                        for_managers=False,
                        meta=meta,
                    )
                    if ok:
                        admin_count += int(cnt)
                except Exception as inner_exc:
                    # log but continue notifying other admins
                    logger.exception(
                        "Failed to create notification for admin id=%s for task id=%s: %s",
                        admin.pk,
                        task.id,
                        inner_exc,
                    )
            if admin_count:
                logger.info("Created %d admin notifications for task id=%s", admin_count, task.id)
        except Exception as exc:
            logger.exception("Failed to create admin notifications for task id=%s: %s", task.id, exc)



class MarkTaskStatusAPIView(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    # allow Admin/Manager/Member to reach this view; object-level checks below enforce member restrictions
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER, User.Roles.MEMBER]

    def patch(self, request, pk=None, *args, **kwargs):
        """
        Patch payload: { "status": "COMPLETED" }  (one of Task.Status choices)
        Members can only update tasks assigned to them. Admin/Manager can update any task.

        After updating status:
          - notify all Managers of the change
          - if status == COMPLETED, also notify all Admins
        """
        task = get_object_or_404(Task, pk=pk)
        user = request.user

        # object-level restriction: Members may only update tasks assigned to them
        if getattr(user, "role", None) == User.Roles.MEMBER:
            assigned = Assignment.objects.filter(task=task, user=user).exists()
            if not assigned:
                return Response(
                    {"detail": "You can only update tasks assigned to you."},
                    status=status.HTTP_403_FORBIDDEN,
                )

        new_status = request.data.get("status", None)
        if new_status is None:
            return Response({"detail": "status is required"}, status=status.HTTP_400_BAD_REQUEST)

        # validate status is one of the allowed choices
        valid_statuses = [choice[0] for choice in Task.Status.choices]
        if new_status not in valid_statuses:
            return Response({"detail": f"Invalid status. Allowed: {valid_statuses}"}, status=status.HTTP_400_BAD_REQUEST)

        # Apply status and set completed_at when appropriate
        try:
            with transaction.atomic():
                task.status = new_status
                if new_status == Task.Status.COMPLETED:
                    if task.completed_at is None:
                        task.completed_at = timezone.now()
                else:
                    # if reverting from completed -> clear completed_at
                    if task.completed_at is not None:
                        task.completed_at = None

                # save the status change
                task.save(update_fields=["status", "completed_at", "updated_at"])
        except Exception as exc:
            logger.exception("Failed to save task status: %s", exc)
            return Response({"detail": "Failed to update task status", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Prepare notification payloads (do not fail the request if notifications fail)
        notif_results = {"managers": 0, "admins": 0, "errors": []}

        # Notify all managers about the status change
        try:
            title = f"Task updated: {task.title}"
            actor = getattr(user, "get_full_name", None)
            actor_name = user.get_full_name() if callable(actor) else getattr(user, "username", str(user.id))
            message = f"Task '{task.title}' status changed to {task.status} by {actor_name}."
            # meta helps link back to the task
            meta = {"task_id": str(task.id), "status": task.status}

            # create_notification(for_managers=True) will create one notification per manager
            ok, count = create_notification(title=title, message=message, type="UPDATE", recipient=None, for_managers=True, meta=meta)
            if ok:
                notif_results["managers"] = int(count)
            else:
                notif_results["errors"].append("Managers notification failed")
        except Exception as exc:
            logger.exception("Error creating manager notifications: %s", exc)
            notif_results["errors"].append(str(exc))

        # If completed, notify all admins as well
        if new_status == Task.Status.COMPLETED:
            try:
                admins = User.objects.filter(role=User.Roles.ADMIN, is_active=True)
                admin_count = 0
                for admin in admins:
                    try:
                        ok, cnt = create_notification(
                            title=f"Task completed: {task.title}",
                            message=f"Task '{task.title}' was marked COMPLETED by {actor_name}.",
                            type="UPDATE",
                            recipient=admin,
                            for_managers=False,
                            meta={"task_id": str(task.id), "status": task.status},
                        )
                        if ok:
                            admin_count += int(cnt)
                    except Exception as exc_inner:
                        logger.exception("Failed creating notification for admin %s: %s", admin.pk, exc_inner)
                        # continue with other admins
                notif_results["admins"] = admin_count
            except Exception as exc:
                logger.exception("Error creating admin notifications: %s", exc)
                notif_results["errors"].append(str(exc))

        # Return success + notification summary
        return Response(
            {
                "detail": "Status updated",
                "status": task.status,
                "completed_at": task.completed_at,
                "notifications": notif_results,
            },
            status=status.HTTP_200_OK,
        )

# ASSIGNMENT VIEWSET
class AssignmentViewSet(viewsets.ModelViewSet):
    """
    Assignment endpoints:
    - Admin & Manager: create/delete/list/update assignments (create sets assigned_by automatically)
    - Member: list only their assignments
    """
    queryset = Assignment.objects.all().order_by("-assigned_at")
    serializer_class = AssignmentSerializer
    permission_classes = [IsAuthenticated, RolePermission]
    # allow managers and admins for unsafe methods; safe methods available to members too
    allowed_roles = [User.Roles.MANAGER, User.Roles.ADMIN, User.Roles.MEMBER]

    def get_queryset(self):
        user = self.request.user
        if getattr(user, "role", None) in {User.Roles.ADMIN, User.Roles.MANAGER}:
            return Assignment.objects.all().order_by("-assigned_at")
        # Member: only own assignments
        return Assignment.objects.filter(user=user).order_by("-assigned_at")

    def perform_create(self, serializer):
        """
        Save assignment (ensure assigned_by set) and then notify:
         - assignee gets an ASSIGNMENT notification
         - all Admins get an UPDATE notification (so they can monitor assignments)
        Notification failures are logged and do not fail the request.
        """
        user = self.request.user

        # Save assignment (serializer may or may not set assigned_by; set fallback)
        assignment = serializer.save(assigned_by=user)

        # Prepare common meta
        meta = {
            "task_id": str(assignment.task.id) if assignment.task_id else None,
            "assignment_id": str(assignment.id),
        }

        # Notify the assigned user
        try:
            title = f"New task assigned: {assignment.task.title}"
            message = (
                f"You have been assigned a new task '{assignment.task.title}' "
                f"by {user.get_full_name() or user.username}."
            )
            # create_notification returns (success_bool, created_count)
            ok, cnt = create_notification(
                title=title,
                message=message,
                type="ASSIGNMENT",
                recipient=assignment.user,
                for_managers=False,
                meta=meta,
            )
            if not ok:
                logger.warning("create_notification returned ok=False for assignee: %s", assignment.user_id)
        except Exception as exc:
            logger.exception("Failed to create notification for assignee (assignment id=%s): %s", assignment.id, exc)

        # Notify all admins (one notification per admin)
        try:
            User = get_user_model()
            admins = User.objects.filter(role=User.Roles.ADMIN, is_active=True)
            admin_count = 0
            for admin in admins:
                try:
                    ok2, cnt2 = create_notification(
                        title=f"Task assigned: {assignment.task.title}",
                        message=(
                            f"Task '{assignment.task.title}' was assigned to "
                            f"{assignment.user.get_full_name() or assignment.user.username} by "
                            f"{user.get_full_name() or user.username}."
                        ),
                        type="UPDATE",   
                        recipient=admin,
                        for_managers=False,
                        meta=meta,
                    )
                    if ok2:
                        admin_count += int(cnt2)
                except Exception as inner_exc:
                    logger.exception("Failed to create notification for admin %s (assignment id=%s): %s", admin.pk, assignment.id, inner_exc)

            logger.debug("Created %d admin notifications for assignment id=%s", admin_count, assignment.id)
        except Exception as exc:
            logger.exception("Failed to notify admins for assignment id=%s: %s", assignment.id, exc)

        # (no return needed; viewset will continue and return serialized object)


# =============================================================
# ===================== Notifications ============================
# =============================================================
class NotificationViewSet(viewsets.ModelViewSet):
    """
    Notifications:
    - Users can list their own notifications and toggle `read`.
    - Admin/Manager can create notifications for users.
    """
    queryset = Notification.objects.all().order_by("-created_at")
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated, RolePermission]
    # allow Admin/Manager to create/update/delete; everyone to read their own
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER, User.Roles.MEMBER]

    def get_queryset(self):
        user = self.request.user
        return Notification.objects.filter(recipient=user).order_by("-created_at")

    def perform_create(self, serializer):
        # allow managers/admins to create notifications; the serializer expects a recipient field
        serializer.save()

    def list(self, request, *args, **kwargs):
        """
        Override list to ensure daily notification generation runs lazily
        on first fetch of the day.
        """
        print("\n\n List Called \n")
        try:
            ensure_daily_notifications(threshold_days=2)
        except Exception as e:
            pass

        return super().list(request, *args, **kwargs)

    @action(detail=True, methods=["post"], url_path="mark-read")
    def mark_read(self, request, pk=None):
        notif = self.get_object()
        # Only recipient or admin/manager can mark as read
        user = request.user
        if notif.recipient != user and getattr(user, "role", None) not in {User.Roles.ADMIN, User.Roles.MANAGER}:
            return Response({"detail": "Not allowed"}, status=status.HTTP_403_FORBIDDEN)
        notif.read = True
        notif.save(update_fields=["read"])
        return Response({"status": "ok"})

class NotificationMarkReadAPIView(APIView):
    """
    PATCH /notifications/<uuid:pk>/mark-read/
    Payload (optional): {"read": true|false}
    - By default sets read=True.
    - Only the recipient may change their notification, except Admins (role).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk=None, *args, **kwargs):
        # payload optional: default to True
        desired = request.data.get("read", True)
        if isinstance(desired, str):
            desired = desired.lower() not in ("false", "0", "no", "off")

        notif = get_object_or_404(Notification, pk=pk)

        # allow if recipient is current user OR current user is Admin
        current_user = request.user
        is_admin = getattr(current_user, "role", None) == getattr(User, "Roles", User()).ADMIN if hasattr(User, "Roles") else False
        # simpler check for admin role (fallback)
        if not (notif.recipient_id == current_user.id or is_admin):
            return Response({"detail": "Not allowed to modify this notification."}, status=status.HTTP_403_FORBIDDEN)

        try:
            notif.read = bool(desired)
            notif.save(update_fields=["read"])
            return Response({"success": True, "id": str(notif.id), "read": notif.read}, status=status.HTTP_200_OK)
        except Exception as exc:
            return Response({"detail": "Failed to update notification.", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NotificationMarkAllReadAPIView(APIView):
    """
    POST /notifications/mark-all-read/
    Marks all unread notifications for the current user as read.
    Returns {"success": True, "updated": <n>}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        user = request.user
        try:
            with transaction.atomic():
                qs = Notification.objects.filter(recipient=user, read=False)
                updated = qs.update(read=True)
            return Response({"success": True, "updated": int(updated)}, status=status.HTTP_200_OK)
        except Exception as exc:
            return Response({"detail": "Failed to mark all notifications as read.", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

# COMMENT VIEWSET
class CommentViewSet(viewsets.ModelViewSet):
    """
    Comments:
    - Admin/Manager: full access
    - Member: create/list on tasks they are assigned to (object-level enforced)
    """
    queryset = Comment.objects.all().order_by("-created_at")
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated, RolePermission, IsTaskAssigneeOrManagerOrAdmin]
    allowed_roles = [User.Roles.MANAGER, User.Roles.MEMBER, User.Roles.ADMIN]

    def get_queryset(self):
        user = self.request.user
        if getattr(user, "role", None) == User.Roles.ADMIN:
            return Comment.objects.all().order_by("-created_at")
        if getattr(user, "role", None) == User.Roles.MANAGER:
            return Comment.objects.all().order_by("-created_at")
        # Members: comments on tasks they are assigned to
        return Comment.objects.filter(task__assignments__user=user).order_by("-created_at")

    def perform_create(self, serializer):
        # author is set by serializer create()
        serializer.save()

class TaskCommentListView(generics.ListAPIView):
    """
    GET /api/tasks/{task_id}/comments/
    - Admin / Manager: list comments for any task
    - Member: list comments only for tasks they are assigned to (403 otherwise)
    """
    serializer_class = CommentSerializer
    permission_classes = [IsAuthenticated, RolePermission]
    # Allowed roles used by RolePermission like in your ViewSet
    allowed_roles = [User.Roles.MANAGER, User.Roles.MEMBER, User.Roles.ADMIN]

    def get_task(self):
        task_id = self.kwargs.get("task_id")
        return get_object_or_404(Task, pk=task_id)

    def get_queryset(self):
        user = self.request.user
        task = self.get_task()

        # base queryset: comments for this task, excluding soft-deleted ones
        qs = Comment.objects.filter(task=task, is_deleted=False).order_by("-created_at")

        # Admin & Manager: full access
        if getattr(user, "role", None) in (User.Roles.ADMIN, User.Roles.MANAGER):
            return qs

        # Member: only allowed if they are assigned to the task
        if getattr(user, "role", None) == User.Roles.MEMBER:
            assigned = task.assignments.filter(user=user).exists()
            if assigned:
                return qs
            # not assigned => forbid access
            raise PermissionDenied("You are not assigned to this task.")

        # Fallback: deny
        raise PermissionDenied("Insufficient permissions to view comments for this task.")
    

# TASKFILE VIEWSET (for file uploads)
class TaskFileViewSet(viewsets.ModelViewSet):
    """
    Uploads/downloads attachments:
    - Admin/Manager: full access
    - Member: create/list for tasks they are assigned to
    """
    queryset = TaskFile.objects.all().order_by("-uploaded_at")
    serializer_class = TaskFileSerializer
    permission_classes = [IsAuthenticated, RolePermission, IsTaskAssigneeOrManagerOrAdmin]
    allowed_roles = [User.Roles.MANAGER, User.Roles.MEMBER, User.Roles.ADMIN]
    parser_classes = [MultiPartParser, FormParser]  # allow multipart uploads

    def get_queryset(self):
        user = self.request.user
        if getattr(user, "role", None) in {User.Roles.ADMIN, User.Roles.MANAGER}:
            return TaskFile.objects.all().order_by("-uploaded_at")
        return TaskFile.objects.filter(task__assignments__user=user).order_by("-uploaded_at")

    def perform_create(self, serializer):
        # uploaded_by set in serializer.create()
        serializer.save()



# =============================================================
# ===================== Dashboards ============================
# =============================================================
class AdminManagerDashboard(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    allowed_roles = [User.Roles.ADMIN, User.Roles.MANAGER]
    
    def get(self, request, *args, **kwargs):
        # All tasks summary
        tasks_qs = Task.objects.all()
        tasks_count = tasks_qs.count()
        completed_count = tasks_qs.filter(status=Task.Status.COMPLETED).count()

        # Users excluding admins - annotate counts of assigned tasks and completed assigned tasks
        users_qs = (
            User.objects
            .exclude(role=User.Roles.ADMIN)
            .annotate(
                total_tasks=Count("assignments", distinct=True),
                completed_tasks=Count(
                    "assignments",
                    filter=Q(assignments__task__status=Task.Status.COMPLETED),
                    distinct=True,
                ),
            )
            .order_by("-total_tasks", "username")
        )

        users_summary = []
        for u in users_qs:
            total = u.total_tasks or 0
            completed = u.completed_tasks or 0
            performance = round((completed / total) * 100, 2) if total > 0 else 0.0

            users_summary.append({
                "first_name": u.first_name,
                "last_name": u.last_name,
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "active_user": u.is_active,
                "total_tasks": total,
                "completed": completed,
                "performance": performance,
            })

        return Response({
            "user_count": users_qs.count(),
            "active_users": users_qs.filter(is_active=True).count(),
            "tasks_count": tasks_count,
            "completed_count": completed_count,
            "users_summary": users_summary,
        })


class MemberDashboard(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    allowed_roles = [User.Roles.MEMBER]

    def _iso(self, dt):
        return dt.isoformat() if dt else None

    def get(self, request, *args, **kwargs):
        user = request.user

        # All tasks assigned to this user (distinct to avoid duplicates)
        tasks_qs = Task.objects.filter(assignments__user=user).distinct()

        tasks_count = tasks_qs.count()
        completed_count = tasks_qs.filter(status=Task.Status.COMPLETED).count()
        progress_count = tasks_qs.filter(status=Task.Status.IN_PROGRESS).count()

        now = timezone.now()
        overdue_count = tasks_qs.filter(due_date__lt=now).exclude(status=Task.Status.COMPLETED).count()

        performance = round((completed_count / tasks_count) * 100, 2) if tasks_count > 0 else 0.0

        # Last 3 assignments for this user (most recent first)
        latest_assignments = (
            Assignment.objects.filter(user=user)
            .select_related("task", "assigned_by")
            .order_by("-assigned_at")[:3]
        )

        last_tasks = []
        for a in latest_assignments:
            t = a.task
            last_tasks.append({
                "assignment_id": a.id,
                "assigned_at": self._iso(a.assigned_at),
                "assigned_by": {
                    "id": a.assigned_by.id if a.assigned_by else None,
                    "name": f"{a.assigned_by.first_name} {a.assigned_by.last_name}" if a.assigned_by else None,
                } if a.assigned_by else None,
                "task": {
                    "id": str(t.id),
                    "title": t.title,
                    "description": t.description,
                    "priority": t.priority,
                    "status": t.status,
                    "due_date": self._iso(t.due_date),
                    "created_at": self._iso(t.created_at),
                },
            })

        payload = {
            "total_tasks": tasks_count,
            "completed": completed_count,
            "progress_count": progress_count,
            "overdue": overdue_count,
            "performance": performance,
            "last_tasks": last_tasks,
        }

        return Response(payload, status=status.HTTP_200_OK)



# reports


class ReportsAPIView(APIView):
    permission_classes = [IsAuthenticated, RolePermission]
    # restrict to Admin / Manager (Members could be limited later)
    allowed_roles = [User.Roles.MANAGER, User.Roles.ADMIN]

    def _parse_date(self, s: str) -> date:
        # Accept YYYY-MM-DD
        return datetime.strptime(s, "%Y-%m-%d").date()

    def _daterange(self, start: date, end: date):
        cur = start
        while cur <= end:
            yield cur
            cur += timedelta(days=1)

    def get(self, request, *args, **kwargs):
        """
        Query params:
          start_date=YYYY-MM-DD, end_date=YYYY-MM-DD (defaults -> last 30 days)
          user_id, status, priority
          group_by = day|week|month  (we implement day)
          csv=1 -> returns CSV response
          raw=1 -> for CSV return raw task rows instead of timeseries
        Response JSON:
        {
          summary: { total_tasks, completed, in_progress, pending, overdue },
          by_status: {PENDING: n, IN_PROGRESS: n, ...},
          by_priority: {HIGH: n, MEDIUM: n, LOW: n},
          timeseries: [{date:'2025-11-01', created:10, completed:4, pending:6}, ...]
        }
        """
        params = request.query_params

        # parse date range
        today = timezone.localdate()
        try:
            end_date = self._parse_date(params.get("end_date")) if params.get("end_date") else today
        except Exception:
            return Response({"detail": "end_date must be YYYY-MM-DD"}, status=400)
        try:
            start_date = self._parse_date(params.get("start_date")) if params.get("start_date") else (end_date - timedelta(days=29))
        except Exception:
            return Response({"detail": "start_date must be YYYY-MM-DD"}, status=400)

        if start_date > end_date:
            return Response({"detail": "start_date must be <= end_date"}, status=400)

        user_id = params.get("user_id")
        status_filter = params.get("status")
        priority_filter = params.get("priority")

        # base queryset
        qs = Task.objects.all()

        # filter by user assignments (if user_id provided)
        if user_id:
            try:
                uid = int(user_id)
                qs = qs.filter(assignments__user_id=uid)
            except Exception:
                return Response({"detail": "user_id must be integer"}, status=400)

        if status_filter:
            qs = qs.filter(status=status_filter)

        if priority_filter:
            qs = qs.filter(priority=priority_filter)

        # summary counts
        total_tasks = qs.count()
        completed_count = qs.filter(status=Task.Status.COMPLETED).count()
        in_progress_count = qs.filter(status=Task.Status.IN_PROGRESS).count()
        pending_count = qs.filter(status=Task.Status.PENDING).count()
        overdue_count = qs.filter(
            due_date__isnull=False,
            due_date__lt=timezone.now(),
        ).exclude(status=Task.Status.COMPLETED).count()

        # aggregate by status/priority
        by_status_qs = qs.values("status").annotate(count=Count("id"))
        by_status = {row["status"]: row["count"] for row in by_status_qs}

        by_priority_qs = qs.values("priority").annotate(count=Count("id"))
        by_priority = {row["priority"]: row["count"] for row in by_priority_qs}

        # timeseries: for each day in range compute created & completed counts and pending snapshot
        timeseries = []
        # To reduce DB queries, we'll prefetch date-based counts
        # Note: using __date lookups—DB must support it (Postgres does).
        created_counts = (
            qs.filter(created_at__date__gte=start_date, created_at__date__lte=end_date)
            .values("created_at__date")
            .annotate(cnt=Count("id"))
        )
        created_map = {r["created_at__date"]: r["cnt"] for r in created_counts}

        completed_counts = (
            qs.filter(completed_at__date__gte=start_date, completed_at__date__lte=end_date)
            .values("completed_at__date")
            .annotate(cnt=Count("id"))
        )
        completed_map = {r["completed_at__date"]: r["cnt"] for r in completed_counts}

        # For pending snapshot we can compute how many tasks exist with status PENDING on that day.
        # A simple approach: pending_by_day = created - completed running sum. Simpler to return current pending count too.
        running_created = 0
        running_completed = 0

        for d in self._daterange(start_date, end_date):
            created = created_map.get(d, 0)
            completed = completed_map.get(d, 0)
            running_created += created
            running_completed += completed
            pending_snapshot = running_created - running_completed

            timeseries.append({
                "date": d.isoformat(),
                "created": created,
                "completed": completed,
                "pending_snapshot": max(0, pending_snapshot),
            })

        payload = {
            "summary": {
                "total_tasks": total_tasks,
                "completed": completed_count,
                "in_progress": in_progress_count,
                "pending": pending_count,
                "overdue": overdue_count,
            },
            "by_status": by_status,
            "by_priority": by_priority,
            "timeseries": timeseries,
        }

        # CSV export?
        if params.get("csv") == "1":
            raw = params.get("raw") == "1"
            filename = f"tasks_report_{start_date.isoformat()}_to_{end_date.isoformat()}.csv"
            if raw:
                # raw tasks rows
                response = HttpResponse(content_type="text/csv")
                response["Content-Disposition"] = f'attachment; filename="{filename}"'
                writer = csv.writer(response)
                writer.writerow(["id", "title", "status", "priority", "created_at", "completed_at", "due_date", "assignee"])
                # we'll iterate filtered qs and include first assigned user if exists
                tasks_qs = qs.select_related("created_by").prefetch_related("assignments__user")
                for t in tasks_qs:
                    assignee_name = None
                    # take first assignment if exists
                    a = getattr(t, "assignments", None)
                    if a:
                        first = t.assignments.first()
                        if first:
                            assignee_name = f"{first.user.get_full_name() or first.user.username}"
                    writer.writerow([str(t.id), t.title, t.status, t.priority, (t.created_at.isoformat() if t.created_at else ""), (t.completed_at.isoformat() if t.completed_at else ""), (t.due_date.isoformat() if t.due_date else ""), assignee_name or ""])
                return response
            else:
                # timeseries csv
                response = HttpResponse(content_type="text/csv")
                response["Content-Disposition"] = f'attachment; filename="{filename}"'
                writer = csv.writer(response)
                # header
                writer.writerow(["date", "created", "completed", "pending_snapshot"])
                for r in timeseries:
                    writer.writerow([r["date"], r["created"], r["completed"], r["pending_snapshot"]])
                # append summary lines
                writer.writerow([])
                writer.writerow(["summary", "value"])
                for k, v in payload["summary"].items():
                    writer.writerow([k, v])
                return response

        return Response(payload)