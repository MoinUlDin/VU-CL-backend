# serializers.py
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from django.db import transaction
from django.utils import timezone
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Task, Assignment, Notification, Comment, TaskFile
User = get_user_model()

        
class SignupSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = [
            "first_name", "last_name", "username", "password",
            "role",
            "employee_number", "department", "picture",
            "email",
        ]

    def validate_role(self, value):
        if value == User.Roles.ADMIN:
            raise serializers.ValidationError("Cannot set role to Supervisor during registration.")
        return value

    def validate_password(self, value):
        validate_password(value)
        return value

    def create(self, validated_data):
        role = validated_data.pop("role", None)
        if not role:
            raise serializers.ValidationError({"role": "This field is required."})
        
        user = User(
            username=validated_data["username"],
            email=validated_data.get("email"),
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            employee_number=validated_data.get("employee_number"),
            department=validated_data.get("department"),
            role=role,
            is_active=False,  
        )

        if validated_data.get("picture"):
            user.picture = validated_data.get("picture")
        user.set_password(validated_data["password"])
        user.save()
        return user


class AuthTokenSerializer(TokenObtainPairSerializer):
    """
    Return the standard access/refresh tokens AND a user_info block.
    Also add small claims to the token (role, username).
    """

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['role'] = user.role
        token['username'] = user.username
        return token

    def validate(self, attrs):
        data = super().validate(attrs)  
        user = getattr(self, 'user', None)

        if getattr(user, 'picture', None):
            try:
                picture_url = self.context.get('request').build_absolute_uri(user.picture.url)
            except Exception:
                picture_url = user.picture.url
        else:
            picture_url = None

        if user and not user.is_active:
            raise serializers.ValidationError(
                {'detail': 'Your account is not active. Please wait for admin approval.'}
            )

        user_info = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': user.role,
            'department': user.department,
            'employee_number': user.employee_number,
            'picture': picture_url if getattr(user, 'picture', None) else None,
            'is_active': user.is_active,
            'approved': bool(user.is_active),
        }
        data['user_info'] = user_info

        return data

class UserProfileSerializer(serializers.ModelSerializer):
    picture = serializers.ImageField(required=False, allow_null=True, use_url=True)

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "department",
            "employee_number",
            "picture",
            "is_active",
            "role",
        ]
        read_only_fields = ["id", "username", "email", "is_active", "role"]

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate_new_password(self, value):
        validate_password(value)
        return value

class InactiveUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", 'employee_number', "last_name", "role", "date_joined"]
        

class AssignmentSerializer(serializers.ModelSerializer):
    assigned_by = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = Assignment
        fields = [
            "id",
            "task",
            "user",
            "assigned_by",
            "assigned_at",
            "role_at_assignment",
        ]
        read_only_fields = ["id", "assigned_at", "assigned_by"]

    def create(self, validated_data):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            validated_data["assigned_by"] = user
        return super().create(validated_data)

    def to_representation(self, instance):
        data = super().to_representation(instance)
        u = instance.user
        data["user_id"] = u.id
        data["user"] = f"{getattr(u, 'first_name', '')} {getattr(u, 'last_name', '')}".strip() or getattr(u, "username", "")
        data["user_name"] = getattr(u, "username", "")
        data["user_email"] = getattr(u, "email", "")
        task = instance.task
        
        if task:
            data['task'] = {
                "id": task.id,
                'title': task.title,
                "description": task.description or None,
                'status': task.status,
                'priority': task.priority,
                'due_date': task.due_date or None,
                'created_at': task.created_at or None,
                
            }

        assigned_by = instance.assigned_by
        if assigned_by:
            data['assigned_by'] = {
                'id': assigned_by.id,
                'name': f'{assigned_by.first_name} {assigned_by.last_name}',
                'email': assigned_by.email or None,
                'username': assigned_by.username
            }
        return data
    
class TaskFileSerializer(serializers.ModelSerializer):
    """
    Handles file uploads and captures file metadata automatically.
    uploaded_by is read-only and set from request.user.
    """
    uploaded_by = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = TaskFile
        fields = [
            "id",
            "task",
            "uploaded_by",
            "file",
            "file_name",
            "file_size",
            "content_type",
            "uploaded_at",
        ]
        read_only_fields = ["id", "uploaded_by", "uploaded_at", "file_name", "file_size", "content_type"]

    def create(self, validated_data):
        request = self.context.get("request")
        user = getattr(request, "user", None)

        uploaded_file = validated_data.get("file")
        # set metadata if file present
        if uploaded_file:
            validated_data["file_name"] = getattr(uploaded_file, "name", "")
            try:
                validated_data["file_size"] = uploaded_file.size
            except Exception:
                validated_data["file_size"] = None
            # Django's UploadedFile exposes content_type sometimes available in .content_type
            validated_data["content_type"] = getattr(uploaded_file, "content_type", None)

        validated_data["uploaded_by"] = user if user and user.is_authenticated else None
        return super().create(validated_data)


class CommentSerializer(serializers.ModelSerializer):
    """
    Comment serializer - author set from request.user.
    """
    author = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = Comment
        fields = [
            "id",
            "task",
            "author",
            "content",
            "created_at",
            "edited_at",
            "parent",
            "is_deleted",
            "meta",
        ]
        read_only_fields = ["id", "author", "created_at", "edited_at"]

    def create(self, validated_data):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        if user and user.is_authenticated:
            validated_data["author"] = user
        return super().create(validated_data)

    def validate(self, attrs):
        # Optional: ensure parent.comment belongs to same task (if parent provided)
        parent = attrs.get("parent")
        task = attrs.get("task")
        if parent and parent.task_id != task.id:
            raise serializers.ValidationError("Parent comment must belong to the same task.")
        return attrs


class NotificationSerializer(serializers.ModelSerializer):
    """
    Notification serializer.
    recipient is required (primary-key). The `read` flag may be toggled by the client.
    """
    recipient = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = Notification
        fields = [
            "id",
            "recipient",
            "type",
            "title",
            "message",
            "meta",
            "read",
            "created_at",
        ]
        read_only_fields = ["id", "created_at"]


class TaskSerializer(serializers.ModelSerializer):
    """
    Task serializer simplified for single-assignee model.
    - assignee_id (write-only): integer or null to assign/unassign a single user.
    - assignee (read-only): object {id, name, username, email} or null.
    """
    created_by = serializers.PrimaryKeyRelatedField(read_only=True)
    assignee_id = serializers.IntegerField(write_only=True, required=False, allow_null=True)
    assignee = serializers.SerializerMethodField(read_only=True)

    files = serializers.SerializerMethodField()    # keep read-only placeholders if needed
    comments = serializers.SerializerMethodField() # remove nested heavy objects if you prefer

    class Meta:
        model = Task
        fields = [
            "id",
            "title",
            "description",
            "priority",
            "status",
            "due_date",
            "created_at",
            "updated_at",
            "completed_at",
            "created_by",
            "is_deleted",
            "meta",
            "assignee_id",
            "assignee",
            "files",
            "comments",
        ]
        read_only_fields = ["id", "created_at", "updated_at", "completed_at", "created_by", "assignee", "files", "comments"]

    def get_assignee(self, obj):
        # return single assignee info or None
        assignment = obj.assignments.select_related("user").first()
        if not assignment or not assignment.user:
            return None
        u = assignment.user
        return {
            "id": u.id,
            "name": f"{getattr(u, 'first_name', '')} {getattr(u, 'last_name', '')}".strip() or getattr(u, "username", ""),
            "username": getattr(u, "username", ""),
            "email": getattr(u, "email", ""),
        }
    def to_representation(self, instance):
        data = super().to_representation(instance)
        created_by = instance.created_by
        if created_by:
            data['created_by'] = {
                "id": created_by.id,
                "username": created_by.username,
                "name": f'{created_by.first_name} {created_by.last_name}',
                "email": created_by.email
            }
        return data
    
    def get_files(self, obj):
        # lightweight file metadata list (optional)
        return [{"id": f.id, "file_name": getattr(f, "file_name", "")} for f in getattr(obj, "files", []).all()] if hasattr(obj, "files") else []

    def get_comments(self, obj):
        # lightweight comment count or short list (optional)
        return []  # keep empty or implement as needed

    def validate_due_date(self, value):
        if value and self.instance is None and value < timezone.now():
            raise serializers.ValidationError("due_date cannot be in the past.")
        return value

    def _ensure_single_assignment(self, task: Task, assignee_id, assigned_by):
        # current assignment user ids
        current = list(task.assignments.values_list("user_id", flat=True))

        if assignee_id is None:
            if current:
                Assignment.objects.filter(task=task).delete()
            return

        try:
            assignee_id = int(assignee_id)
        except (TypeError, ValueError):
            return

        # remove other assignments
        to_remove = [uid for uid in current if uid != assignee_id]
        if to_remove:
            Assignment.objects.filter(task=task, user_id__in=to_remove).delete()

        # if desired assignment already exists, nothing to do
        if assignee_id in current:
            return

        # create new assignment (if user exists)
        try:
            user = User.objects.get(pk=assignee_id)
        except User.DoesNotExist:
            return
        Assignment.objects.create(task=task, user=user, assigned_by=assigned_by)

    @transaction.atomic
    def create(self, validated_data):
        request = self.context.get("request")
        user = getattr(request, "user", None)
        assignee_id = validated_data.pop("assignee_id", None)

        if user and user.is_authenticated:
            validated_data["created_by"] = user

        task = super().create(validated_data)

        assigned_by = user if (user and user.is_authenticated) else None
        # sync single assignment
        self._ensure_single_assignment(task, assignee_id, assigned_by)

        return task

    @transaction.atomic
    def update(self, instance, validated_data):
        assignee_id = validated_data.pop("assignee_id", None)
        new_status = validated_data.get("status")
        if new_status == Task.Status.COMPLETED and instance.completed_at is None:
            validated_data["completed_at"] = timezone.now()

        task = super().update(instance, validated_data)

        request = self.context.get("request")
        user = getattr(request, "user", None)
        assigned_by = user if (user and user.is_authenticated) else None

        self._ensure_single_assignment(task, assignee_id, assigned_by)
        return task



   
    
