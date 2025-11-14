from rest_framework.permissions import BasePermission, SAFE_METHODS
from task.models import Task

class RolePermission(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False


        if getattr(user, "role", None) == user.Roles.ADMIN:
            return True

        allowed = getattr(view, 'allowed_roles', None)
        if allowed is None:
           
            return False


        if request.method in SAFE_METHODS:
            return user.role in allowed

        return user.role in allowed

    def has_object_permission(self, request, view, obj):
    
        return self.has_permission(request, view)


class IsAdminOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        if request.method in SAFE_METHODS:
            return True
        
        return getattr(user, "role", None) == user.Roles.ADMIN


class IsTaskAssigneeOrManagerOrAdmin(BasePermission):
    """
    Object-level permission:
    - Admin: full access
    - Manager: full access
    - Member: allowed only if the user is assigned to the task.
      Applies to Task objects and related objects (Comment, TaskFile) that have `.task`.
    """
    
    def has_permission(self, request, view):
        # Basic auth check first
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False

        # Admin always ok
        if getattr(user, "role", None) == user.Roles.ADMIN:
            return True

        # Managers allowed for broad operations (we'll still enforce object-level where needed)
        if getattr(user, "role", None) == user.Roles.MANAGER:
            return True

        # Members: allow read operations; for writes, object-level check will run
        if getattr(user, "role", None) == user.Roles.MEMBER:
            # let object-level permission decide; return True here so DRF calls has_object_permission
            return True

        return False

    def has_object_permission(self, request, view, obj):
        user = request.user
        # Admin / Manager full access
        if getattr(user, "role", None) in {user.Roles.ADMIN, user.Roles.MANAGER}:
            return True

        # For member check: find the Task instance (obj may be Task, Comment, TaskFile, Assignment, Notification)
        task = None
        if isinstance(obj, Task):
            task = obj
        else:
            # objects like Comment, TaskFile, Notification have a .task FK (nullable). Assignment has .task
            task = getattr(obj, "task", None)

        if task is None:
            # If no related task, deny for members
            return False

        # Member must be assigned to the task
        is_assigned = task.assignments.filter(user_id=user.id).exists()
        return is_assigned



