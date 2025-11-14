from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import CustomUser
from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django.utils.translation import gettext_lazy as _
from task.models import Task, Assignment, Notification, NotificationState
from django.utils import timezone

class CustomUserCreationForm(forms.ModelForm):
    """
    A form for creating new users. Includes all the required
    fields, plus a repeated password.
    """
    password1 = forms.CharField(label=_("Password"), widget=forms.PasswordInput)
    password2 = forms.CharField(label=_("Password confirmation"), widget=forms.PasswordInput)

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'employee_number', 'role', 'department')

    def clean_password2(self):
        p1 = self.cleaned_data.get("password1")
        p2 = self.cleaned_data.get("password2")
        if p1 and p2 and p1 != p2:
            raise forms.ValidationError(_("Passwords don't match"))
        return p2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class CustomUserChangeForm(forms.ModelForm):
    """
    A form for updating users. Includes a read-only password hash field.
    """
    password = ReadOnlyPasswordHashField(label=_("Password"))

    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'first_name', 'last_name', 'employee_number', 'role', 'department', 'password', 'is_active', 'is_staff')


class CustomUserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm

    list_display = ('username', 'email', 'first_name', 'last_name', 'role', 'employee_number', 'is_staff')
    list_filter = ('role', 'is_staff', 'is_superuser', 'is_active')
    search_fields = ('username', 'email', 'first_name', 'last_name', 'employee_number')
    ordering = ('username',)

    fieldsets = (
        (None, {'fields': ('username', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'email', 'employee_number', 'picture', 'department')}),
        ('Permissions', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser',  'groups', 'user_permissions')}),
        ('Dates', {'fields': ('date_joined',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'first_name', 'last_name', 'employee_number', 'role', 'password1', 'password2'),
        }),
    )

@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
    # columns shown in the changelist
    list_display = (
        "short_id",
        "title",
        "priority",
        "status",
        "due_date",
        "created_at",
        "created_by_display",
    )

    # filters at right side
    list_filter = ("priority", "status", "created_by", "is_deleted")
    # quick search
    search_fields = ("title", "description", "created_by__username", "created_by__email")
    # sortable columns / default ordering
    ordering = ("-created_at",)
    # show these on the detail form as readonly
    readonly_fields = ("created_at", "updated_at", "completed_at")

    # nice date drill-down
    date_hierarchy = "created_at"

    # help avoid N+1 by selecting related user
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related("created_by")

    # display shorter id (UUID) for readability
    def short_id(self, obj):
        return str(obj.id)[:8]
    short_id.short_description = "ID"
    short_id.admin_order_field = "id"

    # display created_by nicely
    def created_by_display(self, obj):
        if obj.created_by:
            return f"{obj.created_by.get_full_name() or obj.created_by.username} ({obj.created_by.email})"
        return "-"
    created_by_display.short_description = "Created by"
    created_by_display.admin_order_field = "created_by__username"

    # admin action to mark tasks completed
    actions = ["mark_completed"]

    def mark_completed(self, request, queryset):
        updated = queryset.update(status=Task.Status.COMPLETED, completed_at=timezone.now())
        self.message_user(request, f"{updated} task(s) marked as completed.")
    mark_completed.short_description = "Mark selected tasks as completed"
    

@admin.register(NotificationState)
class NotificationStateAdmin(admin.ModelAdmin):
    list_display = ("name", "last_calculation")
    
    
admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(Assignment)
admin.site.register(Notification)