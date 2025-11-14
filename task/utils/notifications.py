# task/utils/notifications.py
import logging
from typing import Any, Dict, Optional, Tuple, Union, Iterable

from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone

from ..models import Notification, Task, Assignment, NotificationState 
from datetime import timedelta


logger = logging.getLogger(__name__)
User = get_user_model()


def create_notification(
    title: str,
    message: str,
    type: str,
    recipient: Optional[Union[User, int]] = None, # pyright: ignore[reportInvalidTypeForm]
    for_managers: bool = False,
    meta: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, int]:
    """
    Create notifications.

    Returns:
        (success: bool, created_count: int)

    Behaviour:
    - If for_managers is True: create one notification per user with role MANAGER (and is_active=True).
      `recipient` is ignored in that case.
    - Otherwise, create a notification for the single `recipient` (User instance or user PK).
    - The function never raises: on error it logs and returns (False, 0).

    Example:
        success, count = create_notification(
            "New task",
            "You have been assigned a task.",
            Notification.Types.ASSIGNMENT,
            recipient=some_user,
        )
    """
    try:
        # normalize meta
        meta_value = meta or {}

        # Use a transaction to ensure all-or-nothing
        with transaction.atomic():
            created_count = 0

            if for_managers:
                # fetch all active managers
                managers_qs = User.objects.filter(role=User.Roles.MANAGER, is_active=True)
                managers = list(managers_qs)
                if not managers:
                    logger.info("create_notification: no managers found to notify.")
                    return True, 0

                objs = []
                now = timezone.now()
                for mgr in managers:
                    objs.append(
                        Notification(
                            recipient=mgr,
                            type=type,
                            title=title[:50],       # keep within max_length guard
                            message=message,
                            meta=meta_value,
                            read=False,
                            created_at=now,
                        )
                    )

                Notification.objects.bulk_create(objs)
                created_count = len(objs)
                return True, created_count

            # not for_managers -> ensure recipient provided
            if recipient is None:
                logger.error("create_notification: recipient is None and for_managers is False.")
                return False, 0

            # accept either User instance or PK
            if isinstance(recipient, User):
                recipient_user = recipient
            else:
                try:
                    recipient_user = User.objects.get(pk=int(recipient))
                except Exception as e:
                    logger.exception("create_notification: recipient user not found: %s", recipient)
                    return False, 0

            # safe-truncate title (title max_length=50)
            notif = Notification.objects.create(
                recipient=recipient_user,
                type=type,
                title=title[:50],
                message=message,
                meta=meta_value,
                read=False,
            )
            created_count = 1 if notif else 0
            return True, created_count

    except Exception as exc:  # catch-all so caller never has to handle
        logger.exception("create_notification: unexpected error while creating notification: %s", exc)
        return False, 0


def generate_task_deadline_notifications():
    """
    Generate notifications only for tasks that are due TOMORROW (local date).
    Creates:
      - a notification for each assigned user (via Assignment),
      - a notification for all managers (using create_notification(..., for_managers=True)),
      - a notification per admin user.

    Marks task.is_notified = True after notify so it isn't notified again.
    Returns the total number of Notification rows created (sum from create_notification).
    """
    print("\n Generating Notifications \n")
    today = timezone.localdate()
    tomorrow = today + timedelta(days=1)

    # select tasks due tomorrow, not already notified, and not completed/cancelled
    qs = Task.objects.filter(
        is_notified=False,
        due_date__date=tomorrow,
    ).exclude(status__in=[Task.Status.COMPLETED, Task.Status.CANCELLED])

    notifications_created = 0

    # fetch admins once
    admins = list(User.objects.filter(role=User.Roles.ADMIN, is_active=True))

    for task in qs.select_related("created_by").prefetch_related("assignments__user"):
        try:
            title = f"Task approaching deadline: {task.title}"
            msg = f"Task '{task.title}' is due on {task.due_date}. Please take action."

            # 1) notify assigned users (one notification per assignment)
            assignments = list(task.assignments.all())
            if assignments:
                for a in assignments:
                    recipient = a.user
                    ok, cnt = create_notification(
                        title=title,
                        message=msg,
                        type="DEADLINE_REMINDER",
                        recipient=recipient,
                        meta={"task_id": str(task.id), "assignment_id": a.id},
                    )
                    notifications_created += cnt if cnt else 0
            else:
                pass

            # 2) notify all managers (single call uses bulk create inside helper)
            ok_m, cnt_m = create_notification(
                title=title,
                message=msg,
                type="DEADLINE_REMINDER",
                for_managers=True,
                meta={"task_id": str(task.id)},
            )
            notifications_created += cnt_m if cnt_m else 0

            # 3) notify each admin individually
            for admin in admins:
                ok_a, cnt_a = create_notification(
                    title=title,
                    message=msg,
                    type="DEADLINE_REMINDER",
                    recipient=admin,
                    meta={"task_id": str(task.id)},
                )
                notifications_created += cnt_a if cnt_a else 0

            # mark task as notified so we don't notify repeatedly
            task.is_notified = True
            task.save(update_fields=["is_notified"])

        except Exception as exc:
            logger.exception("generate_task_deadline_notifications: failed for task %s: %s", getattr(task, "id", None), exc)
            # continue with other tasks

    return notifications_created



def ensure_daily_notifications(threshold_days: int = 2):
    """
    Ensure the daily notification generator runs at most once per day.
    Uses a DB row as a single-state lock.
    """
    print("\n Ensure Daily Notifications \n")
    today = timezone.localdate()

    with transaction.atomic():
        state, created = NotificationState.objects.select_for_update().get_or_create(
            name="task_notifications", defaults={"last_calculation": None}
        )
        print(f' State: {state}')

        if state.last_calculation == today:
            # already ran today — nothing to do
            return 0

        # run generator
        print('\n Calling generate_task_deadline_notifications \n')
        
        try:
            created_count = generate_task_deadline_notifications()
        except Exception as e:
            print(f'Error as: {e}')
            
        print("\n saving todays Date now \n")
        # update last_calculation
        state.last_calculation = today
        state.save(update_fields=["last_calculation"])

    return created_count
