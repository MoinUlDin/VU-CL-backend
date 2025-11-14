# task/utils/notifications.py
import logging
from typing import Any, Dict, Optional, Tuple, Union, Iterable

from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone

from ..models import Notification  # adjust import path if necessary

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
