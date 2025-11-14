# signals.py (in task app)
from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import Task, NotificationState

@receiver(post_save, sender=Task)
def reset_notifications_on_task_change(sender, instance, created, **kwargs):
    print('\n reset notifications on task change \n')
    # if a task is created or updated that affects deadlines, clear last_calculation
    NotificationState.objects.update_or_create(
        name="task_notifications",
        defaults={"last_calculation": None},
    )
    # optionally, you may want to set instance.is_notified = False for the changed task so it can be re-notified
    # if specific fields changed you can reset is_notified accordingly (left as optional)


@receiver(pre_save, sender=Task)
def mark_task_unnotified_on_change(sender, instance, **kwargs):
    print('\n Marking task Unnotified \n')
    if not instance.pk:
        return
    old = Task.objects.filter(pk=instance.pk).first()
    if not old:
        return
    # if due_date or priority changed, allow notifications to run again
    if old.due_date != instance.due_date:
        instance.is_notified = False