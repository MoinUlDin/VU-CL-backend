from django.apps import AppConfig
import logging

logger = logging.getLogger(__name__)

class TaskConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "task"

    def ready(self):
        # import here so Django has finished loading models/apps and to avoid circular imports
        try:
            # import the signals module so handlers get registered
            import task.signals  # noqa: F401
            logger.debug("task.signals imported successfully")
            print('\n task.signals imported successfully \n')
        except Exception as exc:
            logger.exception("Failed to import task.signals: %s", exc)
            print('\n Failed to import task.signals: %s" \n', exc)
