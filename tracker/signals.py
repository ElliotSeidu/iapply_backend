from django.db.models.signals import post_save
from django.dispatch import receiver

from .models import Application, StatusEvent


@receiver(post_save, sender=Application)
def create_initial_status_event(sender, instance, created, **kwargs):
    """Every new application gets its first timeline entry automatically."""
    if created:
        StatusEvent.objects.create(
            application=instance,
            status=instance.current_status,
            occurred_at=instance.created_at or instance.date_applied,
        )


@receiver(post_save, sender=StatusEvent)
def sync_current_status(sender, instance, created, **kwargs):
    """Push the latest event up to Application.current_status — but only
    if it's actually the newest event, so backfilling old ones doesn't
    clobber a more recent status."""
    if not created:
        return
    application = instance.application
    latest_event = application.status_events.order_by("-occurred_at").first()
    if latest_event and latest_event.id == instance.id:
        if application.current_status != instance.status:
            application.current_status = instance.status
            application.save(update_fields=["current_status", "updated_at"])