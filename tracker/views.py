from django.db.models import Avg, Count, Q, F, ExpressionWrapper, DurationField
from django.utils import timezone
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.serializers import ListSerializer

from .models import Application, Reminder, StatusEvent
from .serializers import (
    ApplicationSerializer,
    ApplicationStatusChangeSerializer,
    ReminderSerializer,
    StatusEventSerializer,
)


class ApplicationViewSet(viewsets.ModelViewSet):
    serializer_class = ApplicationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Application.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

    @action(detail=True, methods=["post"], url_path="log-status")
    def log_status(self, request, pk=None):
        """The only sanctioned way to change current_status — creates a
        StatusEvent, which the signal then syncs onto current_status."""
        application = self.get_object()
        serializer = ApplicationStatusChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        event = StatusEvent.objects.create(
            application=application,
            status=serializer.validated_data["status"],
            notes=serializer.validated_data.get("notes", ""),
        )

        return Response(
            StatusEventSerializer(event).data, status=status.HTTP_201_CREATED
        )

    @action(detail=False, methods=["get"], url_path="stale")
    def stale(self, request):
        """Applications sitting with no movement past the threshold —
        drives the follow-up nudge feature."""
        stale_ids = [
            app.id for app in self.get_queryset() if app.is_stale()
        ]
        queryset = self.get_queryset().filter(id__in=stale_ids)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ReminderViewSet(viewsets.ModelViewSet):
    serializer_class = ReminderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Reminder.objects.filter(application__user=self.request.user)

    def get_serializer(self, *args, **kwargs):
        serializer = super().get_serializer(*args, **kwargs)
        # For list requests (many=True), DRF wraps the serializer in a ListSerializer,
        # which has no .fields of its own — the real field definitions live on .child.
        target = serializer.child if isinstance(serializer, ListSerializer) else serializer
        target.fields['application'].queryset = Application.objects.filter(
            user=self.request.user
        )
        return serializer


class AnalyticsView(APIView):
    """Computed, read-only insights — not a CRUD resource, so a plain
    APIView instead of a viewset."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        applications = Application.objects.filter(user=request.user)
        total = applications.count()

        if total == 0:
            return Response(
                {
                    "total_applications": 0,
                    "status_breakdown": {},
                    "channel_performance": [],
                    "avg_days_to_first_response": None,
                    "stale_count": 0,
                }
            )

        # Status breakdown across all applications
        status_breakdown = dict(
            applications.values_list("current_status")
            .annotate(count=Count("id"))
            .values_list("current_status", "count")
        )

        # Channel performance: total applied vs. how many moved past "applied"
        channel_performance = []
        for channel_value, channel_label in Application.Channel.choices:
            channel_apps = applications.filter(channel=channel_value)
            channel_total = channel_apps.count()
            if channel_total == 0:
                continue
            responded = channel_apps.exclude(
                current_status=Application.Status.APPLIED
            ).count()
            channel_performance.append(
                {
                    "channel": channel_value,
                    "label": channel_label,
                    "total_applications": channel_total,
                    "response_rate": round(responded / channel_total * 100, 1),
                }
            )
        channel_performance.sort(key=lambda c: c["response_rate"], reverse=True)

        # Avg days to first response: first StatusEvent after the initial
        # "applied" event, per application, averaged
        response_gaps = []
        for app in applications.prefetch_related("status_events"):
            events = list(app.status_events.all())
            if len(events) < 2:
                continue
            first_response = events[1]  # events[0] is the initial "applied" event
            gap = (first_response.occurred_at.date() - app.date_applied).days
            if gap >= 0:
                response_gaps.append(gap)

        avg_days_to_first_response = (
            round(sum(response_gaps) / len(response_gaps), 1)
            if response_gaps
            else None
        )

        stale_count = sum(1 for app in applications if app.is_stale())

        return Response(
            {
                "total_applications": total,
                "status_breakdown": status_breakdown,
                "channel_performance": channel_performance,
                "avg_days_to_first_response": avg_days_to_first_response,
                "stale_count": stale_count,
            }
        )