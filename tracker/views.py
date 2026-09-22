from django.db.models import Avg, Count, Q
from django.utils import timezone
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.serializers import ListSerializer
from rest_framework.views import APIView

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
        """
        Scope every query to the authenticated user AND prefetch nested
        relations in a single extra SQL query per relation — prevents the
        N+1 problem where serialising 100 applications would fire 200+
        additional queries for status_events and reminders.
        """
        return (
            Application.objects
            .filter(user=self.request.user)
            .prefetch_related('status_events', 'reminders')
        )

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
        active_statuses = [
            Application.Status.APPLIED,
            Application.Status.OA,
            Application.Status.INTERVIEW,
        ]
        stale_threshold = timezone.now().date() - timezone.timedelta(days=21)
        queryset = self.get_queryset().filter(
            current_status__in=active_statuses,
            date_applied__lte=stale_threshold,
        )
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class ReminderViewSet(viewsets.ModelViewSet):
    serializer_class = ReminderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return (
            Reminder.objects
            .filter(application__user=self.request.user)
            .select_related('application')
        )

    def get_serializer(self, *args, **kwargs):
        serializer = super().get_serializer(*args, **kwargs)
        # For list requests (many=True), DRF wraps the serializer in a
        # ListSerializer — the real field definitions live on .child.
        target = serializer.child if isinstance(serializer, ListSerializer) else serializer
        target.fields['application'].queryset = Application.objects.filter(
            user=self.request.user
        )
        return serializer


class AnalyticsView(APIView):
    """Computed, read-only insights — not a CRUD resource."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        applications = (
            Application.objects
            .filter(user=request.user)
            .prefetch_related('status_events')
        )
        total = applications.count()

        if total == 0:
            return Response({
                "total_applications": 0,
                "status_breakdown": {},
                "channel_performance": [],
                "avg_days_to_first_response": None,
                "stale_count": 0,
            })

        # Status breakdown — single GROUP BY query
        status_breakdown = dict(
            applications.values_list("current_status")
            .annotate(count=Count("id"))
            .values_list("current_status", "count")
        )

        # Channel performance
        channel_performance = []
        for channel_value, channel_label in Application.Channel.choices:
            channel_apps = applications.filter(channel=channel_value)
            channel_total = channel_apps.count()
            if channel_total == 0:
                continue
            responded = channel_apps.exclude(
                current_status=Application.Status.APPLIED
            ).count()
            channel_performance.append({
                "channel": channel_value,
                "label": channel_label,
                "total_applications": channel_total,
                "response_rate": round(responded / channel_total * 100, 1),
            })
        channel_performance.sort(key=lambda c: c["response_rate"], reverse=True)

        # Average days to first response
        response_gaps = []
        for app in applications:
            events = list(app.status_events.all())
            if len(events) < 2:
                continue
            first_response = events[1]
            gap = (first_response.occurred_at.date() - app.date_applied).days
            if gap >= 0:
                response_gaps.append(gap)

        avg_days_to_first_response = (
            round(sum(response_gaps) / len(response_gaps), 1)
            if response_gaps else None
        )

        # Stale count — DB-side filter is O(1) instead of a Python loop
        active_statuses = [
            Application.Status.APPLIED,
            Application.Status.OA,
            Application.Status.INTERVIEW,
        ]
        stale_threshold = timezone.now().date() - timezone.timedelta(days=21)
        stale_count = applications.filter(
            current_status__in=active_statuses,
            date_applied__lte=stale_threshold,
        ).count()

        return Response({
            "total_applications": total,
            "status_breakdown": status_breakdown,
            "channel_performance": channel_performance,
            "avg_days_to_first_response": avg_days_to_first_response,
            "stale_count": stale_count,
        })