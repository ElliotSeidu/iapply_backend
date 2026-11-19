from django.db.models import Avg, Count, ExpressionWrapper, F, OuterRef, Q, Subquery, fields
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


class ReminderViewSet(viewsets.ModelViewSet):
    serializer_class = ReminderSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Reminder.objects.filter(application__user=self.request.user)

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
    """Computed, read-only insights — not a CRUD resource.

    All aggregations are done in the database.  No application objects are
    loaded into Python memory, so the view scales to any dataset size.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        base_qs = Application.objects.filter(user=request.user)
        total = base_qs.count()

        if total == 0:
            return Response({
                "total_applications": 0,
                "status_breakdown": {},
                "channel_performance": [],
                "avg_days_to_first_response": None,
                "stale_count": 0,
            })

        # ── Status breakdown: single GROUP BY query ──────────────────────────
        status_breakdown = dict(
            base_qs.values_list("current_status")
            .annotate(count=Count("id"))
            .values_list("current_status", "count")
        )

        # ── Channel performance: single GROUP BY query ───────────────────────
        channel_stats = base_qs.values("channel").annotate(
            total=Count("id"),
            responded=Count("id", filter=~Q(current_status=Application.Status.APPLIED))
        )

        channel_performance = []
        channel_choices_dict = dict(Application.Channel.choices)

        for stat in channel_stats:
            channel_value = stat["channel"]
            channel_label = channel_choices_dict.get(channel_value, channel_value)
            ch_total = stat["total"]
            responded = stat["responded"]
            if ch_total == 0:
                continue
            channel_performance.append({
                "channel": channel_value,
                "label": channel_label,
                "total_applications": ch_total,
                "response_rate": round(responded / ch_total * 100, 1),
            })
        channel_performance.sort(key=lambda c: c["response_rate"], reverse=True)

        # ── Average days to first response: fully DB-side ────────────────────
        #
        # For each application, the "first response" is the earliest status
        # event that is NOT the initial "applied" entry. (Using "the second
        # event by time" is wrong when users backdate a status change, because
        # the auto-created "applied" event is stamped with the row creation time.)
        # A correlated Subquery fetches only that one timestamp per application,
        # and Avg runs in the database -- O(1) Python memory at any data size.

        second_event_subquery = (
            StatusEvent.objects
            .filter(application=OuterRef("pk"))
            .exclude(status=Application.Status.APPLIED)
            .order_by("occurred_at")
            .values("occurred_at")[:1]
        )

        avg_result = (
            base_qs
            .annotate(second_event_at=Subquery(second_event_subquery))
            .filter(second_event_at__isnull=False)   # only apps with a response
            .annotate(
                days_gap=ExpressionWrapper(
                    F("second_event_at__date") - F("date_applied"),
                    output_field=fields.DurationField(),
                )
            )
            .filter(days_gap__gte=timezone.timedelta(0))  # ignore negative gaps
            .aggregate(avg_gap=Avg("days_gap"))
        )

        raw_avg = avg_result["avg_gap"]
        if raw_avg is not None:
            # DurationField Avg returns a timedelta; extract total seconds → days
            avg_days_to_first_response = round(raw_avg.total_seconds() / 86400, 1)
        else:
            avg_days_to_first_response = None

        # ── Stale count: DB-side filter ──────────────────────────────────────
        active_statuses = [
            Application.Status.APPLIED,
            Application.Status.OA,
            Application.Status.INTERVIEW,
        ]
        stale_threshold = timezone.localdate() - timezone.timedelta(days=21)
        stale_count = base_qs.filter(
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
