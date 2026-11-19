from datetime import timedelta
import re

from django.utils import timezone
from rest_framework import serializers

from .models import Application, Reminder, StatusEvent

_DANGEROUS_SCHEMES = ("javascript:", "data:", "vbscript:")


class StatusEventSerializer(serializers.ModelSerializer):
    class Meta:
        model = StatusEvent
        fields = ["id", "status", "occurred_at", "notes"]
        read_only_fields = ["id"]


class ReminderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Reminder
        fields = [
            "id",
            "application",
            "remind_at",
            "message",
            "is_done",
            "is_auto_generated",
        ]
        read_only_fields = ["id", "is_auto_generated"]

    def validate_application(self, value):
        request = self.context.get("request")
        if request and getattr(request, "user", None) and value.user_id != request.user.id:
            raise serializers.ValidationError("Invalid application.")
        return value

    def validate_remind_at(self, value):
        """Reject reminders set more than 2 years in the future."""
        max_future = timezone.localdate() + timedelta(days=730)
        remind_date = value.date() if hasattr(value, 'date') else value
        if remind_date > max_future:
            raise serializers.ValidationError(
                "Reminder date cannot be more than 2 years in the future."
            )
        return value


class ApplicationSerializer(serializers.ModelSerializer):
    status_events = StatusEventSerializer(many=True, read_only=True)
    reminders = ReminderSerializer(many=True, read_only=True)
    days_since_applied = serializers.SerializerMethodField()
    is_stale = serializers.SerializerMethodField()
    notes = serializers.CharField(required=False, allow_blank=True, max_length=4000)

    class Meta:
        model = Application
        fields = [
            "id",
            "company_name",
            "role_title",
            "channel",
            "source_detail",
            "work_model",
            "job_type",
            "monthly_salary",
            "date_applied",
            "current_status",
            "resume_version",
            "notes",
            "created_at",
            "updated_at",
            "status_events",
            "reminders",
            "days_since_applied",
            "is_stale",
        ]
        read_only_fields = [
            "id",
            "current_status",
            "created_at",
            "updated_at",
        ]

    def validate_monthly_salary(self, value):
        if value is not None and value < 0:
            raise serializers.ValidationError("Monthly salary cannot be negative.")
        return value

    def validate_source_detail(self, value):
        cleaned = (value or "").strip()
        collapsed = re.sub(r"[\s\x00-\x1f]+", "", cleaned.lower())
        if any(collapsed.startswith(scheme) for scheme in _DANGEROUS_SCHEMES):
            raise serializers.ValidationError("Invalid URL scheme in source detail.")
        return cleaned

    def validate_date_applied(self, value):
        """
        Reject obviously bogus dates:
        - Future dates (you cannot have applied for a job tomorrow).
        - Dates more than 50 years in the past (data-entry error guard).
        """
        today = timezone.localdate()
        if value > today:
            raise serializers.ValidationError(
                "Date applied cannot be in the future."
            )
        # Subtracting from the date (not .replace(year=...)) cannot raise on 29 Feb.
        earliest_allowed = today - timedelta(days=365 * 50 + 12)
        if value < earliest_allowed:
            raise serializers.ValidationError(
                "Date applied is too far in the past. Please check the date."
            )
        return value

    def get_days_since_applied(self, obj):
        return obj.days_since_applied()

    def get_is_stale(self, obj):
        return obj.is_stale()


class ApplicationStatusChangeSerializer(serializers.Serializer):
    """Used by a dedicated action/endpoint to log a status change —
    this is the only sanctioned way current_status moves, so it always
    goes through StatusEvent and the sync signal."""

    status = serializers.ChoiceField(choices=Application.Status.choices)
    notes = serializers.CharField(required=False, allow_blank=True, max_length=4000)
