from rest_framework import serializers
from datetime import date, timedelta

from .models import Application, Reminder, StatusEvent


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

    def validate_remind_at(self, value):
        """Reject reminders set more than 2 years in the future."""
        max_future = date.today() + timedelta(days=730)
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

    def validate_date_applied(self, value):
        """
        Reject obviously bogus dates:
        - Future dates (you cannot have applied for a job tomorrow).
        - Dates more than 50 years in the past (data-entry error guard).
        """
        today = date.today()
        if value > today:
            raise serializers.ValidationError(
                "Date applied cannot be in the future."
            )
        earliest_allowed = today.replace(year=today.year - 50)
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
    notes = serializers.CharField(required=False, allow_blank=True)
