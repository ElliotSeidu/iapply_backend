from django.contrib import admin

from .models import Application, StatusEvent, Reminder


class StatusEventInline(admin.TabularInline):
    model = StatusEvent
    extra = 0
    readonly_fields = ["id"]


class ReminderInline(admin.TabularInline):
    model = Reminder
    extra = 0


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
    list_display = [
        "company_name",
        "role_title",
        "user",
        "channel",
        "current_status",
        "date_applied",
    ]
    list_filter = ["channel", "current_status"]
    search_fields = ["company_name", "role_title", "user__email"]
    ordering = ["-date_applied"]
    inlines = [StatusEventInline, ReminderInline]


@admin.register(StatusEvent)
class StatusEventAdmin(admin.ModelAdmin):
    list_display = ["application", "status", "occurred_at"]
    list_filter = ["status"]
    ordering = ["-occurred_at"]


@admin.register(Reminder)
class ReminderAdmin(admin.ModelAdmin):
    list_display = ["application", "message", "remind_at", "is_done", "is_auto_generated"]
    list_filter = ["is_done", "is_auto_generated"]
    ordering = ["remind_at"]