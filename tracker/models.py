import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone


class Application(models.Model):
    """A single job application. `current_status` is a denormalized cache
    kept in sync by a signal — the real history lives in StatusEvent."""

    class Channel(models.TextChoices):
        LINKEDIN = "linkedin", "LinkedIn"
        REFERRAL = "referral", "Referral"
        COMPANY_SITE = "company_site", "Company Site"
        EMAIL = "email", "Email"
        JOB_FAIR = "job_fair", "Job Fair"
        RECRUITER = "recruiter", "Recruiter Outreach"
        OTHER = "other", "Other"

    class Status(models.TextChoices):
        APPLIED = "applied", "Applied"
        OA = "oa", "Online Assessment"
        INTERVIEW = "interview", "Interview"
        OFFER = "offer", "Offer"
        REJECTED = "rejected", "Rejected"
        WITHDRAWN = "withdrawn", "Withdrawn"

    class WorkModel(models.TextChoices):
        REMOTE = "remote", "Remote"
        IN_PERSON = "in_person", "In-person"
        HYBRID = "hybrid", "Hybrid"

    class JobType(models.TextChoices):
        FULL_TIME = "full_time", "Full-time"
        PART_TIME = "part_time", "Part-time"
        CONTRACT = "contract", "Contract"
        INTERNSHIP = "internship", "Internship"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="applications",
    )

    company_name = models.CharField(max_length=255)
    role_title = models.CharField(max_length=255)

    channel = models.CharField(max_length=20, choices=Channel.choices)
    source_detail = models.CharField(
        max_length=500,
        blank=True,
        help_text="e.g. referrer name, job post URL, event name",
    )

    work_model = models.CharField(max_length=20, choices=WorkModel.choices, blank=True, null=True)
    job_type = models.CharField(max_length=20, choices=JobType.choices, blank=True, null=True)
    monthly_salary = models.DecimalField(max_digits=10, decimal_places=2, blank=True, null=True)

    date_applied = models.DateField(default=timezone.now)
    current_status = models.CharField(
        max_length=20, choices=Status.choices, default=Status.APPLIED
    )

    resume_version = models.CharField(max_length=100, blank=True)
    notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-date_applied"]
        indexes = [
            models.Index(fields=["user", "current_status"]),
            models.Index(fields=["user", "channel"]),
        ]

    def __str__(self):
        return f"{self.role_title} @ {self.company_name}"

    def days_since_applied(self):
        return (timezone.now().date() - self.date_applied).days

    def is_stale(self, threshold_days=21):
        """True if it's stuck in an active status with no movement —
        used to drive the stale-application nudge feature."""
        active_statuses = {self.Status.APPLIED, self.Status.OA, self.Status.INTERVIEW}
        return (
            self.current_status in active_statuses
            and self.days_since_applied() >= threshold_days
        )


class StatusEvent(models.Model):
    """Timeline of status changes for an application. Analytics (response
    time, funnel conversion, channel performance) reads from this table,
    not from Application.current_status."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        Application, on_delete=models.CASCADE, related_name="status_events"
    )
    status = models.CharField(max_length=20, choices=Application.Status.choices)
    occurred_at = models.DateTimeField(default=timezone.now)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["occurred_at"]

    def __str__(self):
        return f"{self.application_id} -> {self.status} @ {self.occurred_at:%Y-%m-%d}"


class Reminder(models.Model):
    """Manual or system-generated follow-up reminders tied to an application."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    application = models.ForeignKey(
        Application, on_delete=models.CASCADE, related_name="reminders"
    )
    remind_at = models.DateTimeField()
    message = models.CharField(max_length=255)
    is_done = models.BooleanField(default=False)
    is_auto_generated = models.BooleanField(
        default=False, help_text="True if created by the stale-application check"
    )

    class Meta:
        ordering = ["remind_at"]

    def __str__(self):
        return f"Reminder: {self.message} ({self.application_id})"