from collections import Counter

from django.core.management.base import BaseCommand, CommandError

from accounts.models import User


class Command(BaseCommand):
    help = (
        "Pre-deploy audit of User.email normalization and case-insensitive uniqueness. "
        "Outputs aggregate counts only; never prints user email addresses."
    )

    def handle(self, *args, **options):
        emails = list(User.objects.values_list("email", flat=True))
        total_users = len(emails)

        non_normalized = 0
        normalized_counts = Counter()
        for email in emails:
            raw_value = email or ""
            normalized = raw_value.strip().lower()
            if raw_value != normalized:
                non_normalized += 1
            normalized_counts[normalized] += 1

        duplicate_groups = sum(1 for count in normalized_counts.values() if count > 1)
        users_in_duplicates = sum(
            count for count in normalized_counts.values() if count > 1
        )

        self.stdout.write(
            f"total_users={total_users} "
            f"mixed_case_or_untrimmed_users={non_normalized} "
            f"case_insensitive_duplicate_groups={duplicate_groups} "
            f"users_in_duplicate_groups={users_in_duplicates}"
        )

        if duplicate_groups > 0:
            raise CommandError(
                f"Found {duplicate_groups} case-insensitive duplicate email group(s) "
                f"affecting {users_in_duplicates} user row(s). "
                "Resolve duplicates before running migrations."
            )
