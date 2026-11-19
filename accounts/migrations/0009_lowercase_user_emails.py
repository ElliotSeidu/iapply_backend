from django.db import migrations


def lowercase_user_emails(apps, schema_editor):
    """Normalize existing User.email rows unless case-insensitive collisions exist."""
    User = apps.get_model('accounts', 'User')
    db_alias = schema_editor.connection.alias
    seen = {}
    duplicate_groups = set()
    updates = []

    for pk, raw_email in User.objects.using(db_alias).values_list('pk', 'email'):
        raw_value = raw_email or ''
        normalized = raw_value.strip().lower()
        if normalized in seen:
            duplicate_groups.add(normalized)
        else:
            seen[normalized] = pk
        if raw_value != normalized:
            updates.append((pk, normalized))

    if duplicate_groups:
        raise RuntimeError(
            f'Cannot lowercase user emails: found {len(duplicate_groups)} '
            'case-insensitive duplicate email group(s). Resolve duplicates '
            'manually before applying this migration.'
        )

    for pk, normalized in updates:
        User.objects.using(db_alias).filter(pk=pk).update(email=normalized)


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_user_google_sub'),
    ]

    operations = [
        migrations.RunPython(lowercase_user_emails, migrations.RunPython.noop),
    ]
