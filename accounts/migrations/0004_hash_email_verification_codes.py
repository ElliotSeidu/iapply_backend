from django.contrib.auth.hashers import make_password
from django.db import migrations, models


def hash_existing_codes(apps, schema_editor):
    EmailVerification = apps.get_model('accounts', 'EmailVerification')
    for record in EmailVerification.objects.all().iterator():
        record.code_hash = make_password(record.code)
        record.save(update_fields=['code_hash'])


class Migration(migrations.Migration):
    dependencies = [
        ('accounts', '0003_emailverification_security_patch'),
    ]

    operations = [
        migrations.AddField(
            model_name='emailverification',
            name='code_hash',
            field=models.CharField(max_length=128, null=True),
        ),
        migrations.RunPython(hash_existing_codes, migrations.RunPython.noop),
        migrations.RemoveField(
            model_name='emailverification',
            name='code',
        ),
        migrations.AlterField(
            model_name='emailverification',
            name='code_hash',
            field=models.CharField(max_length=128),
        ),
    ]