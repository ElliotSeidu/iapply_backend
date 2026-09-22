from django.db import migrations, models


class Migration(migrations.Migration):
    """
    Security patch migration:
    1. EmailVerification.password_hash: max_length 128 → 256
       Reason: argon2 hashes can exceed 128 characters; 256 safely covers
       all Django password hashers (pbkdf2_sha256, bcrypt, argon2).

    2. EmailVerification.attempts: new PositiveSmallIntegerField(default=0)
       Reason: tracks incorrect OTP guess count so the view can delete the
       record after MAX_ATTEMPTS failures, preventing brute-force of 6-digit OTPs.
    """

    dependencies = [
        ('accounts', '0002_emailverification'),
    ]

    operations = [
        migrations.AlterField(
            model_name='emailverification',
            name='password_hash',
            field=models.CharField(max_length=256),
        ),
        migrations.AddField(
            model_name='emailverification',
            name='attempts',
            field=models.PositiveSmallIntegerField(default=0),
        ),
    ]
