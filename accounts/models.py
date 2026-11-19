from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("User's must have email address.")
        email = email.strip().lower()
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

    def get_by_natural_key(self, username):
        normalized = (username or "").strip()
        return self.get(**{f"{self.model.USERNAME_FIELD}__iexact": normalized})


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    google_sub = models.CharField(max_length=255, unique=True, null=True, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = UserManager()

    def clean(self):
        super().clean()
        if self.email:
            self.email = self.email.strip().lower()

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.strip().lower()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.email


class EmailVerification(models.Model):
    """
    Temporary record created when a user initiates registration.

    Security properties:
    - `code` is generated with `secrets` (CSPRNG) — not `random`.
    - `attempts` is incremented on every wrong guess; the record is deleted
      after MAX_ATTEMPTS failures to prevent OTP brute-force.
    - The entire record is deleted on success or expiry (10 minutes).
    - `password_hash` stores the Django-hashed password so the plaintext
      never needs to be stored or re-sent.
    """

    MAX_ATTEMPTS = 5
    EXPIRY_MINUTES = 10

    email = models.EmailField(db_index=True)
    # 256 chars: safely covers pbkdf2_sha256, bcrypt, and argon2 hash lengths.
    code_hash = models.CharField(max_length=256)
    password_hash = models.CharField(max_length=256)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    # Number of incorrect verification attempts made against this record.
    attempts = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return f"Verification for {self.email} (attempts: {self.attempts})"


class PasswordResetRequest(models.Model):
    """
    Temporary record for a password-reset OTP flow.

    Security properties:
    - Token is CSPRNG-generated and stored only as a Django-hashed value.
    - MAX_ATTEMPTS prevents brute-force; record is deleted after success or expiry.
    - Expires after 15 minutes.
    - Always responds with the same message to prevent user-enumeration.
    """

    MAX_ATTEMPTS = 5
    EXPIRY_MINUTES = 10
    EXPIRY_MINUTES = 15

    email = models.EmailField(db_index=True)
    code_hash = models.CharField(max_length=256)
    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return f"PasswordReset for {self.email}"