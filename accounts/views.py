from datetime import timedelta
import hashlib
import logging
import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import validate_password
from django.core.cache import cache
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.mail import send_mail
from django.db import DatabaseError, IntegrityError, transaction
from django.utils import timezone

from rest_framework import generics, status
from rest_framework.exceptions import ValidationError as DRFValidationError
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .google_auth import (
    GoogleAuthError,
    GoogleAuthServiceError,
    mark_google_id_token_used,
    split_google_name,
    verify_google_id_token,
)
from .models import EmailVerification, PasswordResetRequest, User
from .serializers import (
    ChangePasswordSerializer,
    DeleteAccountSerializer,
    GoogleLoginSerializer,
    LogoutSerializer,
    MyTokenObtainPairSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    UserSerializer,
    VerificationConfirmSerializer,
    VerificationRequestSerializer,
)
from .throttles import (
    CacheUnavailableError,
    GoogleLoginRateThrottle,
    LoginRateThrottle,
    PasswordActionRateThrottle,
    PasswordResetRateThrottle,
    RefreshRateThrottle,
    RegisterRateThrottle,
    VerifyRateThrottle,
)

logger = logging.getLogger(__name__)


def _is_dev_console():
    """True only for local development with the console email backend, where
    OTP codes are echoed to the terminal so no SMTP server is needed."""
    return (
        getattr(settings, 'DEBUG', False) is True
        and getattr(settings, 'DEPLOYMENT_ENV', 'production') == 'development'
        and getattr(settings, 'EMAIL_BACKEND', '') == 'django.core.mail.backends.console.EmailBackend'
    )


def _consume_email_rate_limit(scope, email, limit=5, window=3600):
    """Enforce a per-email rate limit across all IPs to prevent email bombing.

    Fails closed (HTTP 503) if the cache backend raises an error.
    """
    digest = hashlib.sha256(email.encode('utf-8')).hexdigest()
    key = f'email_rl:{scope}:{digest}'
    try:
        if cache.add(key, 1, timeout=window):
            return True
        try:
            count = cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=window)
            return True
        return count <= limit
    except Exception as exc:
        logger.error('Email rate-limit cache unavailable (%s): %s', scope, exc)
        raise CacheUnavailableError() from exc


def _blacklist_user_tokens(user):
    """Revoke every outstanding, not-yet-blacklisted refresh token for `user`."""
    for token in OutstandingToken.objects.filter(
        user=user,
        blacklistedtoken__isnull=True,
    ):
        try:
            RefreshToken(token.token).blacklist()
        except Exception:
            continue


class RegistrationView(APIView):
    """
    Initiates the email-verification registration flow.

    Security notes:
    - Uses `secrets.randbelow` (CSPRNG) instead of `random` for OTP generation.
    - Always executes identical password-hashing work and returns HTTP 200 with
      the same message whether or not the email already exists, preventing
      user-enumeration via response or timing differences.
    - Rate-limited per IP and per email to curb email-spam abuse.
    """

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [RegisterRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = VerificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = data['email'].strip().lower()

        if not _consume_email_rate_limit('register', email):
            return Response(
                {"message": "Too many requests for this email. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        is_dev_console = _is_dev_console()
        # Hash password and OTP before checking user existence so existing and
        # new emails spend equal CPU time (closes timing enumeration).
        code = str(secrets.randbelow(900000) + 100000)
        password_hash = make_password(data['password'])
        code_hash = make_password(code)

        # Always return the same response whether or not the email is already
        # registered — avoids leaking which emails exist (user enumeration).
        if User.objects.filter(email__iexact=email).exists():
            if is_dev_console:
                print(
                    f"\n{'=' * 64}\n"
                    f"  [iApply DEV NOTE] Registration skipped for {email}\n"
                    f"  Reason: Account already exists. Log in or reset password instead.\n"
                    f"{'=' * 64}\n",
                    flush=True,
                )
            return Response(
                {"message": "Verification code sent to email"},
                status=status.HTTP_200_OK,
            )

        # Delete any previous pending verifications for this email so the
        # user isn't blocked by a stale record.
        with transaction.atomic():
            EmailVerification.objects.filter(email__iexact=email).delete()
            EmailVerification.objects.create(
                email=email,
                code_hash=code_hash,
                password_hash=password_hash,
                first_name=(data.get('first_name') or '').strip(),
                last_name=(data.get('last_name') or '').strip(),
            )
        if is_dev_console:
            print(
                f"\n{'=' * 64}\n"
                f"  [iApply OTP] Email Verification\n"
                f"  To:   {email}\n"
                f"  Code: {code}\n"
                f"{'=' * 64}\n",
                flush=True,
            )
        send_mail(
            subject='Your iApply verification code',
            message=(
                f'Your iApply verification code is: {code}\n\n'
                'This code expires in 10 minutes. If you did not request this, '
                'you can safely ignore this email.'
            ),
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
            recipient_list=[email],
            fail_silently=True,
        )
        return Response(
            {"message": "Verification code sent to email"},
            status=status.HTTP_200_OK,
        )


class VerifyEmailView(APIView):
    """
    Completes registration by verifying the OTP and creating the user account.

    Security notes:
    - Runs inside a DB transaction with select_for_update to prevent a race
      condition where two concurrent requests with the same code both succeed.
    - Increments an attempt counter; deletes the record after MAX_ATTEMPTS
      wrong guesses to prevent brute-force of the 6-digit OTP.
    - Record is always deleted on success or expiry.
    - Rate-limited to 10 requests per IP per hour.
    """

    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [VerifyRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = VerificationConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].strip().lower()
        code = serializer.validated_data['code']

        with transaction.atomic():
            # select_for_update ensures only one concurrent request can
            # process this record at a time, preventing double-account creation.
            record = (
                EmailVerification.objects
                .select_for_update()
                .filter(email__iexact=email)
                .order_by('-created_at')
                .first()
            )

            if not record:
                return Response(
                    {"message": "Invalid or expired code. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check expiry (10 minutes)
            if timezone.now() > record.created_at + timedelta(minutes=EmailVerification.EXPIRY_MINUTES):
                record.delete()
                return Response(
                    {"message": "Code has expired. Please register again."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Enforce attempt limit before checking the code value —
            # this prevents an attacker from learning anything from the
            # sequence of error messages.
            if record.attempts >= EmailVerification.MAX_ATTEMPTS:
                record.delete()
                return Response(
                    {"message": "Too many incorrect attempts. Please register again."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            # Wrong code — increment attempt counter and delete immediately once exhausted.
            if not check_password(code, record.code_hash):
                record.attempts += 1
                if record.attempts >= EmailVerification.MAX_ATTEMPTS:
                    record.delete()
                    return Response(
                        {"message": "No attempts remaining. Please register again."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                record.save(update_fields=['attempts'])
                remaining = EmailVerification.MAX_ATTEMPTS - record.attempts
                return Response(
                    {"message": f"Incorrect code. {remaining} attempt(s) remaining."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Guard against the email being registered between the registration
            # request and now (e.g. via Google sign-in in parallel).
            if User.objects.filter(email__iexact=email).exists():
                record.delete()
                return Response(
                    {"message": "An account with this email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Create user using the pre-hashed password stored during registration.
            user = User(
                email=email,
                first_name=record.first_name,
                last_name=record.last_name,
            )
            user.password = record.password_hash
            try:
                user.save()
            except IntegrityError:
                record.delete()
                return Response(
                    {"message": "An account with this email already exists."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Clean up the verification record — it has served its purpose.
            record.delete()

        # Issue JWT tokens outside the transaction (no DB lock needed).
        refresh = RefreshToken.for_user(user)
        return Response(
            {
                "access": str(refresh.access_token),
                "refresh": str(refresh),
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            status=status.HTTP_201_CREATED,
        )


class MyTokenObtainPairView(TokenObtainPairView):
    """Login endpoint — rate-limited to 10 attempts per IP per hour."""

    serializer_class = MyTokenObtainPairSerializer
    throttle_classes = [LoginRateThrottle]


class MyTokenRefreshView(TokenRefreshView):
    """Refresh endpoint — rate-limited to 30 attempts per IP per hour."""

    throttle_classes = [RefreshRateThrottle]


class PasswordResetRequestView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [PasswordResetRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].strip().lower()

        if not _consume_email_rate_limit('password_reset', email):
            return Response(
                {"message": "Too many requests for this email. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # Compute OTP and hash before looking up user to avoid timing leaks.
        code = str(secrets.randbelow(900000) + 100000)
        code_hash = make_password(code)
        user = User.objects.filter(email__iexact=email, is_active=True).first()

        if user:
            with transaction.atomic():
                PasswordResetRequest.objects.filter(email__iexact=email).delete()
                PasswordResetRequest.objects.create(
                    email=email,
                    code_hash=code_hash,
                )
            if _is_dev_console():
                print(
                    f"\n{'=' * 64}\n"
                    f"  [iApply OTP] Password Reset Code\n"
                    f"  To:   {email}\n"
                    f"  Code: {code}\n"
                    f"{'=' * 64}\n",
                    flush=True,
                )
            send_mail(
                subject='Your iApply password reset code',
                message=(
                    f'Your iApply password reset code is: {code}\n\n'
                    'This code expires in 15 minutes. If you did not request this, '
                    'you can safely ignore this email.'
                ),
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
                recipient_list=[email],
                fail_silently=True,
            )

        return Response(
            {"message": "If an account exists for that email, a reset code has been sent."},
            status=status.HTTP_200_OK,
        )


class PasswordResetConfirmView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_classes = [VerifyRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email'].strip().lower()

        with transaction.atomic():
            record = (
                PasswordResetRequest.objects
                .select_for_update()
                .filter(email__iexact=email)
                .order_by('-created_at')
                .first()
            )

            if not record:
                return Response(
                    {"message": "Invalid or expired code. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if timezone.now() > record.created_at + timedelta(minutes=PasswordResetRequest.EXPIRY_MINUTES):
                record.delete()
                return Response(
                    {"message": "Code has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if record.attempts >= PasswordResetRequest.MAX_ATTEMPTS:
                record.delete()
                return Response(
                    {"message": "Too many incorrect attempts. Please request a new code."},
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )
            if not check_password(serializer.validated_data['code'], record.code_hash):
                record.attempts += 1
                if record.attempts >= PasswordResetRequest.MAX_ATTEMPTS:
                    record.delete()
                    return Response(
                        {"message": "No attempts remaining. Please request a new code."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                record.save(update_fields=['attempts'])
                remaining = PasswordResetRequest.MAX_ATTEMPTS - record.attempts
                return Response(
                    {"message": f"Incorrect code. {remaining} attempt(s) remaining."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.filter(email__iexact=email, is_active=True).first()
            if not user:
                record.delete()
                return Response(
                    {"message": "Invalid or expired code. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            try:
                validate_password(serializer.validated_data['password'], user=user)
            except DjangoValidationError as exc:
                raise DRFValidationError({"password": list(exc.messages)})

            user.set_password(serializer.validated_data['password'])
            user.save(update_fields=['password'])
            record.delete()
            EmailVerification.objects.filter(email__iexact=email).delete()

        _blacklist_user_tokens(user)

        return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)


class MeView(generics.RetrieveAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


class UpdateUserView(generics.UpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def patch(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = LogoutSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {"message": "Logged out successfully"},
            status=status.HTTP_205_RESET_CONTENT,
        )


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [PasswordActionRateThrottle]

    def patch(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'user': request.user},
        )
        serializer.is_valid(raise_exception=True)
        user = request.user
        # Google-only accounts have an unusable password (set_unusable_password).
        # They cannot change their password via this endpoint — they must use the
        # forgot-password flow to set a password first.
        if not user.has_usable_password():
            return Response(
                {"message": "Your account uses Google Sign-In and has no password set. "
                             "Use the Forgot Password flow to set one first."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not user.check_password(serializer.validated_data['old_password']):
            # Generic message — do not hint whether the account exists.
            return Response(
                {"message": "Incorrect current password."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data['new_password'])
        user.save(update_fields=['password'])
        # Pending password-reset OTPs must not survive a password change.
        PasswordResetRequest.objects.filter(email__iexact=user.email).delete()
        _blacklist_user_tokens(user)
        return Response(
            {"message": "Password updated successfully."},
            status=status.HTTP_200_OK,
        )


class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [PasswordActionRateThrottle]

    def delete(self, request, *args, **kwargs):
        serializer = DeleteAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        # Google-only accounts have an unusable password; skip the password check.
        # The user is already authenticated with a valid JWT, which is sufficient
        # proof of identity for account deletion in this case.
        if user.has_usable_password():
            if not user.check_password(serializer.validated_data['password']):
                return Response(
                    {"message": "Invalid password."},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        with transaction.atomic():
            _blacklist_user_tokens(user)
            EmailVerification.objects.filter(email__iexact=user.email).delete()
            PasswordResetRequest.objects.filter(email__iexact=user.email).delete()
            user.delete()
        return Response(
            {"message": "Account deleted successfully."},
            status=status.HTTP_200_OK,
        )


class GoogleLoginView(APIView):
    """
    Sign in (or sign up) with a Google account.

    Security notes:
    - The ID token is verified server-side against Google's public keys with the
      audience pinned to GOOGLE_CLIENT_ID; no client-supplied email is trusted.
    - `email_verified` must be strictly True. Without that check an unverified
      Google address could be used to take over an existing account.
    - Users are matched primarily by Google's stable `sub` identifier and linked
      by verified email on first Google sign-in; conflicting `sub` values are
      rejected.
    - Rate-limited to 10 attempts per IP per hour.
    - Every credential failure returns one generic message, so the endpoint
      cannot be used to probe which emails or Google accounts exist.
    """

    permission_classes = [AllowAny]
    throttle_classes = [GoogleLoginRateThrottle]
    authentication_classes = []

    def post(self, request, *args, **kwargs):
        serializer = GoogleLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            info = verify_google_id_token(serializer.validated_data['credential'])
        except GoogleAuthServiceError:
            return Response(
                {'message': 'Google sign-in is not available right now.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except GoogleAuthError:
            return Response(
                {'message': 'Could not verify that Google account. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        email = info['email']
        google_sub = info['google_sub']
        first_name, last_name = split_google_name(info)

        inactive_or_mismatch = False
        created = False
        refresh = None
        token_marked = False

        try:
            with transaction.atomic():
                user = User.objects.select_for_update().filter(google_sub=google_sub).first()

                if user is None:
                    user = User.objects.select_for_update().filter(email__iexact=email).first()
                    if user is not None:
                        if user.google_sub and user.google_sub != google_sub:
                            inactive_or_mismatch = True
                        elif not user.is_active:
                            inactive_or_mismatch = True
                        else:
                            user.google_sub = google_sub
                            user.save(update_fields=['google_sub'])
                    else:
                        # set_unusable_password(): Google-only until the user explicitly
                        # sets a password, so the account can never be entered with a
                        # blank or guessed password.
                        user = User(
                            email=email,
                            first_name=first_name[:150],
                            last_name=last_name[:150],
                            google_sub=google_sub,
                        )
                        user.set_unusable_password()
                        user.save()
                        created = True
                elif not user.is_active:
                    inactive_or_mismatch = True

                if not inactive_or_mismatch and user is not None:
                    # A Google-verified address proves ownership, so any half-finished
                    # email-verification record for it is now redundant.
                    EmailVerification.objects.filter(email__iexact=email).delete()
                    refresh = RefreshToken.for_user(user)
                    # Burn token only after DB changes and JWT issuance succeed so a
                    # failed login never consumes a valid token.
                    mark_google_id_token_used(info['replay_key'], info['replay_ttl'])
                    token_marked = True
        except GoogleAuthServiceError:
            return Response(
                {'message': 'Google sign-in is not available right now.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except GoogleAuthError:
            return Response(
                {'message': 'Could not verify that Google account. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except IntegrityError:
            if token_marked:
                try:
                    cache.delete(info['replay_key'])
                except Exception:
                    pass
            return Response(
                {'message': 'Could not verify that Google account. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except DatabaseError as exc:
            if token_marked:
                try:
                    cache.delete(info['replay_key'])
                except Exception:
                    pass
            logger.error('Database error during Google login: %s', exc)
            return Response(
                {'message': 'Google sign-in is not available right now.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

        if inactive_or_mismatch or user is None or refresh is None:
            # Same generic message as an invalid token — do not reveal that the
            # account exists, is disabled, or conflicts on Google subject ID.
            return Response(
                {'message': 'Could not verify that Google account. Please try again.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Same response shape as /account/login/ so the frontend can reuse a
        # single code path for both sign-in methods.
        return Response(
            {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'id': str(user.id),
                'created': created,
            },
            status=status.HTTP_200_OK,
        )
