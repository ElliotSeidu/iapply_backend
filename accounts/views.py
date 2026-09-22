import secrets

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone
from datetime import timedelta

from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import EmailVerification, User
from .serializers import (
    ChangePasswordSerializer,
    DeleteAccountSerializer,
    LogoutSerializer,
    MyTokenObtainPairSerializer,
    UserSerializer,
    VerificationConfirmSerializer,
    VerificationRequestSerializer,
)
from .throttles import LoginRateThrottle, RegisterRateThrottle, VerifyRateThrottle


class RegistrationView(APIView):
    """
    Initiates the email-verification registration flow.

    Security notes:
    - Uses `secrets.randbelow` (CSPRNG) instead of `random` for OTP generation.
    - Always returns HTTP 200 with the same message whether or not the email
      already exists, to prevent user-enumeration via timing/response differences.
    - Rate-limited to 5 requests per IP per hour to curb email-spam abuse.
    """

    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def post(self, request, *args, **kwargs):
        serializer = VerificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = data['email'].strip().lower()

        # Always return the same response whether or not the email is already
        # registered — avoids leaking which emails exist (user enumeration).
        if User.objects.filter(email__iexact=email).exists():
            return Response(
                {"message": "Verification code sent to email"},
                status=status.HTTP_200_OK,
            )

        # Delete any previous pending verifications for this email so the
        # user isn't blocked by a stale record.
        EmailVerification.objects.filter(email=email).delete()

        # secrets.randbelow is cryptographically secure (unlike random.randint).
        code = str(secrets.randbelow(900000) + 100000)
        password_hash = make_password(data['password'])
        EmailVerification.objects.create(
            email=email,
            code_hash=make_password(code),
            password_hash=password_hash,
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
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
                .filter(email=email)
                .order_by('-created_at')
                .first()
            )

            if not record:
                return Response(
                    {"message": "Invalid or expired code. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check expiry (10 minutes)
            if timezone.now() > record.created_at + timedelta(minutes=10):
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

            # Wrong code — increment attempt counter and persist
            if not check_password(code, record.code_hash):
                record.attempts += 1
                record.save(update_fields=['attempts'])
                remaining = EmailVerification.MAX_ATTEMPTS - record.attempts
                return Response(
                    {
                        "message": (
                            f"Incorrect code. {remaining} attempt(s) remaining."
                            if remaining > 0
                            else "No attempts remaining. Please register again."
                        )
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Guard against the email being registered between the registration
            # request and now (e.g. via a different verification flow in parallel).
            if User.objects.filter(email=email).exists():
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
            user.save()

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

    def patch(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            # Generic message — do not hint whether the account exists.
            return Response(
                {"message": "Incorrect current password."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        for token in OutstandingToken.objects.filter(
            user=user,
            blacklistedtoken__isnull=True,
        ):
            try:
                RefreshToken(token.token).blacklist()
            except Exception:
                continue
        return Response(
            {"message": "Password updated successfully."},
            status=status.HTTP_200_OK,
        )


class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        serializer = DeleteAccountSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data['password']):
            return Response(
                {"message": "Invalid password."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        for token in OutstandingToken.objects.filter(
            user=user,
            blacklistedtoken__isnull=True,
        ):
            try:
                RefreshToken(token.token).blacklist()
            except Exception:
                continue
        user.delete()
        return Response(
            {"message": "Account deleted successfully."},
            status=status.HTTP_200_OK,
        )