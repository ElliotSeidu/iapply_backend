from django.shortcuts import render
from .serializers import ChangePasswordSerializer, DeleteAccountSerializer, MyTokenObtainPairSerializer, RegistrationSerializer, UserSerializer, LogoutSerializer, VerificationRequestSerializer, VerificationConfirmSerializer
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
import random
from django.contrib.auth.hashers import make_password
from .models import EmailVerification, User
from rest_framework_simplejwt.tokens import RefreshToken

# Create your views here.
class RegistrationView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = VerificationRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        email = data['email']
        # generate a 6-digit code
        code = str(random.randint(100000, 999999))
        password_hash = make_password(data['password'])
        # save verification
        EmailVerification.objects.create(
            email=email,
            code=code,
            password_hash=password_hash,
            first_name=data.get('first_name', ''),
            last_name=data.get('last_name', ''),
        )
        # send email
        subject = 'Your verification code'
        message = f'Your verification code is: {code}'
        from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', None)
        send_mail(subject, message, from_email, [email])
        return Response({"message": "Verification code sent to email"}, status=status.HTTP_200_OK)


class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = VerificationConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        code = serializer.validated_data['code']
        try:
            record = EmailVerification.objects.filter(email=email, code=code).order_by('-created_at').first()
        except EmailVerification.DoesNotExist:
            record = None
        if not record:
            return Response({"message": "Invalid code or email"}, status=status.HTTP_400_BAD_REQUEST)
        # check expiry (10 minutes)
        if timezone.now() > record.created_at + timedelta(minutes=10):
            record.delete()
            return Response({"message": "Code expired"}, status=status.HTTP_400_BAD_REQUEST)
        # create user
        if User.objects.filter(email=email).exists():
            record.delete()
            return Response({"message": "User with this email already exists"}, status=status.HTTP_400_BAD_REQUEST)
        user = User(email=email, first_name=record.first_name, last_name=record.last_name)
        user.password = record.password_hash
        user.save()
        # issue tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)
        record.delete()
        return Response(
            {
                "access": access_token,
                "refresh": refresh_token,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name,
            },
            status=status.HTTP_201_CREATED,
        )


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


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
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, *args, **kwargs):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            is_correct = user.check_password(old_password)
            if is_correct:
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password updated successfully"}, status=status.HTTP_200_OK)
            return Response({"message": "Passwords do not match"}, status=status.HTTP_400_BAD_REQUEST)


class DeleteAccountView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        serializer = DeleteAccountSerializer(data=request.data)
        user = request.user
        if serializer.is_valid(raise_exception=True):
            password = serializer.validated_data["password"]
            is_correct = user.check_password(password)
            if is_correct:
                user.delete()
                return Response({"message": "User deleted successfully"}, status=status.HTTP_200_OK)
            return Response({"message": "Invalid password"}, status=status.HTTP_401_UNAUTHORIZED)