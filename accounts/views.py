from django.shortcuts import render
from .serializers import ChangePasswordSerializer, DeleteAccountSerializer, MyTokenObtainPairSerializer, RegistrationSerializer, UserSerializer, LogoutSerializer
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response

# Create your views here.
class RegistrationView(generics.CreateAPIView):
    serializer_class = RegistrationSerializer
    permission_classes = [AllowAny]


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