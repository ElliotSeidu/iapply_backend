from django.urls import path

from .views import (
    ChangePasswordView,
    DeleteAccountRequestView,
    DeleteAccountView,
    GoogleLoginView,
    LogoutView,
    MeView,
    MyTokenObtainPairView,
    MyTokenRefreshView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RegistrationView,
    UpdateUserView,
    VerifyEmailView,
)

urlpatterns = [
    path("register/", RegistrationView.as_view(), name="register"),
    path("register/verify/", VerifyEmailView.as_view(), name="register-verify"),
    path("login/", MyTokenObtainPairView.as_view(), name="login"),
    path("google/", GoogleLoginView.as_view(), name="google-login"),
    path("password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"),
    path("password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"),
    path("login/refresh/", MyTokenRefreshView.as_view(), name="login-refresh"),
    path('profile/', MeView.as_view(), name='profile'),
    path('update-profile/', UpdateUserView.as_view(), name="update-profile"),
    path('change-password/', ChangePasswordView.as_view(), name="change-password"),
    path('delete-account/request/', DeleteAccountRequestView.as_view(), name='delete-account-request'),
    path('delete-account/', DeleteAccountView.as_view(), name='delete-account'),  # was 'deletePassword'
    path('logout/', LogoutView.as_view(), name='logout'),
]