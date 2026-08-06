from django.urls import path
from .views import ChangePasswordView, DeleteAccountView, LogoutView, MeView, MyTokenObtainPairView, RegistrationView, UpdateUserView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("register/", RegistrationView.as_view(), name="register"),
    path("login/", MyTokenObtainPairView.as_view(), name="login"),
    path("login/refresh/", TokenRefreshView.as_view(), name="login-refresh"),
    path('profile/', MeView.as_view(), name='profile'),
    path('update-profile/', UpdateUserView.as_view(), name="update"),
    path('change-password/', ChangePasswordView.as_view(), name="changePassword"),
    path('delete-account/', DeleteAccountView.as_view(), name='deletePassword'),
    path('logout/', LogoutView.as_view(), name='logout'),
]