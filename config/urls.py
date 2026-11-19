from django.conf import settings
from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path(settings.ADMIN_URL, admin.site.urls),
    path("account/", include("accounts.urls")),
    path("tracker/", include("tracker.urls")),
]