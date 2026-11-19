from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from .health import healthz, readyz

urlpatterns = [
    path("healthz", healthz, name="healthz"),
    path("healthz/", healthz, name="healthz-slash"),
    path("readyz", readyz, name="readyz"),
    path("readyz/", readyz, name="readyz-slash"),
    path(settings.ADMIN_URL, admin.site.urls),
    path("account/", include("accounts.urls")),
    path("tracker/", include("tracker.urls")),
]