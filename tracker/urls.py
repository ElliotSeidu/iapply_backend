from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import ApplicationViewSet, ReminderViewSet, AnalyticsView

router = DefaultRouter()
router.register(r"applications", ApplicationViewSet, basename="application")
router.register(r"reminders", ReminderViewSet, basename="reminder")

urlpatterns = [
    path("analytics/", AnalyticsView.as_view(), name="analytics"),
    path("", include(router.urls)),
]