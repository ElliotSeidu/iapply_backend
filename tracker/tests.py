from datetime import date, timedelta

from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import User
from .models import Application, StatusEvent


class TrackerSecurityAndAnalyticsTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='a@example.com', password='StrongPassw0rd!')
        self.other = User.objects.create_user(email='b@example.com', password='StrongPassw0rd!')
        self.client.force_authenticate(self.user)

    def _app(self, user, days_ago=10, **kw):
        return Application.objects.create(
            user=user, company_name='Acme', role_title='Dev', channel='linkedin',
            date_applied=date.today() - timedelta(days=days_ago), **kw,
        )

    def test_analytics_avg_days_to_first_response_is_db_computed(self):
        app = self._app(self.user, days_ago=10)
        StatusEvent.objects.create(
            application=app, status='interview',
            occurred_at=timezone.now() - timedelta(days=6),
        )
        self._app(self.user, days_ago=3)  # no response yet -> ignored
        resp = self.client.get(reverse('analytics'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['total_applications'], 2)
        self.assertAlmostEqual(resp.data['avg_days_to_first_response'], 4.0, delta=1.0)

    def test_analytics_empty(self):
        resp = self.client.get(reverse('analytics'))
        self.assertEqual(resp.data['avg_days_to_first_response'], None)

    def test_cannot_read_other_users_application(self):
        foreign = self._app(self.other)
        resp = self.client.get(reverse('application-detail', args=[foreign.pk]))
        self.assertEqual(resp.status_code, 404)

    def test_cannot_attach_reminder_to_other_users_application(self):
        foreign = self._app(self.other)
        resp = self.client.post(reverse('reminder-list'), {
            'application': str(foreign.pk),
            'remind_at': (timezone.now() + timedelta(days=1)).isoformat(),
            'message': 'hi',
        }, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_future_date_applied_rejected(self):
        resp = self.client.post(reverse('application-list'), {
            'company_name': 'X', 'role_title': 'Y', 'channel': 'email',
            'date_applied': (date.today() + timedelta(days=2)).isoformat(),
        }, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('date_applied', resp.data)

    def test_far_future_reminder_rejected(self):
        app = self._app(self.user)
        resp = self.client.post(reverse('reminder-list'), {
            'application': str(app.pk),
            'remind_at': (timezone.now() + timedelta(days=1000)).isoformat(),
            'message': 'later',
        }, format='json')
        self.assertEqual(resp.status_code, 400)


class GoogleOnlyAccountTests(APITestCase):
    def setUp(self):
        self.user = User(email='g@example.com')
        self.user.set_unusable_password()
        self.user.save()
        self.client.force_authenticate(self.user)

    def test_profile_reports_no_password(self):
        resp = self.client.get(reverse('profile'))
        self.assertIs(resp.data['has_password'], False)

    def test_change_password_returns_helpful_error(self):
        resp = self.client.patch(reverse('change-password'), {
            'old_password': 'x', 'new_password': 'BrandNewPassw0rd!', 'new_password2': 'BrandNewPassw0rd!',
        }, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('Google', resp.data['message'])

    def test_can_delete_account_without_password(self):
        resp = self.client.delete(reverse('delete-account'), {}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(email='g@example.com').exists())

    def test_password_user_still_needs_password_to_delete(self):
        u = User.objects.create_user(email='p@example.com', password='StrongPassw0rd!')
        self.client.force_authenticate(u)
        resp = self.client.delete(reverse('delete-account'), {}, format='json')
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(User.objects.filter(email='p@example.com').exists())


class OtpFormatTests(APITestCase):
    def test_non_numeric_or_long_code_rejected_before_db(self):
        for bad in ['abcdef', '12345', '1' * 5000]:
            resp = self.client.post(reverse('register-verify'),
                                    {'email': 'x@example.com', 'code': bad}, format='json')
            self.assertEqual(resp.status_code, 400, bad[:10])
            self.assertIn('code', resp.data)
