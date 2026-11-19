from datetime import date, timedelta
from unittest import mock

from django.core.cache import cache
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APITestCase

from accounts.models import User
from .models import Application, Reminder, StatusEvent


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


class RegressionTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='r@example.com', password='StrongPassw0rd!')
        self.client.force_authenticate(self.user)

    def test_date_applied_validation_does_not_crash_on_29_feb(self):
        # Previously `today.replace(year=today.year - 50)` raised ValueError
        # (HTTP 500) when the request was made on 29 Feb.
        with mock.patch('tracker.serializers.timezone.localdate', return_value=date(2028, 2, 29)):
            resp = self.client.post(reverse('application-list'), {
                'company_name': 'X', 'role_title': 'Y', 'channel': 'email',
                'date_applied': '2028-02-01',
            }, format='json')
        self.assertEqual(resp.status_code, 201)

    def test_application_list_query_count_is_constant(self):
        for i in range(8):
            app = Application.objects.create(
                user=self.user, company_name=f'Co{i}', role_title='Dev', channel='email',
            )
            Reminder.objects.create(application=app, remind_at=timezone.now(), message='m')
        # session-less JWT auth: count + page of apps + 2 prefetches. Must not grow with N.
        with self.assertNumQueries(4):
            resp = self.client.get(reverse('application-list'))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.data['results']), 8)

    def test_reminder_list_is_scoped_and_cheap(self):
        other = User.objects.create_user(email='o@example.com', password='StrongPassw0rd!')
        mine = Application.objects.create(user=self.user, company_name='A', role_title='D', channel='email')
        theirs = Application.objects.create(user=other, company_name='B', role_title='D', channel='email')
        Reminder.objects.create(application=mine, remind_at=timezone.now(), message='mine')
        Reminder.objects.create(application=theirs, remind_at=timezone.now(), message='theirs')
        resp = self.client.get(reverse('reminder-list'))
        self.assertEqual([r['message'] for r in resp.data['results']], ['mine'])


class TrackerSecurityHardeningTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user_a = User.objects.create_user(email='ta@example.com', password='StrongPassw0rd!')
        self.user_b = User.objects.create_user(email='tb@example.com', password='StrongPassw0rd!')
        self.app_b = Application.objects.create(
            user=self.user_b,
            company_name='Secret Corp',
            role_title='Staff Engineer',
            channel='referral',
        )
        self.rem_b = Reminder.objects.create(
            application=self.app_b,
            remind_at=timezone.now() + timedelta(days=2),
            message='Follow up secretly',
        )

    def tearDown(self):
        cache.clear()

    def test_unauthenticated_requests_rejected_401(self):
        for method, url in [
            ('get', reverse('application-list')),
            ('post', reverse('application-list')),
            ('get', reverse('application-detail', args=[self.app_b.pk])),
            ('post', reverse('application-log-status', args=[self.app_b.pk])),
            ('get', reverse('reminder-list')),
            ('get', reverse('reminder-detail', args=[self.rem_b.pk])),
            ('get', reverse('analytics')),
        ]:
            resp = getattr(self.client, method)(url, {}, format='json')
            self.assertEqual(resp.status_code, 401, url)

    def test_idor_matrix_prevents_cross_user_access_and_analytics_leakage(self):
        app_a = Application.objects.create(
            user=self.user_a,
            company_name='Mine Inc',
            role_title='Engineer',
            channel='email',
        )
        rem_a = Reminder.objects.create(
            application=app_a,
            remind_at=timezone.now() + timedelta(days=1),
            message='Mine',
        )
        self.client.force_authenticate(self.user_a)

        # User A cannot read, edit, delete, or log status on User B's application
        app_detail_b = reverse('application-detail', args=[self.app_b.pk])
        self.assertEqual(self.client.get(app_detail_b).status_code, 404)
        self.assertEqual(
            self.client.patch(app_detail_b, {'notes': 'pwned'}, format='json').status_code,
            404,
        )
        self.assertEqual(
            self.client.put(
                app_detail_b,
                {'company_name': 'X', 'role_title': 'Y', 'channel': 'email'},
                format='json',
            ).status_code,
            404,
        )
        self.assertEqual(self.client.delete(app_detail_b).status_code, 404)
        self.assertEqual(
            self.client.post(
                reverse('application-log-status', args=[self.app_b.pk]),
                {'status': 'offer'},
                format='json',
            ).status_code,
            404,
        )

        # User A cannot read, edit, delete User B's reminder or repoint own reminder
        rem_detail_b = reverse('reminder-detail', args=[self.rem_b.pk])
        self.assertEqual(self.client.get(rem_detail_b).status_code, 404)
        self.assertEqual(
            self.client.patch(rem_detail_b, {'is_done': True}, format='json').status_code,
            404,
        )
        self.assertEqual(self.client.delete(rem_detail_b).status_code, 404)
        self.assertEqual(
            self.client.patch(
                reverse('reminder-detail', args=[rem_a.pk]),
                {'application': str(self.app_b.pk)},
                format='json',
            ).status_code,
            400,
        )

        # User A's analytics must count only User A's 1 application
        analytics_resp = self.client.get(reverse('analytics'))
        self.assertEqual(analytics_resp.status_code, 200)
        self.assertEqual(analytics_resp.data['total_applications'], 1)

    def test_mass_assignment_ignores_user_and_current_status(self):
        self.client.force_authenticate(self.user_a)
        resp = self.client.post(
            reverse('application-list'),
            {
                'company_name': 'Acme',
                'role_title': 'Backend Dev',
                'channel': 'linkedin',
                'user': self.user_b.pk,
                'current_status': 'offer',
            },
            format='json',
        )
        self.assertEqual(resp.status_code, 201)
        created = Application.objects.get(pk=resp.data['id'])
        self.assertEqual(created.user_id, self.user_a.id)
        self.assertEqual(created.current_status, Application.Status.APPLIED)

    def test_create_application_without_date_applied_uses_localdate_no_crash(self):
        self.client.force_authenticate(self.user_a)
        resp = self.client.post(
            reverse('application-list'),
            {'company_name': 'NoDate Co', 'role_title': 'SRE', 'channel': 'email'},
            format='json',
        )
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.data['days_since_applied'], 0)

    def test_validation_rejects_negative_salary_oversized_notes_and_dangerous_schemes(self):
        self.client.force_authenticate(self.user_a)
        neg_salary = self.client.post(
            reverse('application-list'),
            {
                'company_name': 'Co',
                'role_title': 'Dev',
                'channel': 'email',
                'monthly_salary': '-10.00',
            },
            format='json',
        )
        self.assertEqual(neg_salary.status_code, 400)
        self.assertIn('monthly_salary', neg_salary.data)

        for bad_url in ['javascript:alert(1)', '  JavaScript:alert(1)', 'data:text/html,xss', 'vbscript:msgbox']:
            bad_source = self.client.post(
                reverse('application-list'),
                {
                    'company_name': 'Co',
                    'role_title': 'Dev',
                    'channel': 'email',
                    'source_detail': bad_url,
                },
                format='json',
            )
            self.assertEqual(bad_source.status_code, 400, bad_url)

        long_notes = self.client.post(
            reverse('application-list'),
            {
                'company_name': 'Co',
                'role_title': 'Dev',
                'channel': 'email',
                'notes': 'x' * 4001,
            },
            format='json',
        )
        self.assertEqual(long_notes.status_code, 400)

        app = Application.objects.create(
            user=self.user_a, company_name='Co', role_title='Dev', channel='email'
        )
        long_status_notes = self.client.post(
            reverse('application-log-status', args=[app.pk]),
            {'status': 'interview', 'notes': 'x' * 4001},
            format='json',
        )
        self.assertEqual(long_status_notes.status_code, 400)

    def test_removed_stale_endpoint_returns_404(self):
        self.client.force_authenticate(self.user_a)
        resp = self.client.get('/tracker/applications/stale/')
        self.assertEqual(resp.status_code, 404)