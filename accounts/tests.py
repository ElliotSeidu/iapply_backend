from datetime import timedelta
import importlib
import json
import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.apps import apps as django_apps
from django.conf import settings
from django.core.cache import cache
from django.db import DatabaseError, connection
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from google.auth import exceptions as google_exceptions
import requests
from rest_framework.test import APIClient, APITestCase
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken

from config.settings import check_shared_throttle_cache
from .models import AccountDeletionRequest, EmailVerification, PasswordResetRequest, User


class EmailVerificationTests(TestCase):
	def test_request_creates_verification_record(self):
		url = reverse('register')
		payload = {
			'email': 'testuser@example.com',
			'password': 'StrongPassw0rd!',
			'password2': 'StrongPassw0rd!',
			'first_name': 'Test',
			'last_name': 'User',
		}
		response = self.client.post(url, data=payload, content_type='application/json')
		self.assertEqual(response.status_code, 200)
		records = EmailVerification.objects.filter(email='testuser@example.com')
		self.assertTrue(records.exists())

	def test_verify_creates_user_and_deletes_record(self):
		# simulate request
		req_url = reverse('register')
		payload = {
			'email': 'verifyme@example.com',
			'password': 'AnotherStrong1!',
			'password2': 'AnotherStrong1!',
			'first_name': 'Verify',
			'last_name': 'Me',
		}
		with patch('accounts.views.secrets.randbelow', return_value=123456):
			resp = self.client.post(req_url, data=payload, content_type='application/json')
		self.assertEqual(resp.status_code, 200)
		record = EmailVerification.objects.filter(email='verifyme@example.com').first()
		self.assertIsNotNone(record)
		self.assertNotEqual(record.code_hash, '223456')
		# call verify endpoint
		verify_url = reverse('register-verify')
		verify_resp = self.client.post(
			verify_url,
			data={'email': 'verifyme@example.com', 'code': '223456'},
			content_type='application/json',
		)
		self.assertEqual(verify_resp.status_code, 201)
		# user should exist and record deleted
		self.assertTrue(User.objects.filter(email='verifyme@example.com').exists())
		self.assertFalse(EmailVerification.objects.filter(email='verifyme@example.com').exists())


class SessionRevocationTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = User.objects.create_user(
			email='session@example.com',
			password='StrongPassw0rd!',
		)
		self.client.force_authenticate(user=self.user)

	def test_logout_only_blacklists_authenticated_users_refresh_token(self):
		refresh = RefreshToken.for_user(self.user)
		response = self.client.post(
			reverse('logout'),
			data={'refresh': str(refresh)},
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 205)
		self.assertTrue(
			BlacklistedToken.objects.filter(token__token=str(refresh)).exists()
		)

	def test_password_change_revokes_all_refresh_tokens(self):
		refresh = RefreshToken.for_user(self.user)
		response = self.client.patch(
			reverse('change-password'),
			data={
				'old_password': 'StrongPassw0rd!',
				'new_password': 'NewStrongPassw0rd!',
				'new_password2': 'NewStrongPassw0rd!',
			},
			content_type='application/json',
		)

		self.assertEqual(response.status_code, 200)
		self.assertTrue(
			BlacklistedToken.objects.filter(token__token=str(refresh)).exists()
		)


class PasswordResetTests(TestCase):
	def setUp(self):
		self.client = APIClient()
		self.user = User.objects.create_user(
			email='reset@example.com',
			password='StrongPassw0rd!',
		)

	def test_request_sends_code_and_confirm_changes_password(self):
		with patch('accounts.views.secrets.randbelow', return_value=123456), patch('accounts.views.send_mail'):
			request_response = self.client.post(
				reverse('password-reset-request'),
				data={'email': self.user.email},
				content_type='application/json',
			)
		self.assertEqual(request_response.status_code, 200)
		self.assertTrue(PasswordResetRequest.objects.filter(email=self.user.email).exists())

		confirm_response = self.client.post(
			reverse('password-reset-confirm'),
			data={
				'email': self.user.email,
				'code': '223456',
				'password': 'NewStrongPassw0rd!',
				'password2': 'NewStrongPassw0rd!',
			},
			content_type='application/json',
		)
		self.assertEqual(confirm_response.status_code, 200)
		self.user.refresh_from_db()
		self.assertTrue(self.user.check_password('NewStrongPassw0rd!'))
		self.assertFalse(PasswordResetRequest.objects.filter(email=self.user.email).exists())

	def test_unknown_email_returns_generic_response(self):
		with patch('accounts.views.send_mail') as send_mail:
			response = self.client.post(
				reverse('password-reset-request'),
				data={'email': 'unknown@example.com'},
				content_type='application/json',
			)
		self.assertEqual(response.status_code, 200)
		self.assertEqual(
			response.data['message'],
			"If an account exists for that email, a reset code has been sent.",
		)
		send_mail.assert_not_called()


class AccountSecurityRegressionTests(APITestCase):
	def setUp(self):
		cache.clear()
		self.user = User.objects.create_user(
			email='alice@example.com',
			password='StrongPassw0rd!',
			first_name='Alice',
			last_name='Rivers',
		)
		self.other = User.objects.create_user(
			email='bob@example.com',
			password='StrongPassw0rd!',
			first_name='Bob',
			last_name='Stone',
		)

	def tearDown(self):
		cache.clear()

	def test_protected_account_endpoints_require_authentication(self):
		for method, url in [
			('get', reverse('profile')),
			('patch', reverse('update-profile')),
			('patch', reverse('change-password')),
			('delete', reverse('delete-account')),
			('post', reverse('logout')),
		]:
			resp = getattr(self.client, method)(url, {}, format='json')
			self.assertEqual(resp.status_code, 401, url)

	def test_logout_rejects_another_users_refresh_token(self):
		other_refresh = RefreshToken.for_user(self.other)
		self.client.force_authenticate(self.user)
		resp = self.client.post(
			reverse('logout'),
			{'refresh': str(other_refresh)},
			format='json',
		)
		self.assertEqual(resp.status_code, 400)
		self.assertFalse(
			BlacklistedToken.objects.filter(token__token=str(other_refresh)).exists()
		)

	def test_profile_update_blocks_mass_assignment(self):
		self.client.force_authenticate(self.user)
		resp = self.client.patch(
			reverse('update-profile'),
			{
				'first_name': '  Updated  ',
				'email': 'hijack@example.com',
				'is_staff': True,
				'is_superuser': True,
				'google_sub': 'evil-sub',
			},
			format='json',
		)
		self.assertEqual(resp.status_code, 200)
		self.user.refresh_from_db()
		self.assertEqual(self.user.first_name, 'Updated')
		self.assertEqual(self.user.email, 'alice@example.com')
		self.assertFalse(self.user.is_staff)
		self.assertFalse(self.user.is_superuser)
		self.assertIsNone(self.user.google_sub)

	def test_case_insensitive_login_works(self):
		resp = self.client.post(
			reverse('login'),
			{'email': '  ALICE@Example.COM ', 'password': 'StrongPassw0rd!'},
			format='json',
		)
		self.assertEqual(resp.status_code, 200)
		self.assertIn('access', resp.data)
		self.assertIn('refresh', resp.data)

	def test_user_stored_with_mixed_case_email_can_still_log_in(self):
		User.objects.filter(pk=self.user.pk).update(email='Alice.Mixed@Example.COM')
		for login_email in ('alice.mixed@example.com', '  ALICE.MIXED@example.com '):
			resp = self.client.post(
				reverse('login'),
				{'email': login_email, 'password': 'StrongPassw0rd!'},
				format='json',
			)
			self.assertEqual(resp.status_code, 200)
			self.assertIn('access', resp.data)

	def test_mixed_case_registration_of_existing_email_treated_as_same_account(self):
		User.objects.filter(pk=self.user.pk).update(email='Alice.Stored@Example.COM')
		initial_count = User.objects.count()
		with patch('accounts.views.send_mail') as mock_mail:
			resp = self.client.post(
				reverse('register'),
				{
					'email': '  ALICE.STORED@example.com  ',
					'password': 'UniquePassw0rd!99',
					'password2': 'UniquePassw0rd!99',
					'first_name': 'Alice',
					'last_name': 'Dup',
				},
				format='json',
			)
		self.assertEqual(resp.status_code, 200)
		self.assertEqual(resp.data, {'message': 'Verification code sent to email'})
		self.assertEqual(User.objects.count(), initial_count)
		self.assertFalse(
			EmailVerification.objects.filter(email__iexact='alice.stored@example.com').exists()
		)
		mock_mail.assert_not_called()

	def test_user_save_normalizes_email_to_lowercase(self):
		direct = User(email='  DirectSave@Example.COM  ')
		direct.set_password('StrongPassw0rd!')
		direct.save()
		direct.refresh_from_db()
		self.assertEqual(direct.email, 'directsave@example.com')

	def test_lowercase_user_emails_migration_normalizes_and_stops_on_duplicates(self):
		migration_mod = importlib.import_module('accounts.migrations.0009_lowercase_user_emails')
		schema_editor = SimpleNamespace(connection=connection)
		User.objects.filter(pk=self.user.pk).update(email='Alice.PreMigration@Example.COM')

		migration_mod.lowercase_user_emails(django_apps, schema_editor)
		self.user.refresh_from_db()
		self.assertEqual(self.user.email, 'alice.premigration@example.com')

		# Create case-insensitive duplicate rows directly via bulk_create (bypassing save())
		User.objects.bulk_create([
			User(email='Dupe.User@Example.COM', password='x'),
			User(email='dupe.user@example.com', password='x'),
		])
		with self.assertRaises(RuntimeError) as ctx:
			migration_mod.lowercase_user_emails(django_apps, schema_editor)
		self.assertIn('1 case-insensitive duplicate email group(s)', str(ctx.exception))
		self.assertNotIn('@example.com', str(ctx.exception).lower())
		self.assertTrue(User.objects.filter(email='Dupe.User@Example.COM').exists())

	def test_registration_enumeration_response_and_work_parity(self):
		payload_existing = {
			'email': self.user.email,
			'password': 'UniquePassw0rd!99',
			'password2': 'UniquePassw0rd!99',
			'first_name': 'Other',
			'last_name': 'Person',
		}
		payload_new = {
			'email': 'brandnew@example.com',
			'password': 'UniquePassw0rd!99',
			'password2': 'UniquePassw0rd!99',
			'first_name': 'New',
			'last_name': 'Person',
		}
		with patch('accounts.views.make_password', return_value='hashed') as mock_hash, patch(
			'accounts.views.send_mail'
		) as mock_mail:
			resp_existing = self.client.post(reverse('register'), payload_existing, format='json')
			existing_hash_calls = mock_hash.call_count
			mock_hash.reset_mock()
			resp_new = self.client.post(reverse('register'), payload_new, format='json')
			new_hash_calls = mock_hash.call_count

		self.assertEqual(resp_existing.status_code, 200)
		self.assertEqual(resp_new.status_code, 200)
		self.assertEqual(resp_existing.data, resp_new.data)
		self.assertEqual(existing_hash_calls, new_hash_calls)
		self.assertEqual(mock_mail.call_count, 1)

	def test_register_verify_deletes_record_immediately_on_fifth_wrong_attempt(self):
		with patch('accounts.views.secrets.randbelow', return_value=123456), patch(
			'accounts.views.send_mail'
		):
			self.client.post(
				reverse('register'),
				{
					'email': 'bruteforce@example.com',
					'password': 'StrongPassw0rd!9',
					'password2': 'StrongPassw0rd!9',
					'first_name': 'Brute',
					'last_name': 'Force',
				},
				format='json',
			)

		verify_url = reverse('register-verify')
		for _ in range(EmailVerification.MAX_ATTEMPTS):
			resp = self.client.post(
				verify_url,
				{'email': 'bruteforce@example.com', 'code': '000000'},
				format='json',
			)
			self.assertEqual(resp.status_code, 400)

		self.assertFalse(
			EmailVerification.objects.filter(email='bruteforce@example.com').exists()
		)
		# Even the real code now fails because the record was purged on attempt 5.
		late = self.client.post(
			verify_url,
			{'email': 'bruteforce@example.com', 'code': '223456'},
			format='json',
		)
		self.assertEqual(late.status_code, 400)

	def test_password_reset_confirm_deletes_record_immediately_on_fifth_wrong_attempt(self):
		with patch('accounts.views.secrets.randbelow', return_value=123456), patch(
			'accounts.views.send_mail'
		):
			self.client.post(
				reverse('password-reset-request'),
				{'email': self.user.email},
				format='json',
			)

		confirm_url = reverse('password-reset-confirm')
		for _ in range(PasswordResetRequest.MAX_ATTEMPTS):
			resp = self.client.post(
				confirm_url,
				{
					'email': self.user.email,
					'code': '000000',
					'password': 'NewStrongPassw0rd!9',
					'password2': 'NewStrongPassw0rd!9',
				},
				format='json',
			)
			self.assertEqual(resp.status_code, 400)

		self.assertFalse(
			PasswordResetRequest.objects.filter(email=self.user.email).exists()
		)
		late = self.client.post(
			confirm_url,
			{
				'email': self.user.email,
				'code': '223456',
				'password': 'NewStrongPassw0rd!9',
				'password2': 'NewStrongPassw0rd!9',
			},
			format='json',
		)
		self.assertEqual(late.status_code, 400)

	def test_password_change_invalidates_pending_reset_codes_and_checks_similarity(self):
		with patch('accounts.views.secrets.randbelow', return_value=123456), patch(
			'accounts.views.send_mail'
		):
			self.client.post(
				reverse('password-reset-request'),
				{'email': self.user.email},
				format='json',
			)
		self.assertTrue(
			PasswordResetRequest.objects.filter(email=self.user.email).exists()
		)

		self.client.force_authenticate(self.user)
		# Password too similar to user's email/name must be rejected.
		weak_resp = self.client.patch(
			reverse('change-password'),
			{
				'old_password': 'StrongPassw0rd!',
				'new_password': 'alice@example.com!',
				'new_password2': 'alice@example.com!',
			},
			format='json',
		)
		self.assertEqual(weak_resp.status_code, 400)

		ok_resp = self.client.patch(
			reverse('change-password'),
			{
				'old_password': 'StrongPassw0rd!',
				'new_password': 'BrandNewUnique#99',
				'new_password2': 'BrandNewUnique#99',
			},
			format='json',
		)
		self.assertEqual(ok_resp.status_code, 200)
		self.assertFalse(
			PasswordResetRequest.objects.filter(email=self.user.email).exists()
		)

		self.client.force_authenticate(user=None)
		stale_reset = self.client.post(
			reverse('password-reset-confirm'),
			{
				'email': self.user.email,
				'code': '223456',
				'password': 'AttackerPassword!99',
				'password2': 'AttackerPassword!99',
			},
			format='json',
		)
		self.assertEqual(stale_reset.status_code, 400)

	def test_login_throttle_ignores_forged_xff_when_num_proxies_zero(self):
		login_url = reverse('login')
		for i in range(10):
			resp = self.client.post(
				login_url,
				{'email': self.user.email, 'password': 'WrongPassword!1'},
				format='json',
				HTTP_X_FORWARDED_FOR=f'203.0.113.{i + 1}',
			)
			self.assertEqual(resp.status_code, 401)
		throttled = self.client.post(
			login_url,
			{'email': self.user.email, 'password': 'WrongPassword!1'},
			format='json',
			HTTP_X_FORWARDED_FOR='203.0.113.99',
		)
		self.assertEqual(throttled.status_code, 429)

	def test_login_throttle_pins_rightmost_proxy_ip_when_num_proxies_one(self):
		login_url = reverse('login')
		with override_settings(REST_FRAMEWORK={**settings.REST_FRAMEWORK, 'NUM_PROXIES': 1}):
			for i in range(10):
				resp = self.client.post(
					login_url,
					{'email': self.user.email, 'password': 'WrongPassword!1'},
					format='json',
					HTTP_X_FORWARDED_FOR=f'198.51.100.{i + 1}, 192.0.2.50',
				)
				self.assertEqual(resp.status_code, 401)
			throttled = self.client.post(
				login_url,
				{'email': self.user.email, 'password': 'WrongPassword!1'},
				format='json',
				HTTP_X_FORWARDED_FOR='10.0.0.1, 198.51.100.250, 192.0.2.50',
			)
			self.assertEqual(throttled.status_code, 429)

			# A distinct rightmost client IP still has its own independent bucket.
			other_client = self.client.post(
				login_url,
				{'email': self.user.email, 'password': 'WrongPassword!1'},
				format='json',
				HTTP_X_FORWARDED_FOR='198.51.100.250, 192.0.2.99',
			)
			self.assertEqual(other_client.status_code, 401)

	def test_per_email_rate_limit_blocks_distributed_email_bombing(self):
		with patch('accounts.views.send_mail'):
			for i in range(5):
				resp = self.client.post(
					reverse('password-reset-request'),
					{'email': 'victim@example.com'},
					format='json',
					REMOTE_ADDR=f'10.0.0.{i + 1}',
				)
				self.assertEqual(resp.status_code, 200)
			blocked = self.client.post(
				reverse('password-reset-request'),
				{'email': 'victim@example.com'},
				format='json',
				REMOTE_ADDR='10.0.0.99',
			)
		self.assertEqual(blocked.status_code, 429)

	def test_security_headers_and_csp_on_responses(self):
		resp = self.client.get(reverse('profile'))
		csp = resp.headers.get('Content-Security-Policy', '')
		self.assertIn("default-src 'none'", csp)
		self.assertIn("frame-ancestors 'none'", csp)
		self.assertNotIn("'unsafe-inline'", csp)
		self.assertNotIn("'unsafe-eval'", csp)
		self.assertIn('https://accounts.google.com/gsi/client', csp)
		self.assertIn('https://accounts.google.com/gsi/style', csp)
		self.assertIn('https://accounts.google.com/gsi/', csp)
		self.assertEqual(resp.headers.get('X-Frame-Options'), 'DENY')
		self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')
		self.assertEqual(resp.headers.get('Referrer-Policy'), 'strict-origin-when-cross-origin')

	def test_deploy_check_warns_without_redis_in_production(self):
		with patch('config.settings.DEPLOYMENT_ENV', 'production'), patch(
			'config.settings.REDIS_URL', ''
		):
			warnings = check_shared_throttle_cache(None)
		self.assertEqual([w.id for w in warnings], ['iapply.W001'])

		with patch('config.settings.DEPLOYMENT_ENV', 'production'), patch(
			'config.settings.REDIS_URL', 'redis://localhost:6379/1'
		):
			issues = check_shared_throttle_cache(None)
		self.assertEqual([i.id for i in issues], ['iapply.E001'])

		with patch('config.settings.DEPLOYMENT_ENV', 'production'), patch(
			'config.settings.REDIS_URL', 'rediss://localhost:6379/1'
		):
			self.assertEqual(check_shared_throttle_cache(None), [])

	def test_all_protected_endpoints_fail_closed_503_on_cache_outage(self):
		failing_cache = MagicMock()
		failing_cache.get.side_effect = ConnectionError('redis unreachable')
		failing_cache.set.side_effect = ConnectionError('redis unreachable')
		failing_cache.add.side_effect = ConnectionError('redis unreachable')
		failing_cache.incr.side_effect = ConnectionError('redis unreachable')

		anon_calls = [
			('post', reverse('login'), {'email': self.user.email, 'password': 'WrongPassword!1'}),
			('post', reverse('register'), {
				'email': 'outage@example.com',
				'password': 'StrongPassw0rd!9',
				'password2': 'StrongPassw0rd!9',
				'first_name': 'Out',
				'last_name': 'Age',
			}),
			('post', reverse('register-verify'), {'email': 'outage@example.com', 'code': '123456'}),
			('post', reverse('password-reset-request'), {'email': self.user.email}),
			('post', reverse('password-reset-confirm'), {
				'email': self.user.email,
				'code': '123456',
				'password': 'NewStrongPassw0rd!9',
				'password2': 'NewStrongPassw0rd!9',
			}),
			('post', reverse('google-login'), {'credential': 'tok'}),
			('post', reverse('login-refresh'), {'refresh': 'tok'}),
		]
		authed_calls = [
			('patch', reverse('change-password'), {
				'old_password': 'StrongPassw0rd!',
				'new_password': 'AnotherStrongPass!9',
				'new_password2': 'AnotherStrongPass!9',
			}),
			('delete', reverse('delete-account'), {'password': 'StrongPassw0rd!'}),
			('get', reverse('application-list'), {}),
		]

		with patch('rest_framework.throttling.SimpleRateThrottle.cache', failing_cache), patch(
			'accounts.views.cache', failing_cache
		), patch('accounts.google_auth.cache', failing_cache):
			self.client.force_authenticate(user=None)
			for method, url, body in anon_calls:
				resp = getattr(self.client, method)(url, body, format='json')
				self.assertEqual(resp.status_code, 503, url)
				self.assertNotIn('redis unreachable', str(resp.data))

			self.client.force_authenticate(self.user)
			for method, url, body in authed_calls:
				resp = getattr(self.client, method)(url, body, format='json')
				self.assertEqual(resp.status_code, 503, url)
				self.assertNotIn('redis unreachable', str(resp.data))

	def test_email_rate_limit_fails_closed_503_on_cache_outage(self):
		failing_cache = MagicMock()
		failing_cache.add.side_effect = ConnectionError('email rl redis down')
		with patch('accounts.views.cache', failing_cache):
			resp = self.client.post(
				reverse('password-reset-request'),
				{'email': self.user.email},
				format='json',
			)
		self.assertEqual(resp.status_code, 503)
		self.assertNotIn('email rl redis down', str(resp.data))


@override_settings(GOOGLE_CLIENT_ID='test-client.apps.googleusercontent.com')
class GoogleSignInSecurityTests(APITestCase):
	def setUp(self):
		cache.clear()
		self.url = reverse('google-login')
		self.client_id = 'test-client.apps.googleusercontent.com'

	def tearDown(self):
		cache.clear()

	def _claims(self, **overrides):
		base = {
			'iss': 'https://accounts.google.com',
			'aud': self.client_id,
			'sub': 'google-sub-123',
			'email': 'googleuser@example.com',
			'email_verified': True,
			'given_name': 'Grace',
			'family_name': 'Hopper',
			'exp': int(timezone.now().timestamp()) + 600,
			'jti': 'jti-123',
		}
		base.update(overrides)
		return base

	def test_missing_credential_returns_400(self):
		resp = self.client.post(self.url, {}, format='json')
		self.assertEqual(resp.status_code, 400)

	def test_unconfigured_client_id_returns_503(self):
		with override_settings(GOOGLE_CLIENT_ID=''):
			resp = self.client.post(self.url, {'credential': 'tok'}, format='json')
		self.assertEqual(resp.status_code, 503)

	def test_invalid_or_expired_token_returns_generic_400(self):
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			side_effect=ValueError('Token expired'),
		):
			resp = self.client.post(self.url, {'credential': 'bad.jwt.token'}, format='json')
		self.assertEqual(resp.status_code, 400)
		self.assertEqual(
			resp.data,
			{'message': 'Could not verify that Google account. Please try again.'},
		)

	def test_google_auth_library_error_and_bad_issuer_return_400_not_500(self):
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			side_effect=google_exceptions.GoogleAuthError('Wrong issuer'),
		):
			resp1 = self.client.post(self.url, {'credential': 'tok1'}, format='json')
		self.assertEqual(resp1.status_code, 400)

		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(iss='https://evil.example.com'),
		):
			resp2 = self.client.post(self.url, {'credential': 'tok2'}, format='json')
		self.assertEqual(resp2.status_code, 400)

	def test_wrong_audience_returns_400(self):
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(aud='other-app.apps.googleusercontent.com'),
		):
			resp = self.client.post(self.url, {'credential': 'tok'}, format='json')
		self.assertEqual(resp.status_code, 400)

	def test_unverified_email_boolean_or_string_returns_400(self):
		for val in (False, 'true', None):
			with patch(
				'google.oauth2.id_token.verify_oauth2_token',
				return_value=self._claims(email_verified=val),
			):
				resp = self.client.post(self.url, {'credential': f'tok-{val}'}, format='json')
			self.assertEqual(resp.status_code, 400)

	def test_missing_sub_returns_400(self):
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(sub=''),
		):
			resp = self.client.post(self.url, {'credential': 'tok'}, format='json')
		self.assertEqual(resp.status_code, 400)

	def test_cert_transport_error_returns_503_not_500(self):
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			side_effect=google_exceptions.TransportError('Network unreachable'),
		):
			resp = self.client.post(self.url, {'credential': 'tok'}, format='json')
		self.assertEqual(resp.status_code, 503)

	def test_replayed_id_token_is_rejected(self):
		claims = self._claims(jti='unique-jti-replay')
		with patch('google.oauth2.id_token.verify_oauth2_token', return_value=claims):
			first = self.client.post(self.url, {'credential': 'same-jwt'}, format='json')
			second = self.client.post(self.url, {'credential': 'same-jwt'}, format='json')
		self.assertEqual(first.status_code, 200)
		self.assertEqual(second.status_code, 400)

	def test_creates_google_only_user_clears_pending_verification_and_issues_working_jwt(self):
		EmailVerification.objects.create(
			email='googleuser@example.com',
			code_hash='hash',
			password_hash='hash',
		)
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(),
		):
			resp = self.client.post(self.url, {'credential': 'valid-jwt'}, format='json')

		self.assertEqual(resp.status_code, 200)
		self.assertTrue(resp.data['created'])
		user = User.objects.get(email='googleuser@example.com')
		self.assertEqual(user.google_sub, 'google-sub-123')
		self.assertFalse(user.has_usable_password())
		self.assertFalse(
			EmailVerification.objects.filter(email='googleuser@example.com').exists()
		)

		self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")
		me = self.client.get(reverse('profile'))
		self.assertEqual(me.status_code, 200)
		self.assertIs(me.data['has_password'], False)

	def test_links_existing_password_user_safely_and_rejects_conflicting_sub(self):
		existing = User.objects.create_user(
			email='linked@example.com',
			password='StrongPassw0rd!',
			first_name='Ada',
		)
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(email='linked@example.com', sub='sub-ada-1', jti='jti-a'),
		):
			resp = self.client.post(self.url, {'credential': 'tok-a'}, format='json')
		self.assertEqual(resp.status_code, 200)
		self.assertFalse(resp.data['created'])
		existing.refresh_from_db()
		self.assertEqual(existing.google_sub, 'sub-ada-1')

		# Different Google sub claiming same email must be blocked.
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(email='linked@example.com', sub='sub-attacker-2', jti='jti-b'),
		):
			conflict = self.client.post(self.url, {'credential': 'tok-b'}, format='json')
		self.assertEqual(conflict.status_code, 400)
		existing.refresh_from_db()
		self.assertEqual(existing.google_sub, 'sub-ada-1')

	def test_google_login_matches_existing_account_regardless_of_case(self):
		existing = User.objects.create_user(
			email='case.match@example.com',
			password='StrongPassw0rd!',
			first_name='Grace',
		)
		User.objects.filter(pk=existing.pk).update(email='Case.Match@Example.COM')
		initial_count = User.objects.count()
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(
				email='  CASE.MATCH@example.com  ',
				sub='sub-case-match',
				jti='jti-case-match',
			),
		):
			resp = self.client.post(self.url, {'credential': 'tok-case'}, format='json')
		self.assertEqual(resp.status_code, 200)
		self.assertFalse(resp.data['created'])
		self.assertEqual(User.objects.count(), initial_count)
		existing.refresh_from_db()
		self.assertEqual(existing.google_sub, 'sub-case-match')

	def test_inactive_user_rejected_without_binding_sub(self):
		inactive = User.objects.create_user(
			email='disabled@example.com',
			password='StrongPassw0rd!',
			is_active=False,
		)
		with patch(
			'google.oauth2.id_token.verify_oauth2_token',
			return_value=self._claims(email='disabled@example.com', sub='sub-disabled', jti='jti-d'),
		):
			resp = self.client.post(self.url, {'credential': 'tok-d'}, format='json')
		self.assertEqual(resp.status_code, 400)
		inactive.refresh_from_db()
		self.assertIsNone(inactive.google_sub)

	def test_google_auth_uses_official_requests_transport_with_timeout(self):
		captured = {}

		def fake_verify(token, transport_request, audience):
			captured['transport_request'] = transport_request
			return self._claims(jti='jti-transport-check')

		with patch('google.oauth2.id_token.verify_oauth2_token', side_effect=fake_verify):
			resp = self.client.post(self.url, {'credential': 'tok-transport'}, format='json')

		self.assertEqual(resp.status_code, 200)
		req_callable = captured['transport_request']
		self.assertEqual(req_callable.keywords.get('timeout'), 10)
		self.assertEqual(
			type(req_callable.func).__module__,
			'google.auth.transport.requests',
		)

	def test_google_cert_fetch_timeout_maps_to_generic_503(self):
		with patch(
			'requests.Session.request',
			side_effect=requests.exceptions.Timeout('timed out'),
		):
			resp = self.client.post(self.url, {'credential': 'tok-timeout'}, format='json')
		self.assertEqual(resp.status_code, 503)
		self.assertEqual(resp.data, {'message': 'Google sign-in is not available right now.'})

	def test_transient_db_failure_does_not_burn_token_and_retry_succeeds(self):
		claims = self._claims(email='retry@example.com', sub='sub-retry', jti='jti-retry-1')
		with patch('google.oauth2.id_token.verify_oauth2_token', return_value=claims):
			with patch(
				'accounts.views.RefreshToken.for_user',
				side_effect=DatabaseError('transient db error'),
			):
				failed = self.client.post(self.url, {'credential': 'tok-retry'}, format='json')
			self.assertEqual(failed.status_code, 503)
			self.assertFalse(User.objects.filter(email='retry@example.com').exists())

			retried = self.client.post(self.url, {'credential': 'tok-retry'}, format='json')
		self.assertEqual(retried.status_code, 200)
		self.assertIn('access', retried.data)
		self.assertTrue(User.objects.filter(email='retry@example.com').exists())

	def test_inactive_user_failure_does_not_burn_token(self):
		user = User.objects.create_user(
			email='reactivate@example.com',
			password='StrongPassw0rd!',
			is_active=False,
		)
		claims = self._claims(
			email='reactivate@example.com',
			sub='sub-reactivate',
			jti='jti-reactivate-1',
		)
		with patch('google.oauth2.id_token.verify_oauth2_token', return_value=claims):
			first = self.client.post(self.url, {'credential': 'tok-reactivate'}, format='json')
			self.assertEqual(first.status_code, 400)

			user.is_active = True
			user.save(update_fields=['is_active'])

			second = self.client.post(self.url, {'credential': 'tok-reactivate'}, format='json')
		self.assertEqual(second.status_code, 200)
		self.assertIn('access', second.data)

	def test_replay_cache_outage_fails_closed_with_503_and_rolls_back(self):
		claims = self._claims(email='cachefail@example.com', sub='sub-cf', jti='jti-cf-1')
		with patch('google.oauth2.id_token.verify_oauth2_token', return_value=claims):
			failing_get_cache = MagicMock()
			failing_get_cache.get.side_effect = ConnectionError('redis down')
			with patch('accounts.google_auth.cache', failing_get_cache):
				resp_get = self.client.post(self.url, {'credential': 'tok-cf-1'}, format='json')
			self.assertEqual(resp_get.status_code, 503)

			failing_add_cache = MagicMock()
			failing_add_cache.get.return_value = None
			failing_add_cache.add.side_effect = ConnectionError('redis down')
			with patch('accounts.google_auth.cache', failing_add_cache):
				resp_add = self.client.post(self.url, {'credential': 'tok-cf-1'}, format='json')
			self.assertEqual(resp_add.status_code, 503)

		self.assertFalse(User.objects.filter(email='cachefail@example.com').exists())

	def test_replay_ttl_does_not_exceed_remaining_validity_and_rejects_expired(self):
		short_claims = self._claims(
			email='shortttl@example.com',
			sub='sub-short',
			jti='jti-short-ttl',
			exp=int(timezone.now().timestamp()) + 12,
		)
		with patch('google.oauth2.id_token.verify_oauth2_token', return_value=short_claims), patch(
			'accounts.google_auth.cache.add', wraps=cache.add
		) as mock_add:
			resp = self.client.post(self.url, {'credential': 'tok-short'}, format='json')
		self.assertEqual(resp.status_code, 200)
		mock_add.assert_called_once()
		timeout_used = mock_add.call_args.kwargs['timeout']
		self.assertGreaterEqual(timeout_used, 1)
		self.assertLessEqual(timeout_used, 12)

		expired_claims = self._claims(
			email='expired@example.com',
			sub='sub-exp',
			jti='jti-expired',
			exp=int(timezone.now().timestamp()),
		)
		with patch('google.oauth2.id_token.verify_oauth2_token', return_value=expired_claims):
			expired_resp = self.client.post(self.url, {'credential': 'tok-expired'}, format='json')
		self.assertEqual(expired_resp.status_code, 400)


class GoogleOnlyAccountDeletionTests(APITestCase):
	def setUp(self):
		cache.clear()
		self.google_user = User(email='google.del@example.com', google_sub='sub-del-1')
		self.google_user.set_unusable_password()
		self.google_user.save()

		self.other_google_user = User(email='other.del@example.com', google_sub='sub-del-2')
		self.other_google_user.set_unusable_password()
		self.other_google_user.save()

		self.password_user = User.objects.create_user(
			email='pw.del@example.com',
			password='StrongPassw0rd!',
		)
		self.request_url = reverse('delete-account-request')
		self.delete_url = reverse('delete-account')

	def tearDown(self):
		cache.clear()

	def _request_code(self, user, randbelow_val=123456):
		self.client.force_authenticate(user)
		with patch('accounts.views.secrets.randbelow', return_value=randbelow_val), patch(
			'accounts.views.send_mail'
		) as mock_mail:
			resp = self.client.post(self.request_url, {}, format='json')
		return resp, mock_mail, str(randbelow_val + 100000)

	def test_password_user_cannot_request_deletion_otp_and_still_requires_password(self):
		self.client.force_authenticate(self.password_user)
		req_resp = self.client.post(self.request_url, {}, format='json')
		self.assertEqual(req_resp.status_code, 400)

		bad_pw = self.client.delete(self.delete_url, {'password': 'WrongPassword!1'}, format='json')
		self.assertEqual(bad_pw.status_code, 401)
		self.assertTrue(User.objects.filter(pk=self.password_user.pk).exists())

		ok_pw = self.client.delete(self.delete_url, {'password': 'StrongPassw0rd!'}, format='json')
		self.assertEqual(ok_pw.status_code, 200)
		self.assertFalse(User.objects.filter(pk=self.password_user.pk).exists())

	def test_request_stores_hashed_otp_and_deletes_user_on_valid_code(self):
		deleted_pk = self.google_user.pk
		deleted_email = self.google_user.email
		refresh = RefreshToken.for_user(self.google_user)
		access_token = str(refresh.access_token)
		EmailVerification.objects.create(
			email=deleted_email, code_hash='h', password_hash='p'
		)
		PasswordResetRequest.objects.create(email=deleted_email, code_hash='h')

		req_resp, mock_mail, code = self._request_code(self.google_user, randbelow_val=234567)
		self.assertEqual(req_resp.status_code, 200)
		mock_mail.assert_called_once()
		self.assertEqual(mock_mail.call_args.kwargs['recipient_list'], [deleted_email])

		record = AccountDeletionRequest.objects.get(user=self.google_user)
		self.assertNotEqual(record.code_hash, code)

		# Missing or malformed code rejected cleanly without deleting account
		self.assertEqual(
			self.client.delete(self.delete_url, {}, format='json').status_code,
			400,
		)
		self.assertEqual(
			self.client.delete(self.delete_url, {'code': 'abcdef'}, format='json').status_code,
			400,
		)
		self.assertTrue(User.objects.filter(pk=deleted_pk).exists())

		# Valid code deletes user, revokes refresh tokens, and purges related OTP records
		del_resp = self.client.delete(self.delete_url, {'code': code}, format='json')
		self.assertEqual(del_resp.status_code, 200)
		self.assertFalse(User.objects.filter(pk=deleted_pk).exists())
		self.assertFalse(AccountDeletionRequest.objects.filter(user_id=deleted_pk).exists())
		self.assertFalse(EmailVerification.objects.filter(email=deleted_email).exists())
		self.assertFalse(PasswordResetRequest.objects.filter(email=deleted_email).exists())
		self.assertTrue(BlacklistedToken.objects.filter(token__token=str(refresh)).exists())

		# Reusing the deleted account's Bearer JWT + OTP code is rejected
		self.client.force_authenticate(user=None)
		reuse = self.client.delete(
			self.delete_url,
			{'code': code},
			format='json',
			HTTP_AUTHORIZATION=f'Bearer {access_token}',
		)
		self.assertEqual(reuse.status_code, 401)

	def test_five_wrong_codes_purge_deletion_request(self):
		req_resp, _, real_code = self._request_code(self.google_user, randbelow_val=111111)
		self.assertEqual(req_resp.status_code, 200)

		for _ in range(AccountDeletionRequest.MAX_ATTEMPTS):
			resp = self.client.delete(self.delete_url, {'code': '000000'}, format='json')
			self.assertEqual(resp.status_code, 400)

		self.assertFalse(AccountDeletionRequest.objects.filter(user=self.google_user).exists())
		late = self.client.delete(self.delete_url, {'code': real_code}, format='json')
		self.assertEqual(late.status_code, 400)
		self.assertTrue(User.objects.filter(pk=self.google_user.pk).exists())

	def test_expired_and_other_users_code_are_rejected(self):
		_, _, other_code = self._request_code(self.other_google_user, randbelow_val=555555)
		_, _, my_code = self._request_code(self.google_user, randbelow_val=666666)

		# Victim cannot be deleted with another user's valid code
		self.client.force_authenticate(self.google_user)
		cross = self.client.delete(self.delete_url, {'code': other_code}, format='json')
		self.assertEqual(cross.status_code, 400)
		self.assertTrue(User.objects.filter(pk=self.google_user.pk).exists())

		# Expire my_code beyond EXPIRY_MINUTES
		record = AccountDeletionRequest.objects.get(user=self.google_user)
		AccountDeletionRequest.objects.filter(pk=record.pk).update(
			created_at=timezone.now() - timedelta(minutes=AccountDeletionRequest.EXPIRY_MINUTES + 1)
		)
		expired = self.client.delete(self.delete_url, {'code': my_code}, format='json')
		self.assertEqual(expired.status_code, 400)
		self.assertFalse(AccountDeletionRequest.objects.filter(pk=record.pk).exists())
		self.assertTrue(User.objects.filter(pk=self.google_user.pk).exists())

	def test_deletion_request_and_confirm_rate_limits(self):
		self.client.force_authenticate(self.google_user)
		with patch('accounts.views.send_mail'):
			for _ in range(5):
				resp = self.client.post(self.request_url, {}, format='json')
				self.assertEqual(resp.status_code, 200)
			# 6th request hits per-email limit (5/hour)
			email_limited = self.client.post(self.request_url, {}, format='json')
			self.assertEqual(email_limited.status_code, 429)

		# Additional confirm attempts hit PasswordActionRateThrottle (10/hour per user across views)
		self.client.force_authenticate(self.other_google_user)
		for _ in range(10):
			resp = self.client.delete(self.delete_url, {'code': '000000'}, format='json')
			self.assertEqual(resp.status_code, 400)
		throttled = self.client.delete(self.delete_url, {'code': '000000'}, format='json')
		self.assertEqual(throttled.status_code, 429)

	def test_deletion_request_fails_closed_on_cache_outage(self):
		self.client.force_authenticate(self.google_user)
		failing_cache = MagicMock()
		failing_cache.get.side_effect = ConnectionError('redis down')
		failing_cache.add.side_effect = ConnectionError('redis down')
		with patch('rest_framework.throttling.SimpleRateThrottle.cache', failing_cache), patch(
			'accounts.views.cache', failing_cache
		):
			resp = self.client.post(self.request_url, {}, format='json')
		self.assertEqual(resp.status_code, 503)


class ProductionConfigAndHealthTests(APITestCase):
	def test_healthz_returns_ok_unauthenticated_with_security_headers(self):
		resp = self.client.get(reverse('healthz'))
		self.assertEqual(resp.status_code, 200)
		self.assertEqual(resp.json(), {'status': 'ok'})
		self.assertEqual(resp.headers.get('X-Frame-Options'), 'DENY')
		self.assertEqual(resp.headers.get('X-Content-Type-Options'), 'nosniff')
		self.assertIn("object-src 'none'", resp.headers.get('Content-Security-Policy', ''))

	def test_readyz_reports_ready_or_503_without_leaking_internals(self):
		ok = self.client.get(reverse('readyz'))
		self.assertEqual(ok.status_code, 200)
		self.assertEqual(ok.json(), {'status': 'ready'})

		with patch('config.health.connection.cursor', side_effect=RuntimeError('pg auth failed secret')):
			db_down = self.client.get(reverse('readyz'))
		self.assertEqual(db_down.status_code, 503)
		self.assertEqual(db_down.json(), {'status': 'unavailable'})
		self.assertNotIn('pg auth failed secret', db_down.content.decode('utf-8'))

		with override_settings(REDIS_URL='rediss://localhost:6379/1'), patch(
			'config.health.cache.get', side_effect=ConnectionError('redis secret host down')
		):
			cache_down = self.client.get(reverse('readyz'))
		self.assertEqual(cache_down.status_code, 503)
		self.assertEqual(cache_down.json(), {'status': 'unavailable'})
		self.assertNotIn('redis secret host down', cache_down.content.decode('utf-8'))

	def test_oversized_json_request_body_rejected(self):
		with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=128):
			resp = self.client.post(
				reverse('login'),
				{'email': 'a' * 300 + '@example.com', 'password': 'x'},
				format='json',
			)
		self.assertIn(resp.status_code, (400, 413))

	def test_json_log_formatter_outputs_single_line_structured_json(self):
		from config.logging_utils import JsonFormatter

		formatter = JsonFormatter()
		record = logging.LogRecord(
			name='accounts.tests',
			level=logging.INFO,
			pathname=__file__,
			lineno=1,
			msg='Login failed for %s',
			args=('user_redacted',),
			exc_info=None,
		)
		rendered = formatter.format(record)
		parsed = json.loads(rendered)
		self.assertEqual(parsed['level'], 'INFO')
		self.assertEqual(parsed['logger'], 'accounts.tests')
		self.assertEqual(parsed['message'], 'Login failed for user_redacted')
		self.assertIn('timestamp', parsed)


class EmailNormalizationAuditCommandTests(TestCase):
	def test_clean_users_pass_with_counts_only(self):
		from io import StringIO
		from django.core.management import call_command

		User.objects.create_user(email='clean@example.com', password='Password123!')
		out = StringIO()
		call_command('check_email_normalization', stdout=out)
		output = out.getvalue()
		self.assertIn('total_users=1', output)
		self.assertIn('mixed_case_or_untrimmed_users=0', output)
		self.assertIn('case_insensitive_duplicate_groups=0', output)
		self.assertIn('users_in_duplicate_groups=0', output)
		self.assertNotIn('clean@example.com', output)

	def test_mixed_case_row_reported_without_email_leak(self):
		from io import StringIO
		from django.core.management import call_command

		user = User.objects.create_user(email='mixed@example.com', password='Password123!')
		User.objects.filter(pk=user.pk).update(email='MixedCase@Example.COM')

		out = StringIO()
		call_command('check_email_normalization', stdout=out)
		output = out.getvalue()
		self.assertIn('total_users=1', output)
		self.assertIn('mixed_case_or_untrimmed_users=1', output)
		self.assertIn('case_insensitive_duplicate_groups=0', output)
		self.assertNotIn('MixedCase@Example.COM', output)
		self.assertNotIn('mixedcase@example.com', output)

	def test_case_insensitive_duplicate_emails_raise_command_error(self):
		from io import StringIO
		from django.core.management import call_command
		from django.core.management.base import CommandError

		u1 = User.objects.create_user(email='dup1@example.com', password='Password123!')
		u2 = User.objects.create_user(email='dup2@example.com', password='Password123!')
		User.objects.filter(pk=u1.pk).update(email='DupUser@Example.COM')
		User.objects.filter(pk=u2.pk).update(email='dupuser@example.com')

		out = StringIO()
		with self.assertRaises(CommandError) as ctx:
			call_command('check_email_normalization', stdout=out)
		output = out.getvalue()
		self.assertIn('case_insensitive_duplicate_groups=1', output)
		self.assertIn('users_in_duplicate_groups=2', output)
		self.assertNotIn('DupUser@Example.COM', output)
		self.assertNotIn('dupuser@example.com', output)
		self.assertNotIn('DupUser', str(ctx.exception))
		self.assertNotIn('dupuser', str(ctx.exception).lower())
