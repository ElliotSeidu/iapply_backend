from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken

from .models import EmailVerification, User


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
