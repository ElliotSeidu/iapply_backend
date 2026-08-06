from django.test import TestCase
from django.urls import reverse
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
		resp = self.client.post(req_url, data=payload, content_type='application/json')
		self.assertEqual(resp.status_code, 200)
		record = EmailVerification.objects.filter(email='verifyme@example.com').first()
		self.assertIsNotNone(record)
		# call verify endpoint
		verify_url = reverse('register-verify')
		verify_resp = self.client.post(verify_url, data={'email': 'verifyme@example.com', 'code': record.code}, content_type='application/json')
		self.assertEqual(verify_resp.status_code, 201)
		# user should exist and record deleted
		self.assertTrue(User.objects.filter(email='verifyme@example.com').exists())
		self.assertFalse(EmailVerification.objects.filter(email='verifyme@example.com').exists())
