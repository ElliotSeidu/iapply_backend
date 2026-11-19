"""
Custom per-endpoint throttle classes.

Why not just rely on the global anon/user throttles in settings?
  - Auth endpoints are unauthenticated, so they share the global `anon` bucket
    (60/hour) across ALL anonymous users. That means a single attacker reaching
    the limit would block every genuine visitor.
  - These scoped throttles give each IP address its own independent bucket, at
    much stricter rates, for the endpoints that matter most for credential abuse.
"""

import logging

from django.core.exceptions import ImproperlyConfigured
from rest_framework.exceptions import APIException
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

logger = logging.getLogger(__name__)


class CacheUnavailableError(APIException):
    status_code = 503
    default_detail = {
        'message': 'Service temporarily unavailable. Please try again shortly.'
    }
    default_code = 'service_unavailable'


class _FailClosedThrottleMixin:
    """Fail closed with HTTP 503 if the throttle cache backend raises an error."""

    def allow_request(self, request, view):
        try:
            return super().allow_request(request, view)
        except ImproperlyConfigured:
            raise
        except Exception as exc:
            logger.error(
                "Throttle cache unavailable for scope '%s': %s",
                getattr(self, 'scope', 'unknown'),
                exc,
            )
            raise CacheUnavailableError() from exc


class FailClosedAnonRateThrottle(_FailClosedThrottleMixin, AnonRateThrottle):
    """Global anonymous throttle that fails closed (503) on cache outages."""


class FailClosedUserRateThrottle(_FailClosedThrottleMixin, UserRateThrottle):
    """Global user throttle that fails closed (503) on cache outages."""


class LoginRateThrottle(FailClosedAnonRateThrottle):
    """
    10 login attempts per IP per hour.
    Mitigates password-spray / credential-stuffing attacks on the login endpoint.
    """
    scope = 'login'


class RegisterRateThrottle(FailClosedAnonRateThrottle):
    """
    5 registration requests per IP per hour.
    Slows down bulk account-creation abuse and verification-email spam.
    """
    scope = 'register'


class VerifyRateThrottle(FailClosedAnonRateThrottle):
    """
    10 verification attempts per IP per hour.
    A 6-digit OTP has 10^6 combinations; at 10/hour that would take 11+ years
    to brute-force — and the per-record attempt limit (5 tries → delete) kicks
    in long before that.
    """
    scope = 'verify'


class PasswordResetRateThrottle(FailClosedAnonRateThrottle):
    """5 password-reset requests per IP per hour."""
    scope = 'password_reset'


class GoogleLoginRateThrottle(FailClosedAnonRateThrottle):
    """
    10 Google sign-in attempts per IP per hour.

    Each attempt forces a network round-trip to Google's public-key endpoint, so
    this also stops the endpoint being used as an outbound-request amplifier.
    """
    scope = 'google_login'


class RefreshRateThrottle(FailClosedAnonRateThrottle):
    """30 token refresh attempts per IP per hour."""
    scope = 'token_refresh'


class PasswordActionRateThrottle(FailClosedUserRateThrottle):
    """10 sensitive password/account-deletion attempts per user per hour."""
    scope = 'password_action'
