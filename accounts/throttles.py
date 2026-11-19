"""
Custom per-endpoint throttle classes.

Why not just rely on the global anon/user throttles in settings?
  - Auth endpoints are unauthenticated, so they share the global `anon` bucket
    (60/hour) across ALL anonymous users. That means a single attacker reaching
    the limit would block every genuine visitor.
  - These scoped throttles give each IP address its own independent bucket, at
    much stricter rates, for the endpoints that matter most for credential abuse.
"""

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle


class LoginRateThrottle(AnonRateThrottle):
    """
    10 login attempts per IP per hour.
    Mitigates password-spray / credential-stuffing attacks on the login endpoint.
    """
    scope = 'login'


class RegisterRateThrottle(AnonRateThrottle):
    """
    5 registration requests per IP per hour.
    Slows down bulk account-creation abuse and verification-email spam.
    """
    scope = 'register'


class VerifyRateThrottle(AnonRateThrottle):
    """
    10 verification attempts per IP per hour.
    A 6-digit OTP has 10^6 combinations; at 10/hour that would take 11+ years
    to brute-force — and the per-record attempt limit (5 tries → delete) kicks
    in long before that.
    """
    scope = 'verify'


class PasswordResetRateThrottle(AnonRateThrottle):
    """5 password-reset requests per IP per hour."""
    scope = 'password_reset'


class GoogleLoginRateThrottle(AnonRateThrottle):
    """
    10 Google sign-in attempts per IP per hour.

    Each attempt forces a network round-trip to Google's public-key endpoint, so
    this also stops the endpoint being used as an outbound-request amplifier.
    """
    scope = 'google_login'


class RefreshRateThrottle(AnonRateThrottle):
    """30 token refresh attempts per IP per hour."""
    scope = 'token_refresh'


class PasswordActionRateThrottle(UserRateThrottle):
    """10 sensitive password/account-deletion attempts per user per hour."""
    scope = 'password_action'
