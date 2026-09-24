"""
Custom per-endpoint throttle classes.

Why not just rely on the global anon/user throttles in settings?
  - Auth endpoints are unauthenticated, so they share the global `anon` bucket
    (30/hour) across ALL anonymous users. That means a single attacker reaching
    the limit would block every genuine visitor.
  - These scoped throttles give each IP address its own independent bucket, at
    much stricter rates, for the endpoints that matter most for credential abuse.
"""

from rest_framework.throttling import AnonRateThrottle


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
