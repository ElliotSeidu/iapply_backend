"""
Google Sign-In (Google Identity Services) verification helper.

Flow
----
1. The browser renders Google's official button (Google Identity Services) and
   obtains an *ID token* (a signed JWT) after the user consents.
2. The browser POSTs that ID token to `/account/google/`.
3. The server verifies the token's signature, issuer, audience and expiry —
   directly against Google's public keys — before trusting a single claim.

We deliberately do NOT accept the user's email/name from the request body: the
only trusted source of identity is the signature-verified token. That is what
makes this safe against a client that simply posts `{"email": "ceo@company.com"}`.
"""

import functools
import hashlib
import logging
import time

from django.conf import settings
from django.core.cache import cache
from google.auth import exceptions as google_exceptions

logger = logging.getLogger(__name__)

_GOOGLE_ISSUERS = frozenset({'accounts.google.com', 'https://accounts.google.com'})
_GOOGLE_CERT_FETCH_TIMEOUT_SECONDS = 10


class GoogleAuthError(Exception):
    """Raised when a Google ID token cannot be trusted."""


class GoogleAuthServiceError(GoogleAuthError):
    """Raised when Google Sign-In is unconfigured or Google's certs cannot be reached."""


def get_google_client_id():
    """The OAuth 2.0 *Web* client ID this backend accepts ID tokens for."""
    return (getattr(settings, 'GOOGLE_CLIENT_ID', '') or '').strip()


def verify_google_id_token(id_token):
    """
    Verify a Google ID token and return the safe subset of its claims.

    Raises GoogleAuthServiceError for server/upstream availability errors and
    GoogleAuthError for invalid, unverified, or replayed credentials so callers
    can map every credential failure to a single generic client-facing message.
    """
    client_id = get_google_client_id()
    if not client_id:
        # Misconfiguration, not a bad user token — surfaced as 503 by the view.
        raise GoogleAuthServiceError('GOOGLE_CLIENT_ID is not configured on the server.')

    try:
        import requests
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:  # pragma: no cover - depends on install
        raise GoogleAuthServiceError(
            'Server is missing the google-auth or requests dependency.'
        ) from exc

    try:
        # verify_oauth2_token checks, in order: JWT signature against Google's
        # rotating public keys, `aud` == our client_id, `iss` in
        # {accounts.google.com, https://accounts.google.com}, and `exp`/`iat`.
        # _fetch_certs() calls request(certs_url, method="GET") without a
        # timeout argument, so bind the timeout on Google's requests transport.
        with requests.Session() as session:
            transport_request = functools.partial(
                google_requests.Request(session=session),
                timeout=_GOOGLE_CERT_FETCH_TIMEOUT_SECONDS,
            )
            claims = google_id_token.verify_oauth2_token(
                id_token,
                transport_request,
                client_id,
            )
    except google_exceptions.TransportError as exc:
        logger.warning('Google cert fetch failed during ID token verification: %s', exc)
        raise GoogleAuthServiceError('Could not reach Google to verify credential.') from exc
    except (ValueError, KeyError, google_exceptions.GoogleAuthError) as exc:
        # Log only the failure reason server-side (never the raw token).
        logger.warning('Google ID token verification failed: %s', exc)
        raise GoogleAuthError('Invalid Google credential.') from exc

    if claims.get('iss') not in _GOOGLE_ISSUERS:
        raise GoogleAuthError('Invalid Google token issuer.')

    if claims.get('aud') != client_id:
        raise GoogleAuthError('Invalid Google token audience.')

    # Google only sets boolean True for addresses it has actually verified.
    if claims.get('email_verified') is not True:
        raise GoogleAuthError('Google account email address is not verified.')

    google_sub = (claims.get('sub') or '').strip()
    if not google_sub:
        raise GoogleAuthError('Google account did not provide a subject identifier.')

    email = (claims.get('email') or '').strip().lower()
    if not email:
        raise GoogleAuthError('Google account did not provide an email address.')

    # Check replay cache after verifying signature/claims (without burning yet;
    # the view marks the token consumed only once login/issuance succeeds).
    # Note: LocMemCache is per-process, so replay protection is only reliable
    # across multiple Gunicorn workers when REDIS_URL is configured.
    replay_seed = str(claims.get('jti') or id_token)
    digest = hashlib.sha256(replay_seed.encode('utf-8')).hexdigest()
    replay_key = f'google_id_token_used:{digest}'
    exp = claims.get('exp')
    if isinstance(exp, (int, float)):
        remaining = int(exp - time.time())
        if remaining <= 0:
            raise GoogleAuthError('Google credential has expired.')
        replay_ttl = min(3600, remaining)
    else:
        replay_ttl = 3600

    try:
        already_used = cache.get(replay_key)
    except Exception as exc:
        # Fail closed on cache outages so a Redis failure never silently bypasses replay checks.
        logger.error('Google replay cache lookup failed: %s', exc)
        raise GoogleAuthServiceError('Replay protection cache is unavailable.') from exc

    if already_used:
        raise GoogleAuthError('Google credential has already been used.')

    return {
        'email': email,
        'email_verified': True,
        'first_name': (claims.get('given_name') or '').strip(),
        'last_name': (claims.get('family_name') or '').strip(),
        'full_name': (claims.get('name') or '').strip(),
        'google_sub': google_sub,
        'picture': claims.get('picture') or '',
        'replay_key': replay_key,
        'replay_ttl': replay_ttl,
    }


def mark_google_id_token_used(replay_key, ttl):
    """Mark a verified Google ID token's replay key as consumed.

    Called only after user lookup/creation and JWT issuance succeed so a
    failed login attempt does not burn a valid credential. Fails closed (503)
    if the cache backend raises an error. Cross-worker enforcement requires a
    shared cache (REDIS_URL).
    """
    try:
        added = cache.add(replay_key, 1, timeout=ttl)
    except Exception as exc:
        logger.error('Google replay cache write failed: %s', exc)
        raise GoogleAuthServiceError('Replay protection cache is unavailable.') from exc

    if not added:
        raise GoogleAuthError('Google credential has already been used.')


def split_google_name(info):
    """
    Best-effort first/last name from Google claims.

    Google sometimes omits given_name/family_name (or they are blank for
    non-Latin scripts), so fall back to splitting the display name.
    """
    first = info.get('first_name') or ''
    last = info.get('last_name') or ''
    if first or last:
        return first, last

    full = info.get('full_name') or ''
    if not full:
        return '', ''
    parts = full.split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else '')
