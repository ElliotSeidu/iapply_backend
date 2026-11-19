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

import hashlib
import http.client
import logging
import ssl
import time
import urllib.error
import urllib.request

from django.conf import settings
from django.core.cache import cache
from google.auth import exceptions as google_exceptions
from google.auth import transport as google_transport

logger = logging.getLogger(__name__)

_GOOGLE_ISSUERS = frozenset({'accounts.google.com', 'https://accounts.google.com'})


class _StdlibHttpsResponse(google_transport.Response):
    """Minimal google.auth.transport.Response backed by Python stdlib."""

    def __init__(self, status, headers, data):
        self._status = status
        self._headers = {k.lower(): v for k, v in headers.items()}
        self._data = data

    @property
    def status(self):
        return self._status

    @property
    def headers(self):
        return self._headers

    @property
    def data(self):
        return self._data


class _StdlibHttpsRequest(google_transport.Request):
    """HTTPS-only google.auth.transport.Request using Python's stdlib urllib/ssl.

    Avoids requiring `requests` when `google-auth` is installed without extras,
    enforces HTTPS and certificate verification, and bounds outbound fetches.
    """

    def __init__(self, default_timeout=10):
        self._default_timeout = default_timeout
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ssl.create_default_context())
        )

    def __call__(self, url, method="GET", body=None, headers=None, timeout=None, **kwargs):
        if not isinstance(url, str) or not url.startswith("https://"):
            raise google_exceptions.TransportError("Only HTTPS URLs are permitted.")
        req = urllib.request.Request(
            url,
            data=body,
            headers=dict(headers or {}),
            method=method,
        )
        effective_timeout = self._default_timeout if timeout is None else timeout
        try:
            with self._opener.open(req, timeout=effective_timeout) as resp:
                return _StdlibHttpsResponse(resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as err:
            return _StdlibHttpsResponse(err.code, dict(err.headers or {}), err.read())
        except (urllib.error.URLError, http.client.HTTPException, OSError) as exc:
            raise google_exceptions.TransportError(exc) from exc


def _build_transport_request():
    """Prefer google.auth.transport.requests when available; fall back to stdlib HTTPS."""
    try:
        from google.auth.transport import requests as google_requests
        return google_requests.Request()
    except ImportError:
        return _StdlibHttpsRequest()


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
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:  # pragma: no cover - depends on install
        raise GoogleAuthServiceError(
            'Server is missing the google-auth dependency.'
        ) from exc

    try:
        # verify_oauth2_token checks, in order: JWT signature against Google's
        # rotating public keys, `aud` == our client_id, `iss` in
        # {accounts.google.com, https://accounts.google.com}, and `exp`/`iat`.
        claims = google_id_token.verify_oauth2_token(
            id_token,
            _build_transport_request(),
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

    # Enforce single-use replay protection only after signature and claims validate.
    replay_seed = str(claims.get('jti') or id_token)
    digest = hashlib.sha256(replay_seed.encode('utf-8')).hexdigest()
    exp = claims.get('exp')
    if isinstance(exp, (int, float)):
        ttl = max(60, min(3600, int(exp - time.time())))
    else:
        ttl = 3600
    if not cache.add(f'google_id_token_used:{digest}', 1, timeout=ttl):
        raise GoogleAuthError('Google credential has already been used.')

    return {
        'email': email,
        'email_verified': True,
        'first_name': (claims.get('given_name') or '').strip(),
        'last_name': (claims.get('family_name') or '').strip(),
        'full_name': (claims.get('name') or '').strip(),
        'google_sub': google_sub,
        'picture': claims.get('picture') or '',
    }


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
