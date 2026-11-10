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

import logging

from django.conf import settings

logger = logging.getLogger(__name__)


class GoogleAuthError(Exception):
    """Raised when a Google ID token cannot be trusted."""


def get_google_client_id():
    """The OAuth 2.0 *Web* client ID this backend accepts ID tokens for."""
    return (getattr(settings, 'GOOGLE_CLIENT_ID', '') or '').strip()


def verify_google_id_token(id_token):
    """
    Verify a Google ID token and return the safe subset of its claims.

    Raises GoogleAuthError (never a library-specific exception) so callers can
    map every failure to a single generic client-facing message.
    """
    client_id = get_google_client_id()
    if not client_id:
        # Misconfiguration, not a bad user token — surfaced as 503 by the view.
        raise GoogleAuthError('GOOGLE_CLIENT_ID is not configured on the server.')

    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token
    except ImportError as exc:  # pragma: no cover - depends on install
        raise GoogleAuthError(
            'Server is missing the google-auth dependency.'
        ) from exc

    try:
        # verify_oauth2_token checks, in order: JWT signature against Google's
        # rotating public keys, `aud` == our client_id, `iss` in
        # {accounts.google.com, https://accounts.google.com}, and `exp`/`iat`.
        claims = google_id_token.verify_oauth2_token(
            id_token,
            google_requests.Request(),
            client_id,
        )
    except ValueError as exc:
        # google-auth raises ValueError for every verification failure.
        # Log the reason server-side, return nothing specific to the client.
        logger.warning('Google ID token verification failed: %s', exc)
        raise GoogleAuthError('Invalid Google credential.') from exc

    email = (claims.get('email') or '').strip().lower()
    if not email:
        raise GoogleAuthError('Google account did not provide an email address.')

    # Google only sets this for addresses it has actually verified. Without it we
    # would be trusting an unverified address, which would let someone claim an
    # account they do not own.
    if not claims.get('email_verified'):
        raise GoogleAuthError('Google account email address is not verified.')

    return {
        'email': email,
        'email_verified': True,
        'first_name': (claims.get('given_name') or '').strip(),
        'last_name': (claims.get('family_name') or '').strip(),
        'full_name': (claims.get('name') or '').strip(),
        'google_sub': claims.get('sub') or '',
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
