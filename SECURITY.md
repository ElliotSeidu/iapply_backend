# Security deployment requirements

## Secrets

- Never commit `.env`, API keys, SMTP passwords, signing keys, certificates, or database files.
- Set `SECRET_KEY` and all provider credentials through the deployment secret manager. Use a new random `SECRET_KEY` per environment and rotate it after any suspected exposure.
- The application does not print secret values. Keep production logs and CI artifacts private.

## Data protection

- User passwords and email-verification codes are one-way hashed, not encrypted or recoverable.
- Production user data must live in PostgreSQL with the provider's encryption-at-rest feature enabled, encrypted backups, restricted network access, and least-privilege database credentials. Local SQLite is for development only and is ignored by Git.
- Database TLS is required when `DEPLOYMENT_ENV=production`; use `verify-full` with a trusted CA where the hosting provider supports it.
- Do not add plaintext credentials or third-party API keys to model fields, fixtures, tests, or source code. Store external service credentials in the deployment secret manager and retrieve them through environment injection.

## Production configuration

Set `DEPLOYMENT_ENV=production`, `DEBUG=False`, HTTPS-only settings, a real email backend, and `CSP_REPORT_ONLY=False`. The settings module rejects production configurations that use SQLite, non-TLS PostgreSQL, non-delivery or non-TLS email backends, insecure redirects, wildcard `ALLOWED_HOSTS`/`CORS_ALLOWED_ORIGINS`/`CSRF_TRUSTED_ORIGINS`, short `SECRET_KEY` values (< 50 chars), missing/non-TLS `REDIS_URL`, or report-only CSP.

### Origin, HSTS, Request Limits & Static Files

- **Hosts & CORS/CSRF:** `ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`, and `CSRF_TRUSTED_ORIGINS` forbid wildcards in production (`CORS` and `CSRF` require exact `https://` origins; cookies are not used for API auth and `CORS_ALLOW_CREDENTIALS = False`).
- **HSTS preload:** `SECURE_HSTS_SECONDS` defaults to `31536000` (1 year), `SECURE_HSTS_INCLUDE_SUBDOMAINS=True`, and `SECURE_HSTS_PRELOAD=True` (yielding zero `manage.py check --deploy` warnings). Override `SECURE_HSTS_SECONDS=300` and `SECURE_HSTS_PRELOAD=False` during initial staging rollout until HTTPS is confirmed across the apex domain and every subdomain before submitting to `hstspreload.org`.
- **Headers & CSP:** `config/middleware.py` sets `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `Cross-Origin-Opener-Policy: same-origin-allow-popups` (for Google Identity Services popups), and strict CSP with no `'unsafe-inline'` or `'unsafe-eval'` on API routes (`'unsafe-inline'` in `style-src` is permitted only on Django Admin HTML templates).
- **Body & upload limits:** `DATA_UPLOAD_MAX_MEMORY_SIZE` and `FILE_UPLOAD_MAX_MEMORY_SIZE` default to `262144` bytes (256 KiB); `DATA_UPLOAD_MAX_NUMBER_FIELDS = 100`.
- **Static files & Admin:** Static assets (if exposing Django Admin) are served via WhiteNoise (`CompressedManifestStaticFilesStorage`). Override `ADMIN_URL` with an unpredictable path and restrict access at the reverse proxy/VPN with an IP allowlist and admin MFA/2FA.

### Logging, Error Tracking & Health Probes

- **Structured logs:** When `DEBUG=False`, logs emit single-line JSON via `config/logging_utils.py`. Never log passwords, JWTs, OTP codes, full email addresses, or raw request payloads. A commented Sentry SDK hook point lives in `config/settings.py` (with `send_default_pii=False`) for optional adoption.
- **Health endpoints:** `GET /healthz` returns `{"status":"ok"}` (200, unauthenticated process check) and `GET /readyz` verifies DB and configured Redis connectivity (`{"status":"ready"}` 200 or `{"status":"unavailable"}` 503 with no internal details).
- **Email authentication:** Production SMTP requires `EMAIL_USE_TLS=True` or `EMAIL_USE_SSL=True` and `EMAIL_TIMEOUT=10`. Configure DNS **SPF**, **DKIM**, and **DMARC** records for the sending domain before sending OTP emails in production.

### Database configuration (`DB_*` variables; `DATABASE_URL` is unused)

`config/settings.py` does **not** use `dj-database-url` and does **not** read `DATABASE_URL`. Configure the database explicitly via environment variables:

- **Development (default)**: `DB_ENGINE=sqlite3` (no other database variables required; writes to `db.sqlite3`).
- **Production (PostgreSQL, required when `DEPLOYMENT_ENV=production`)**: set `DB_ENGINE=postgres`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` (defaults to `5432`), and `DB_SSLMODE` (defaults to `require` in `production` / `prefer` otherwise; must be `require`, `verify-ca`, or `verify-full` in `production`).

Set `REDIS_URL` using TLS (`rediss://...`) in production; `config/settings.py` rejects `DEPLOYMENT_ENV=production` startups when `REDIS_URL` is missing or uses plaintext `redis://`. Socket connect and read timeouts default to `3` seconds (`REDIS_SOCKET_CONNECT_TIMEOUT`, `REDIS_SOCKET_TIMEOUT`). Without `REDIS_URL` (development/staging only), Django falls back to per-process `LocMemCache`.

All security-critical cache consumers **fail closed** (HTTP 503 with a generic message, never unhandled HTTP 500 or silent bypass) if Redis is unreachable:

- Global and scoped DRF throttles (`FailClosedAnonRateThrottle`, `FailClosedUserRateThrottle`)
- Per-email registration / password-reset rate limits (`_consume_email_rate_limit`)
- Google ID-token replay check and single-use burn (`verify_google_id_token`, `mark_google_id_token_used`)

Set `NUM_PROXIES` and `TRUST_PROXY_SSL_HEADER` to match your reverse-proxy topology, and override `ADMIN_URL` if exposing Django Admin.

### Reverse proxy and client IP throttling (`NUM_PROXIES`)

DRF per-IP rate limiting derives the client IP using `REST_FRAMEWORK['NUM_PROXIES']` (configured in `config/settings.py` as `1 if not DEBUG else 0` when `NUM_PROXIES` is unset):

- **Development (`DEBUG=True`)**: defaults to `0` (`X-Forwarded-For` is ignored; `REMOTE_ADDR` is used). Local test runs also evaluate `NUM_PROXIES` at settings import time from `.env` (`0` when `.env` sets `DEBUG=True`, `1` when `DEBUG=False`).
- **Production (`DEBUG=False`)**: defaults to `1` (trusts only the single rightmost `X-Forwarded-For` hop appended by one reverse proxy).
- **Choosing the exact value for your host**: set `NUM_PROXIES` to the exact number of trusted proxies/load balancers/CDNs between the browser and Django that append client IPs to `X-Forwarded-For` (commonly `1` behind a platform router/nginx/Cloud Run, `2` behind CDN + load balancer, `0` if Django accepts direct traffic).
  - **Too low** (e.g. `0` behind a proxy, or `1` behind 2 proxies): all traffic shares the proxy's IP throttle bucket, causing unrelated users to throttle one another.
  - **Too high** (e.g. `1` with no proxy, or `2` behind only 1 proxy): attackers can forge leftmost `X-Forwarded-For` values to evade per-IP login and OTP throttles.

Before publishing, run:

```text
python manage.py check --deploy
python manage.py makemigrations --check --dry-run
python manage.py test
```
