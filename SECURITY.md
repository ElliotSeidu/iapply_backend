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

Set `DEPLOYMENT_ENV=production`, `DEBUG=False`, HTTPS-only settings, a real email backend, and `CSP_REPORT_ONLY=False`. The settings module rejects production configurations that use SQLite, non-TLS PostgreSQL, non-delivery email backends, insecure redirects, short `SECRET_KEY` values (< 50 chars), or report-only CSP.

### Database configuration (`DB_*` variables; `DATABASE_URL` is unused)

`config/settings.py` does **not** use `dj-database-url` and does **not** read `DATABASE_URL`. Configure the database explicitly via environment variables:

- **Development (default)**: `DB_ENGINE=sqlite3` (no other database variables required; writes to `db.sqlite3`).
- **Production (PostgreSQL, required when `DEPLOYMENT_ENV=production`)**: set `DB_ENGINE=postgres`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` (defaults to `5432`), and `DB_SSLMODE` (defaults to `require` in `production` / `prefer` otherwise; must be `require`, `verify-ca`, or `verify-full` in `production`).

Set `REDIS_URL` in multi-worker production deployments (e.g. Gunicorn with multiple workers) so DRF throttles, per-email rate limits, and Google ID-token replay caches are shared across workers rather than isolated per worker. Without `REDIS_URL`, Django falls back to `LocMemCache`, which is per-process — Google ID-token replay protection is NOT reliable across multiple workers unless `REDIS_URL` is configured.

Google ID-token replay checking and marking **fail closed** (returning HTTP 503) if the cache backend raises an error, so a cache outage never silently disables replay protection or triggers an unhandled 500 error.

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
