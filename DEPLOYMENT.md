# iApply Backend Deployment & Migration Guide

## Pre-Deploy Database Checklist

1. **Back up the PostgreSQL database before every release:**

   ```bash
   PGSSLMODE=verify-full pg_dump --format=custom --no-owner --no-acl -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" > "iapply_predeploy_$(date -u +%Y%m%dT%H%M%SZ).dump"
   ```

2. **Audit existing `User.email` rows (run against a staging copy or maintenance snapshot first):**

   ```bash
   python manage.py check_email_normalization
   ```

   This command prints only aggregate row counts (`total_users`, `mixed_case_or_untrimmed_users`, `case_insensitive_duplicate_groups`, `users_in_duplicate_groups`) and exits non-zero if any case-insensitive duplicate emails exist. Resolve duplicate accounts manually before running migrations (otherwise `accounts/migrations/0009_lowercase_user_emails.py` will refuse to run and raise `RuntimeError`).

3. **Inspect the pending migration plan:**

   ```bash
   python manage.py showmigrations
   python manage.py migrate --plan
   ```

4. **Apply migrations (before or during coordinated rollout; verify compatibility):**

   ```bash
   python manage.py migrate --noinput
   python manage.py makemigrations --check --dry-run
   ```

## Recent Migration Safety Review

- `accounts/migrations/0008_user_google_sub.py`: Adds nullable `google_sub` column (`null=True`, `blank=True`) and a unique index (`models.UniqueConstraint` / `unique=True`). Safe on existing rows (populated rows stay `NULL`; PostgreSQL allows multiple `NULL` values in a `UNIQUE` column). Small metadata/lock footprint (`ALTER TABLE ... ADD COLUMN` in PostgreSQL is instantaneous when `NULL` with no rewrite).
- `accounts/migrations/0009_lowercase_user_emails.py`: Safe data migration that normalizes existing `User.email` values to lowercase. Detects case-insensitive duplicates across existing rows FIRST and raises `RuntimeError` rather than merging or deleting user records. Reverse migration is intentionally a no-op (`migrations.RunPython.noop`) because original mixed-case spelling is not retained.
- `accounts/migrations/0010_accountdeletionrequest.py`: Creates a new `accounts_accountdeletionrequest` table and composite `(user, -created_at)` index for Google-only OTP account deletion verification. Zero impact on existing tables (`accounts_user` only gets a foreign key target).
- `tracker/migrations/0004_alter_application_date_applied_and_more.py`: Metadata-only `AlterField` changing `Application.date_applied` default from `django.utils.timezone.now` to `tracker.models._today_date`. Generates no destructive table rewrite on existing data.
- `tracker/migrations/0005_reminder_tracker_rem_applica_5c37ed_idx.py`: Adds a non-unique B-tree index on `tracker_reminder(application_id, remind_at)`. Note: on large production PostgreSQL tables, standard `CREATE INDEX` briefly takes a `SHARE` lock (blocking writes during index build); schedule during low traffic or verify table size first.

## PostgreSQL Staging / CI Verification (Required Before Production Go-Live)

This repository does not assume PostgreSQL is installed on a local developer workstation. Note that `config/settings.py` reads the discrete `DB_*` variables below (it does **not** parse `DATABASE_URL`, and `CONN_MAX_AGE` is fixed at `60`). Before deploying to production, run the full migration chain and test suite against the target PostgreSQL engine version:

```bash
export DEPLOYMENT_ENV=production
export SECRET_KEY="<64+ char random value>"
export DB_ENGINE=postgres
export DB_NAME="<db-name>"
export DB_USER="<db-user>"
export DB_PASSWORD="<db-password>"
export DB_HOST="<db-host>"
export DB_PORT="5432"
export DB_SSLMODE=verify-full
export REDIS_URL="rediss://:<password>@<redis-host>:6379/1"
export CORS_ALLOWED_ORIGINS="https://<your-frontend-origin>"
export CSRF_TRUSTED_ORIGINS="https://<your-api-origin>"
export ALLOWED_HOSTS="<your-api-host>"
export EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend"
export EMAIL_HOST="<smtp-host>"
export EMAIL_PORT="587"
export EMAIL_USE_TLS="True"
export EMAIL_HOST_USER="<smtp-user>"
export EMAIL_HOST_PASSWORD="<smtp-password>"
export DEFAULT_FROM_EMAIL="no-reply@<your-domain>"
export GOOGLE_CLIENT_ID="<your-google-oauth-client-id>"

python manage.py check --deploy --fail-level WARNING
python manage.py migrate --noinput
python manage.py test
```

## Rollback Procedure

1. **Application rollback:** Redeploy the previous container/release artifact only if database schema changes are backward-compatible.
2. **Schema rollback (backward reversal):** Reverse targeted unapplied/new migrations with explicit target numbers only when safe (e.g., `python manage.py migrate tracker 0004` to drop the `Reminder` index, or `python manage.py migrate accounts 0009` to drop `AccountDeletionRequest`).
   - **Important:** `accounts/migrations/0009_lowercase_user_emails.py` uses a no-op reverse function; rolling back past `0009` does not restore original uppercase email casing.
3. **Full data rollback (destructive schema/data recovery):** Restore from the pre-deploy `pg_dump` or managed PostgreSQL point-in-time recovery (PITR) snapshot taken in Step 1:

   ```bash
   PGSSLMODE=verify-full pg_restore --clean --if-exists --no-owner --no-acl -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" iapply_predeploy_<timestamp>.dump
   ```

## Running in Production (Gunicorn & Static Files)

`manage.py runserver` and `DEBUG=True` are **prohibited** in production. Serve the WSGI application with Gunicorn using the checked-in `gunicorn.conf.py`:

```bash
python manage.py collectstatic --noinput
gunicorn -c gunicorn.conf.py config.wsgi:application
```

- `gunicorn.conf.py` binds to `GUNICORN_BIND` (default `0.0.0.0:$PORT`, fallback port `8000`), uses bounded `workers` (`WEB_CONCURRENCY`, 1–16) and `gthread` `threads` (`GUNICORN_THREADS`, 1–8), sets `timeout = 30`, `graceful_timeout = 30`, `keepalive = 5`, `max_requests = 1000` (`jitter = 100`), caps request header/line limits (`limit_request_line = 4094`, `limit_request_fields = 64`, `limit_request_field_size = 4096`), and writes access/error logs to stdout/stderr.
- Ensure your reverse proxy (e.g., nginx, platform router) enforces HTTPS redirect, forwards `X-Forwarded-For` / `X-Forwarded-Proto` matching `NUM_PROXIES` and `TRUST_PROXY_SSL_HEADER`, and serves `STATIC_ROOT` (`staticfiles/`) if Django Admin is enabled (or keep Django Admin restricted/disabled in production).

