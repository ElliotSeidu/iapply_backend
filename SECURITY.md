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

Set `DEPLOYMENT_ENV=production`, `DEBUG=False`, HTTPS-only settings, a real email backend, and `CSP_REPORT_ONLY=False`. The settings module rejects production configurations that use SQLite, non-TLS PostgreSQL, console email, insecure redirects, or report-only CSP.

Before publishing, run:

```text
python manage.py check --deploy
python manage.py makemigrations --check --dry-run
python manage.py test
```
