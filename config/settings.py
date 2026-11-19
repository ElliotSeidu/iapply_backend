from datetime import timedelta
from pathlib import Path

from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from decouple import Csv, config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# ──────────────────────────────────────────────────────────────────────────────
# Core
# ──────────────────────────────────────────────────────────────────────────────

SECRET_KEY = config('SECRET_KEY', default='')
DEBUG = config('DEBUG', default=False, cast=bool)
# Default to production to ensure secure defaults (fail-closed).
ALLOWED_DEPLOYMENT_ENVS = {'development', 'test', 'staging', 'production'}
DEPLOYMENT_ENV = config('DEPLOYMENT_ENV', default='production').strip().lower()
if DEPLOYMENT_ENV not in ALLOWED_DEPLOYMENT_ENVS:
    raise ImproperlyConfigured(
        f'DEPLOYMENT_ENV must be one of {sorted(ALLOWED_DEPLOYMENT_ENVS)}.'
    )

if not SECRET_KEY or SECRET_KEY == 'change-me-to-a-long-random-string':
    raise ImproperlyConfigured('SECRET_KEY must be set to a unique random value.')

if DEPLOYMENT_ENV == 'production':
    if DEBUG:
        raise ImproperlyConfigured('DEBUG must be False in production.')
    if len(SECRET_KEY) < 50:
        raise ImproperlyConfigured('SECRET_KEY must be at least 50 characters in production.')

ALLOWED_HOSTS = config(
    'ALLOWED_HOSTS',
    default='localhost,127.0.0.1',
    cast=Csv(),
)

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ──────────────────────────────────────────────────────────────────────────────
# CORS / CSRF
# ──────────────────────────────────────────────────────────────────────────────

CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:3000,http://127.0.0.1:5173',
    cast=Csv(),
)

CSRF_TRUSTED_ORIGINS = config('CSRF_TRUSTED_ORIGINS', default='', cast=Csv())

# Only send cookies over HTTPS in production.
CORS_ALLOW_CREDENTIALS = False  # We use Bearer tokens, not cookies for API.


# ──────────────────────────────────────────────────────────────────────────────
# HTTPS / TLS security
# ──────────────────────────────────────────────────────────────────────────────

SECURE_SSL_REDIRECT = config('SECURE_SSL_REDIRECT', default=not DEBUG, cast=bool)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=not DEBUG, cast=bool)
CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', default=not DEBUG, cast=bool)
# Only trust the X-Forwarded-Proto header when explicitly enabled behind a reverse proxy.
TRUST_PROXY_SSL_HEADER = config('TRUST_PROXY_SSL_HEADER', default=not DEBUG, cast=bool)
if not DEBUG and TRUST_PROXY_SSL_HEADER:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = config('USE_X_FORWARDED_HOST', default=False, cast=bool)

# X-Content-Type-Options: nosniff prevents MIME-sniffing attacks.
SECURE_CONTENT_TYPE_NOSNIFF = True

# Note: SECURE_BROWSER_XSS_FILTER was removed in Django 4.0 (the header it
# set is deprecated and ignored by all modern browsers) — do not add it back.

if not DEBUG:
    SECURE_HSTS_SECONDS = config('SECURE_HSTS_SECONDS', default=31536000, cast=int)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = config('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True, cast=bool)
    # Set SECURE_HSTS_PRELOAD=False during initial staging rollout until HTTPS works on all subdomains.
    SECURE_HSTS_PRELOAD = config('SECURE_HSTS_PRELOAD', default=True, cast=bool)

X_FRAME_OPTIONS = 'DENY'
DATA_UPLOAD_MAX_MEMORY_SIZE = config('DATA_UPLOAD_MAX_MEMORY_SIZE', default=262144, cast=int)
FILE_UPLOAD_MAX_MEMORY_SIZE = config('FILE_UPLOAD_MAX_MEMORY_SIZE', default=262144, cast=int)
DATA_UPLOAD_MAX_NUMBER_FIELDS = 100


# ──────────────────────────────────────────────────────────────────────────────
# Applications
# ──────────────────────────────────────────────────────────────────────────────

INSTALLED_APPS = [
    'accounts',
    'tracker',
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
]


# ──────────────────────────────────────────────────────────────────────────────
# Middleware
# ──────────────────────────────────────────────────────────────────────────────

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # WhiteNoise serves compressed static files directly from the process — no
    # nginx/S3 needed for static assets. Must be placed directly after
    # SecurityMiddleware and before all other middleware.
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'config.middleware.SecurityHeadersMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'


# ──────────────────────────────────────────────────────────────────────────────
# Security Settings
# ──────────────────────────────────────────────────────────────────────────────
# CSP is implemented via our custom middleware in config.middleware.py
CSP_REPORT_ONLY = config('CSP_REPORT_ONLY', default=False, cast=bool)
# ──────────────────────────────────────────────────────────────────────────────

# Referrer-Policy — only send the origin, not the full path, when crossing origins.
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SAMESITE = 'Lax'
# Allow Google Identity Services sign-in popups to communicate cleanly.
SECURE_CROSS_ORIGIN_OPENER_POLICY = 'same-origin-allow-popups'


# ──────────────────────────────────────────────────────────────────────────────
# JWT
# ──────────────────────────────────────────────────────────────────────────────

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=15),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    # Prevent the algorithm from being downgraded by a malicious token header.
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
}


# ──────────────────────────────────────────────────────────────────────────────
# Django REST Framework
# ──────────────────────────────────────────────────────────────────────────────

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'accounts.throttles.FailClosedAnonRateThrottle',
        'accounts.throttles.FailClosedUserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        # Global buckets (shared across all endpoints of that type)
        'anon': '60/hour',
        'user': '2000/day',
        # Per-endpoint buckets — applied via throttle_classes on each view
        'login': '10/hour',
        'register': '5/hour',
        'verify': '10/hour',
        'password_reset': '5/hour',
        'google_login': '10/hour',
        'token_refresh': '30/hour',
        'password_action': '10/hour',
    },
    'DEFAULT_PAGINATION_CLASS': 'config.pagination.ApplicationPagination',
    # Do not expose internal exception details in production.
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
    # In dev/test default to 0 so client-forged X-Forwarded-For headers are ignored;
    # behind a single reverse proxy (e.g. nginx/Cloud Run) defaults to 1.
    'NUM_PROXIES': config('NUM_PROXIES', default=1 if not DEBUG else 0, cast=int),
}
if not DEBUG:
    REST_FRAMEWORK['DEFAULT_RENDERER_CLASSES'] = (
        'rest_framework.renderers.JSONRenderer',
    )


# ──────────────────────────────────────────────────────────────────────────────
# Storage, Caching, and Logging
# ──────────────────────────────────────────────────────────────────────────────

# H8 Fix: Use WhiteNoise for efficient static file serving with manifest hash versioning.
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# Configurable throttle cache: use TLS Redis in multi-worker production (REDIS_URL),
# falling back safely to LocMemCache for local development/testing.
REDIS_URL = config('REDIS_URL', default='').strip()
REDIS_SOCKET_CONNECT_TIMEOUT = config('REDIS_SOCKET_CONNECT_TIMEOUT', default=3, cast=int)
REDIS_SOCKET_TIMEOUT = config('REDIS_SOCKET_TIMEOUT', default=3, cast=int)
if REDIS_URL:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": REDIS_URL,
            "KEY_PREFIX": "iapply",
            "OPTIONS": {
                "socket_connect_timeout": REDIS_SOCKET_CONNECT_TIMEOUT,
                "socket_timeout": REDIS_SOCKET_TIMEOUT,
            },
        }
    }
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            "LOCATION": "unique-iapply-cache",
        }
    }


@checks.register(checks.Tags.security, deploy=True)
def check_shared_throttle_cache(app_configs, **kwargs):
    issues = []
    if DEPLOYMENT_ENV in {'staging', 'production'} and not REDIS_URL:
        issues.append(
            checks.Warning(
                'REDIS_URL is not configured in production.',
                hint=(
                    'Set REDIS_URL (e.g. rediss://...) so DRF throttles, per-email '
                    'rate limits, and Google ID-token replay protection are shared '
                    'across Gunicorn workers.'
                ),
                id='iapply.W001',
            )
        )
    if DEPLOYMENT_ENV == 'production' and REDIS_URL and not REDIS_URL.startswith('rediss://'):
        issues.append(
            checks.Error(
                'Production REDIS_URL must use TLS (rediss://).',
                id='iapply.E001',
            )
        )
    return issues

# H9 Fix: Add basic logging to capture 500 errors in production.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'json': {
            '()': 'config.logging_utils.JsonFormatter',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose' if DEBUG else 'json',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO' if not DEBUG else 'DEBUG',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'django.request': {
            'handlers': ['console'],
            'level': 'ERROR',
            'propagate': False,
        },
    },
}

# Optional external error-tracking hook point (e.g. Sentry):
# if SENTRY_DSN and not DEBUG:
#     import sentry_sdk
#     sentry_sdk.init(dsn=SENTRY_DSN, send_default_pii=False, environment=DEPLOYMENT_ENV)

# ──────────────────────────────────────────────────────────────────────────────
# Database
# ──────────────────────────────────────────────────────────────────────────────

DB_ENGINE = config('DB_ENGINE', default='sqlite3')

if DB_ENGINE == 'postgres':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': config('DB_NAME', default='iapply_backend'),
            'USER': config('DB_USER', default=''),
            'PASSWORD': config('DB_PASSWORD', default=''),
            'HOST': config('DB_HOST', default='localhost'),
            'PORT': config('DB_PORT', default='5432'),
            'OPTIONS': {
                # Enforce SSL for the DB connection in production.
                'sslmode': config(
                    'DB_SSLMODE',
                    default='require' if DEPLOYMENT_ENV == 'production' else 'prefer',
                ),
            },
            'CONN_MAX_AGE': 60,  # Persistent connections — avoids reconnect overhead
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }


# ──────────────────────────────────────────────────────────────────────────────
# Password validation
# ──────────────────────────────────────────────────────────────────────────────

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Use Argon2 when available (install argon2-cffi) -- it is memory-hard and far
# more resistant to GPU brute-force attacks than PBKDF2.  Django automatically
# re-hashes existing PBKDF2 passwords to Argon2 on next login via the fallback
# list below, so there is no need for a data migration.
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
]
try:  # Only prefer Argon2 when the library is actually installed --
    import argon2  # noqa: F401  otherwise make_password() would raise.
    PASSWORD_HASHERS.insert(0, 'django.contrib.auth.hashers.Argon2PasswordHasher')
except ImportError:
    pass


# ──────────────────────────────────────────────────────────────────────────────
# Internationalisation
# ──────────────────────────────────────────────────────────────────────────────

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True


# ──────────────────────────────────────────────────────────────────────────────
# Static files
# ──────────────────────────────────────────────────────────────────────────────

STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATIC_ROOT.mkdir(parents=True, exist_ok=True)
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


# ──────────────────────────────────────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────────────────────────────────────

AUTH_USER_MODEL = 'accounts.User'


# ──────────────────────────────────────────────────────────────────────────────
# Google Sign-In (Google Identity Services)
# ──────────────────────────────────────────────────────────────────────────────
# The OAuth 2.0 *Web* client ID the frontend renders the Google button with, and
# that this backend verifies the resulting ID token against.
# It is NOT a secret — the browser needs it — but it must match exactly, because
# the `aud` claim check is what stops a token minted for a different app being
# replayed against ours.
#
# Leave blank to disable Google sign-in: /account/google/ then returns 503 and
# the frontend hides the button entirely.
GOOGLE_CLIENT_ID = config('GOOGLE_CLIENT_ID', default='')


# ──────────────────────────────────────────────────────────────────────────────
# Email
# ──────────────────────────────────────────────────────────────────────────────
# Development default: prints emails to the console so you can see
# verification codes without an SMTP server.
#
# For production, set EMAIL_BACKEND to 'django.core.mail.backends.smtp.EmailBackend'
# and fill in the SMTP_* variables in your .env file.
# ──────────────────────────────────────────────────────────────────────────────

EMAIL_BACKEND = config(
    'EMAIL_BACKEND',
    default='django.core.mail.backends.console.EmailBackend',
)
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@iapply.app')

EMAIL_HOST = config('EMAIL_HOST', default='smtp.gmail.com')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)
EMAIL_USE_SSL = config('EMAIL_USE_SSL', default=False, cast=bool)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
EMAIL_TIMEOUT = config('EMAIL_TIMEOUT', default=10, cast=int)

ADMIN_URL = config('ADMIN_URL', default='admin/').strip().lstrip('/')
if ADMIN_URL and not ADMIN_URL.endswith('/'):
    ADMIN_URL += '/'

_DISALLOWED_PROD_EMAIL_BACKENDS = {
    'django.core.mail.backends.console.EmailBackend',
    'django.core.mail.backends.locmem.EmailBackend',
    'django.core.mail.backends.dummy.EmailBackend',
}

if DEPLOYMENT_ENV == 'production':
    if not ALLOWED_HOSTS or any(
        host == '*' or host.startswith('*.') for host in ALLOWED_HOSTS
    ):
        raise ImproperlyConfigured(
            'Production ALLOWED_HOSTS must explicitly list hostnames without wildcards.'
        )
    if DB_ENGINE != 'postgres':
        raise ImproperlyConfigured('Production deployments must use PostgreSQL.')
    if config('DB_SSLMODE', default='require') not in {'require', 'verify-ca', 'verify-full'}:
        raise ImproperlyConfigured('Production database connections must use TLS.')
    if not SECURE_SSL_REDIRECT:
        raise ImproperlyConfigured('SECURE_SSL_REDIRECT must be enabled in production.')
    if not SESSION_COOKIE_SECURE:
        raise ImproperlyConfigured('SESSION_COOKIE_SECURE must be enabled in production.')
    if not CSRF_COOKIE_SECURE:
        raise ImproperlyConfigured('CSRF_COOKIE_SECURE must be enabled in production.')
    if CSP_REPORT_ONLY:
        raise ImproperlyConfigured('CSP_REPORT_ONLY must be False in production.')
    if not CORS_ALLOWED_ORIGINS or any(
        '*' in origin or not origin.startswith('https://')
        for origin in CORS_ALLOWED_ORIGINS
    ):
        raise ImproperlyConfigured(
            'Production CORS_ALLOWED_ORIGINS must contain exact HTTPS origins without wildcards.'
        )
    if any(
        '*' in origin or not origin.startswith('https://')
        for origin in CSRF_TRUSTED_ORIGINS
    ):
        raise ImproperlyConfigured(
            'Production CSRF_TRUSTED_ORIGINS must contain exact HTTPS origins without wildcards.'
        )
    if EMAIL_BACKEND in _DISALLOWED_PROD_EMAIL_BACKENDS:
        raise ImproperlyConfigured('Production email must use a real delivery backend.')
    if EMAIL_BACKEND == 'django.core.mail.backends.smtp.EmailBackend' and not (
        EMAIL_USE_TLS or EMAIL_USE_SSL
    ):
        raise ImproperlyConfigured('Production SMTP must enable TLS or SSL.')
    if not REDIS_URL:
        raise ImproperlyConfigured('REDIS_URL must be configured in production.')
    if not REDIS_URL.startswith('rediss://'):
        raise ImproperlyConfigured('Production REDIS_URL must use TLS (rediss://).')