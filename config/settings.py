from datetime import timedelta
from pathlib import Path

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
DEPLOYMENT_ENV = config('DEPLOYMENT_ENV', default='production').lower()

if not SECRET_KEY or SECRET_KEY == 'change-me-to-a-long-random-string':
    raise ImproperlyConfigured('SECRET_KEY must be set to a unique random value.')

if DEPLOYMENT_ENV == 'production' and DEBUG:
    raise ImproperlyConfigured('DEBUG must be False in production.')

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
# Only trust the X-Forwarded-Proto header when we know we are sitting behind
# a reverse proxy (i.e. not in debug mode directly exposed to the internet).
if not DEBUG:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = config('USE_X_FORWARDED_HOST', default=False, cast=bool)

# X-Content-Type-Options: nosniff prevents MIME-sniffing attacks.
SECURE_CONTENT_TYPE_NOSNIFF = True

# Note: SECURE_BROWSER_XSS_FILTER was removed in Django 4.0 (the header it
# set is deprecated and ignored by all modern browsers) — do not add it back.

if not DEBUG:
    SECURE_HSTS_SECONDS = config('SECURE_HSTS_SECONDS', default=31536000, cast=int)
    SECURE_HSTS_INCLUDE_SUBDOMAINS = config('SECURE_HSTS_INCLUDE_SUBDOMAINS', default=True, cast=bool)
    SECURE_HSTS_PRELOAD = config('SECURE_HSTS_PRELOAD', default=True, cast=bool)


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
# ──────────────────────────────────────────────────────────────────────────────

# Referrer-Policy — only send the origin, not the full path, when crossing origins.
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'


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
    # Use the standard 'sub' claim for user ID so tokens are compatible with
    # third-party tooling.
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
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
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
    },
    'DEFAULT_PAGINATION_CLASS': 'config.pagination.ApplicationPagination',
    # Do not expose internal exception details in production.
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
    # B3 Fix: Tell DRF we are behind 1 proxy (e.g. nginx/Cloud Run) so it correctly
    # uses the last IP in X-Forwarded-For for rate limiting instead of trusting the whole chain.
    'NUM_PROXIES': 1 if not DEBUG else None,
}


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

# B3 Fix: Throttling requires a cache. We use LocMemCache here, but in a multi-worker
# production environment you should use RedisCache.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "unique-iapply-cache",
    }
}

# H9 Fix: Add basic logging to capture 500 errors in production.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
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
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')

if DEPLOYMENT_ENV == 'production':
    if DB_ENGINE != 'postgres':
        raise ImproperlyConfigured('Production deployments must use PostgreSQL.')
    if config('DB_SSLMODE', default='require') not in {'require', 'verify-ca', 'verify-full'}:
        raise ImproperlyConfigured('Production database connections must use TLS.')
    if config('SECURE_SSL_REDIRECT', default=True, cast=bool) is False:
        raise ImproperlyConfigured('SECURE_SSL_REDIRECT must be enabled in production.')
    if not config('SESSION_COOKIE_SECURE', default=True, cast=bool):
        raise ImproperlyConfigured('SESSION_COOKIE_SECURE must be enabled in production.')
    if not config('CSRF_COOKIE_SECURE', default=True, cast=bool):
        raise ImproperlyConfigured('CSRF_COOKIE_SECURE must be enabled in production.')
    if config('CSP_REPORT_ONLY', default=False, cast=bool):
        raise ImproperlyConfigured('CSP_REPORT_ONLY must be False in production.')
    if not CORS_ALLOWED_ORIGINS or any(
        origin.startswith('http://') for origin in CORS_ALLOWED_ORIGINS
    ):
        raise ImproperlyConfigured(
            'Production CORS_ALLOWED_ORIGINS must contain only HTTPS origins.'
        )
    if EMAIL_BACKEND == 'django.core.mail.backends.console.EmailBackend':
        raise ImproperlyConfigured('Production email must use a real delivery backend.')