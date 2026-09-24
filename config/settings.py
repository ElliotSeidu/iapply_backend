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
DEPLOYMENT_ENV = config('DEPLOYMENT_ENV', default='development').lower()

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
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = config('USE_X_FORWARDED_HOST', default=False, cast=bool)

# X-Content-Type-Options: nosniff prevents MIME-sniffing attacks.
SECURE_CONTENT_TYPE_NOSNIFF = True

# X-XSS-Protection header (legacy browsers — modern ones ignore it in favour of CSP).
SECURE_BROWSER_XSS_FILTER = True

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
# Content Security Policy (django-csp)
# ──────────────────────────────────────────────────────────────────────────────
# Policy explanation:
#   default-src 'none'       — block everything unless explicitly allowed
#   connect-src 'self'       — API calls only go back to the same origin
#   script-src  'self'       — no inline scripts, no eval
#   style-src   'self' 'unsafe-inline' — Tailwind injects <style> tags
#   img-src     'self' data: — data URIs for favicon/placeholder images
#   font-src    'self'
#   frame-ancestors 'none'   — equivalent to X-Frame-Options: DENY
#
# Start in REPORT_ONLY mode so violations are logged without breaking anything.
# Switch CSP_REPORT_ONLY to False once you've reviewed the reports in prod.
# ──────────────────────────────────────────────────────────────────────────────

CSP_REPORT_ONLY = config('CSP_REPORT_ONLY', default=True, cast=bool)

CSP_DEFAULT_SRC = ("'none'",)
CSP_CONNECT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:")
CSP_FONT_SRC = ("'self'",)
CSP_FRAME_ANCESTORS = ("'none'",)
CSP_FORM_ACTION = ("'self'",)
CSP_BASE_URI = ("'none'",)

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
    },
    'DEFAULT_PAGINATION_CLASS': 'config.pagination.ApplicationPagination',
    # Do not expose internal exception details in production.
    'EXCEPTION_HANDLER': 'rest_framework.views.exception_handler',
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
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


# ──────────────────────────────────────────────────────────────────────────────
# Authentication
# ──────────────────────────────────────────────────────────────────────────────

AUTH_USER_MODEL = 'accounts.User'


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