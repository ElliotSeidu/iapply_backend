from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe


@never_cache
@require_safe
def healthz(request):
    """Lightweight liveness probe returning only {"status": "ok"}."""
    return JsonResponse({'status': 'ok'})


@never_cache
@require_safe
def readyz(request):
    """Readiness probe verifying database and shared cache without leaking internals."""
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        if getattr(settings, 'REDIS_URL', ''):
            cache.get('__iapply_readyz__')
    except Exception:
        return JsonResponse({'status': 'unavailable'}, status=503)
    return JsonResponse({'status': 'ready'})
