"""Production Gunicorn configuration for iApply backend."""

import multiprocessing
import os


def _bounded_int(env_var: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(env_var)
    try:
        value = int(raw) if raw is not None else default
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


bind = os.getenv("GUNICORN_BIND") or f"0.0.0.0:{os.getenv('PORT', '8000')}"

_default_workers = min(multiprocessing.cpu_count() * 2 + 1, 4)
workers = _bounded_int("WEB_CONCURRENCY", _default_workers, 1, 16)
worker_class = "gthread"
threads = _bounded_int("GUNICORN_THREADS", 2, 1, 8)

timeout = 30
graceful_timeout = 30
keepalive = 5

max_requests = 1000
max_requests_jitter = 100

limit_request_line = 4094
limit_request_fields = 64
limit_request_field_size = 4096

accesslog = "-"
errorlog = "-"
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
capture_output = True
