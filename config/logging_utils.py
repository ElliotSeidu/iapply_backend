from datetime import datetime, timezone
import json
import logging


class JsonFormatter(logging.Formatter):
    """Emit single-line JSON log records suitable for production log aggregation."""

    def format(self, record):
        payload = {
            'timestamp': datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'module': record.module,
            'message': record.getMessage(),
        }
        if record.exc_info:
            payload['exception'] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)
