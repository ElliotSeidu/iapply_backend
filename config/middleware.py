"""
Security headers middleware for iApply.

Adds defence-in-depth HTTP security headers to all responses:
- Content-Security-Policy (CSP)
- Permissions-Policy
- Referrer-Policy
- X-Content-Type-Options
"""

from django.conf import settings


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Content-Security-Policy header
        # Prevents XSS, frame injection, and restricted asset loads
        csp_directives = [
            "default-src 'none'",
            "img-src 'self' data: https:",
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com data:",
            "script-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
        ]
        csp_header_value = "; ".join(csp_directives)

        if "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = csp_header_value

        # Permissions-Policy to disable unnecessary browser APIs (camera, mic, geolocation)
        if "Permissions-Policy" not in response:
            response["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

        # Strict Referrer-Policy
        if "Referrer-Policy" not in response:
            response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Prevent MIME-type confusion attacks
        if "X-Content-Type-Options" not in response:
            response["X-Content-Type-Options"] = "nosniff"

        # Frame busting / clickjacking protection
        if "X-Frame-Options" not in response:
            response["X-Frame-Options"] = "DENY"

        return response
