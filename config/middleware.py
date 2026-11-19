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

        admin_prefix = '/' + (getattr(settings, 'ADMIN_URL', 'admin/') or 'admin/').lstrip('/')
        is_admin_path = request.path.startswith(admin_prefix)
        style_src = (
            "style-src 'self' 'unsafe-inline' https://accounts.google.com/gsi/style"
            if is_admin_path
            else "style-src 'self' https://accounts.google.com/gsi/style"
        )

        # Content-Security-Policy header
        # Prevents XSS, frame injection, and restricted asset loads
        csp_directives = [
            "default-src 'none'",
            "img-src 'self' data: https:",
            style_src,
            "font-src 'self' data:",
            # Exact Google Identity Services script URL required for Sign In with Google.
            "script-src 'self' https://accounts.google.com/gsi/client",
            # API calls to our own backend + Google Identity Services credential exchange.
            "connect-src 'self' https://accounts.google.com/gsi/",
            # Google One-Tap / Sign-In button renders inside an iframe from GIS.
            "frame-src https://accounts.google.com/gsi/",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "object-src 'none'",
        ]
        csp_header_value = "; ".join(csp_directives)
        csp_header_name = (
            "Content-Security-Policy-Report-Only"
            if getattr(settings, "CSP_REPORT_ONLY", False)
            else "Content-Security-Policy"
        )

        if csp_header_name not in response:
            response[csp_header_name] = csp_header_value

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
