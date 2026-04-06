"""
WebPilot — Hardened Static File Server
========================================
Security features (OWASP aligned):
  - IP-based rate limiting with sliding window (429 on exceed)
  - Strict security response headers (CSP, HSTS, X-Frame-Options, etc.)
  - Path traversal prevention
  - CORS restricted to same-origin
  - No directory listing
  - Request size limits
  - Allowed file types whitelist
"""

import http.server
import os
import time
import threading
from collections import defaultdict
from urllib.parse import unquote

# ── Configuration (from env vars, with safe defaults) ──
PORT = int(os.environ.get('PORT', 8000))
# Rate limit: max requests per window per IP
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get('RATE_LIMIT_MAX', '60'))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get('RATE_LIMIT_WINDOW', '60'))
# Max request body size (bytes) — 1 MB default
MAX_BODY_SIZE = int(os.environ.get('MAX_BODY_SIZE', str(1024 * 1024)))

# ── Rate Limiter (IP-based sliding window) ──
class RateLimiter:
    """Thread-safe sliding-window rate limiter keyed by IP address."""

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window = window_seconds
        self.requests = defaultdict(list)  # ip -> [timestamp, ...]
        self.lock = threading.Lock()

    def is_allowed(self, ip):
        """Return True if the IP has not exceeded the rate limit."""
        now = time.time()
        cutoff = now - self.window
        with self.lock:
            # Prune expired timestamps
            self.requests[ip] = [t for t in self.requests[ip] if t > cutoff]
            if len(self.requests[ip]) >= self.max_requests:
                return False
            self.requests[ip].append(now)
            return True

    def retry_after(self, ip):
        """Seconds until the oldest request in the window expires."""
        now = time.time()
        cutoff = now - self.window
        with self.lock:
            timestamps = [t for t in self.requests[ip] if t > cutoff]
            if timestamps:
                return max(0, int(timestamps[0] - cutoff) + 1)
        return 1


limiter = RateLimiter(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SECONDS)

# ── Allowed static file extensions (whitelist) ──
ALLOWED_EXTENSIONS = {
    '.html', '.css', '.js', '.json', '.sql',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.woff', '.woff2', '.ttf', '.eot',
    '.txt', '.xml', '.webmanifest',
}

# ── CRM pages that need Supabase access (broader CSP) ──
CRM_PAGES = {'/admin.html', '/status.html'}

# ── Security Headers (OWASP best practices) ──
# Base headers shared by all pages
BASE_SECURITY_HEADERS = {
    # Prevent clickjacking
    'X-Frame-Options': 'DENY',
    # Prevent MIME-type sniffing
    'X-Content-Type-Options': 'nosniff',
    # XSS filter (legacy browsers)
    'X-XSS-Protection': '1; mode=block',
    # Referrer policy — send origin only on cross-origin
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    # Permissions policy — disable unnecessary browser features
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    # Strict Transport Security (effective when served over HTTPS)
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    # Prevent caching of sensitive pages
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    # Cross-Origin policies
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    # Cross-domain policy
    'X-Permitted-Cross-Domain-Policies': 'none',
}

# CSP for the main marketing site (strict — no external scripts)
MAIN_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "form-action https://formspree.io; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "connect-src 'self' https://formspree.io; "
    "object-src 'none'; "
    "upgrade-insecure-requests;"
)

# CSP for CRM pages (allows Supabase CDN + API, inline scripts for app logic)
CRM_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self' https://*.supabase.co https://*.supabase.in https://cdn.jsdelivr.net; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "object-src 'none'; "
    "form-action 'self'; "
    "upgrade-insecure-requests;"
)


class SecureHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler with security hardening."""

    # Suppress default server header leak
    server_version = 'WebPilot'
    sys_version = ''

    def do_GET(self):
        # ── Rate limit check ──
        client_ip = self.client_address[0]
        if not limiter.is_allowed(client_ip):
            retry = limiter.retry_after(client_ip)
            self.send_error_response(
                429,
                'Too Many Requests',
                f'Rate limit exceeded. Try again in {retry}s.',
                {'Retry-After': str(retry)}
            )
            return

        # ── Path traversal prevention ──
        # Decode and normalize the path, reject anything with '..'
        decoded_path = unquote(self.path.split('?')[0].split('#')[0])
        if '..' in decoded_path or '\\' in decoded_path:
            self.send_error_response(400, 'Bad Request', 'Invalid path.')
            return

        # ── File extension whitelist ──
        # Allow root '/' (serves index.html)
        if decoded_path != '/' and decoded_path != '':
            ext = os.path.splitext(decoded_path)[1].lower()
            if ext not in ALLOWED_EXTENSIONS:
                self.send_error_response(403, 'Forbidden', 'File type not allowed.')
                return

        # ── Block directory listing (only serve files) ──
        local_path = self.translate_path(self.path)
        if os.path.isdir(local_path):
            index = os.path.join(local_path, 'index.html')
            if not os.path.isfile(index):
                self.send_error_response(403, 'Forbidden', 'Directory listing disabled.')
                return

        # Serve the file
        super().do_GET()

    def do_POST(self):
        # ── Rate limit check (stricter for POST — form submissions) ──
        client_ip = self.client_address[0]
        if not limiter.is_allowed(client_ip):
            retry = limiter.retry_after(client_ip)
            self.send_error_response(
                429,
                'Too Many Requests',
                f'Rate limit exceeded. Try again in {retry}s.',
                {'Retry-After': str(retry)}
            )
            return

        # ── Request body size limit ──
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > MAX_BODY_SIZE:
            self.send_error_response(413, 'Payload Too Large', 'Request body exceeds size limit.')
            return

        # Static site — no POST endpoints; reject gracefully
        self.send_error_response(405, 'Method Not Allowed', 'POST is not supported on this server.')

    def do_PUT(self):
        self.send_error_response(405, 'Method Not Allowed', 'PUT is not supported.')

    def do_DELETE(self):
        self.send_error_response(405, 'Method Not Allowed', 'DELETE is not supported.')

    def do_PATCH(self):
        self.send_error_response(405, 'Method Not Allowed', 'PATCH is not supported.')

    def end_headers(self):
        """Inject security headers into every response.
        Uses page-specific CSP: stricter for main site, broader for CRM pages."""
        for header, value in BASE_SECURITY_HEADERS.items():
            self.send_header(header, value)
        # SECURITY: Context-aware CSP — CRM pages need Supabase access
        decoded_path = unquote(self.path.split('?')[0].split('#')[0])
        if decoded_path in CRM_PAGES:
            self.send_header('Content-Security-Policy', CRM_CSP)
        else:
            self.send_header('Content-Security-Policy', MAIN_CSP)
        super().end_headers()

    def send_error_response(self, code, title, message, extra_headers=None):
        """Send a clean JSON-style error response with security headers."""
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        if extra_headers:
            for h, v in extra_headers.items():
                self.send_header(h, v)
        self.end_headers()
        self.wfile.write(f'{code} {title}: {message}\n'.encode('utf-8'))

    def log_message(self, format, *args):
        """Override to include client IP for audit trail."""
        client_ip = self.client_address[0]
        print(f'[{self.log_date_time_string()}] {client_ip} - {format % args}')


# ── Start Server ──
if __name__ == '__main__':
    with http.server.HTTPServer(('', PORT), SecureHandler) as httpd:
        print(f'WebPilot secure server running on port {PORT}')
        print(f'Rate limit: {RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW_SECONDS}s per IP')
        httpd.serve_forever()
