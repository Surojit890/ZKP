"""Flask application factory.

This module owns *process-level* wiring:
- Loads environment variables from `.env`
- Configures logging
- Initializes storage (MongoDB if configured; otherwise in-memory)
- Registers the API Blueprint
- Applies security headers and optional HTTPS redirect

Keeping these concerns here makes `routes.py` focused purely on request/response
logic.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request
from flask_cors import CORS

from .routes import api_bp
from .storage import Storage


def create_app() -> Flask:
    # Load environment variables from `.env` once, at app creation time.
    load_dotenv()

    # Configure logging (keeps INFO default).
    # The routes use `current_app.logger` and this module-level logger.
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    app = Flask(__name__)
    CORS(app)

    # Storage initialization:
    # - If `MONGODB_URI` is set and reachable, use MongoDB collections.
    # - Otherwise fall back to in-memory dicts (useful for local dev/tests).
    app.extensions["storage"] = Storage(
        mongodb_uri=os.getenv("MONGODB_URI"),
        logger=logger,
    )

    app.register_blueprint(api_bp)

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(error):
        logger.error(f"Server error: {str(error)}")
        return jsonify({"error": "Server error"}), 500

    @app.after_request
    def set_security_headers(response):
        """Add comprehensive security headers to all responses."""
        # These are copied from the prior monolithic implementation to preserve
        # behavior and baseline hardening (CSP, clickjacking, HSTS, etc.).
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "object-src 'none'; "
            "media-src 'none'; "
            "frame-src 'none'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        return response

    @app.before_request
    def redirect_https():
        """Redirect HTTP to HTTPS in production."""
        # Only enforce redirects when explicitly running in production.
        if not request.is_secure and os.getenv("FLASK_ENV") == "production":
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

    return app
