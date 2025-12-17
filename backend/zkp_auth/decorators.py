"""Small Flask decorators used by the API routes."""

from __future__ import annotations

from functools import wraps

from flask import jsonify, request


def verify_request_data(*required_fields):
    """Ensure the request is JSON and includes the required fields.

    This keeps route handlers simpler and makes error responses consistent.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400

            data = request.get_json()
            missing = [field for field in required_fields if field not in data]

            if missing:
                return jsonify({"error": f'Missing fields: {", ".join(missing)}'}), 400

            return f(*args, **kwargs)

        return decorated_function

    return decorator
