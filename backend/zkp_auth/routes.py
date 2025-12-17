"""HTTP routes (Flask Blueprint).

All endpoints are defined here to keep the Flask app factory small.
The Blueprint is registered in `zkp_auth.app.create_app()`.

Important: Route paths and response shapes are kept compatible with the
pre-refactor implementation.
"""

from __future__ import annotations

from datetime import datetime, timezone

import nacl.utils
from flask import Blueprint, current_app, jsonify, request

from .crypto import verify_schnorr_zkp
from .decorators import verify_request_data
from .validation import validate_hex_string, validate_username

api_bp = Blueprint("api", __name__)


@api_bp.get("/health")
def health():
    """Lightweight liveness endpoint."""
    return jsonify({"status": "ok"}), 200


@api_bp.post("/api/register")
@verify_request_data("username", "public_key")
def register():
    """Register a new username with its Ed25519 public key.

    The server stores *only* the public key; secrets never leave the client.
    """
    try:
        data = request.get_json()
        raw_username = data.get("username", "")
        raw_public_key = data.get("public_key", "")

        ok, username, error = validate_username(raw_username)
        if not ok:
            return jsonify({"error": error}), 400

        ok, public_key, error = validate_hex_string(raw_public_key, 64)
        if not ok:
            return jsonify({"error": error}), 400

        try:
            bytes.fromhex(public_key)
        except ValueError:
            return jsonify({"error": "Invalid hex in public key"}), 400

        # Storage is attached by the app factory in `app.extensions`.
        storage = current_app.extensions["storage"]

        if storage.get_user(username):
            return jsonify({"error": "Username exists"}), 409

        user_data = {
            "username": username,
            "public_key": public_key,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "last_login": None,
        }

        storage.save_user(username, user_data)
        current_app.logger.info(f"Registered: {username}")

        return jsonify({"message": "Registered successfully"}), 201

    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({"error": "Registration failed"}), 500


@api_bp.post("/api/auth/challenge")
@verify_request_data("username")
def get_challenge():
    """Issue a random challenge for the client to prove knowledge of the secret."""
    try:
        data = request.get_json()
        raw_username = data.get("username", "")

        ok, username, error = validate_username(raw_username)
        if not ok:
            return jsonify({"error": error}), 400

        storage = current_app.extensions["storage"]
        user = storage.get_user(username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Challenge is 32 random bytes (hex-encoded for transport).
        challenge = nacl.utils.random(32).hex()

        storage.save_challenge(
            username,
            {
                "username": username,
                "challenge": challenge,
                "created_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        current_app.logger.info(f"Challenge issued for {username}")
        return jsonify({"challenge": challenge}), 200

    except Exception as e:
        current_app.logger.error(f"Challenge error: {str(e)}")
        return jsonify({"error": "Failed"}), 500


@api_bp.post("/api/auth/verify")
@verify_request_data("username", "V", "c", "r")
def verify():
    """Verify a Schnorr-style ZKP against the stored public key."""
    try:
        data = request.get_json()
        raw_username = data.get("username", "")
        raw_V = data.get("V", "")
        raw_c = data.get("c", "")
        raw_r = data.get("r", "")

        ok, username, error = validate_username(raw_username)
        if not ok:
            return jsonify({"error": error}), 400

        ok, V_hex, error = validate_hex_string(raw_V, 64)
        if not ok:
            return jsonify({"error": f"Invalid V: {error}"}), 400

        ok, c_hex, error = validate_hex_string(raw_c, 64)
        if not ok:
            return jsonify({"error": f"Invalid c: {error}"}), 400

        ok, r_hex, error = validate_hex_string(raw_r, 64)
        if not ok:
            return jsonify({"error": f"Invalid r: {error}"}), 400

        storage = current_app.extensions["storage"]
        user = storage.get_user(username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Core cryptographic verification: checks [r]G + [c]A == V.
        is_valid = verify_schnorr_zkp(V_hex, c_hex, r_hex, user["public_key"], current_app.logger)

        if is_valid:
            user["last_login"] = datetime.now(timezone.utc).isoformat()
            storage.save_user(username, user)

            # Demo session token (stateless). If you later add real sessions,
            # keep the response shape stable for the frontend.
            token = nacl.utils.random(32).hex()

            current_app.logger.info(f"Auth success: {username}")
            return (
                jsonify(
                    {
                        "message": "Authentication successful",
                        "session_token": token,
                        "username": username,
                    }
                ),
                200,
            )

        current_app.logger.warning(f"Auth failed: {username}")
        return jsonify({"error": "Invalid proof"}), 401

    except Exception as e:
        current_app.logger.error(f"Verify error: {str(e)}")
        return jsonify({"error": "Verification failed"}), 500


@api_bp.get("/api/user/<username>")
def get_user_info(username):
    """Return public profile info (no secrets)."""
    try:
        ok, sanitized_username, _error = validate_username(username)
        if not ok:
            return jsonify({"error": "Invalid username format"}), 400

        storage = current_app.extensions["storage"]
        user = storage.get_user(sanitized_username)
        if not user:
            return jsonify({"error": "User not found"}), 404

        return (
            jsonify(
                {
                    "username": user["username"],
                    "created_at": user["created_at"],
                    "last_login": user.get("last_login"),
                }
            ),
            200,
        )

    except Exception as e:
        current_app.logger.error(f"Error: {str(e)}")
        return jsonify({"error": "Server error"}), 500


@api_bp.get("/api/debug/users")
def debug_users():
    """Debug endpoint to list users (do not expose in untrusted environments)."""
    try:
        storage = current_app.extensions["storage"]
        users = storage.list_users()
        return jsonify({"users": users}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
