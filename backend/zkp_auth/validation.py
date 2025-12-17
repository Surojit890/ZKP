"""Input validation and sanitization.

The frontend is untrusted input. These helpers provide consistent validation for:
- usernames (safe characters / length)
- hex-encoded values (keys and proof components)

They intentionally return (ok, sanitized_value, error_message) so routes can
respond with stable, user-friendly error messages.
"""

from __future__ import annotations

import html
import re
import urllib.parse
from typing import Optional, Tuple

USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{3,50}$")
HEX_PATTERN = re.compile(r"^[a-fA-F0-9]+$")


def sanitize_input(value: str) -> str:
    """Sanitize user input to prevent XSS."""
    if not isinstance(value, str):
        return ""

    # URL decode first to handle encoded payloads (e.g., %3Cscript%3E).
    try:
        decoded = urllib.parse.unquote(urllib.parse.unquote(value))
    except Exception:
        decoded = value

    # HTML escape the result so it is safe to log/display.
    return html.escape(decoded.strip())


def validate_username(username: str) -> Tuple[bool, str, str]:
    """Validate username format - returns (is_valid, sanitized_username, error_message)."""
    if not username:
        return False, "", "Username required"

    sanitized = sanitize_input(username)

    # Check for XSS patterns
    dangerous_patterns = ["<", ">", "script", "javascript:", "onerror", "onload", "onclick"]
    lower_input = sanitized.lower()
    for pattern in dangerous_patterns:
        if pattern in lower_input:
            return False, "", "Invalid username format"

    # Validate against allowed pattern
    if not USERNAME_PATTERN.match(sanitized):
        return False, "", "Username must be 3-50 alphanumeric characters, underscores, or hyphens"

    return True, sanitized, ""


def validate_hex_string(value: str, expected_length: Optional[int] = None) -> Tuple[bool, str, str]:
    """Validate hex string - returns (is_valid, sanitized_value, error_message)."""
    if not value:
        return False, "", "Value required"

    sanitized = value.strip()

    if not HEX_PATTERN.match(sanitized):
        return False, "", "Invalid hex format"

    if expected_length and len(sanitized) != expected_length:
        return False, "", f"Expected {expected_length} hex characters"

    return True, sanitized, ""
