"""Cryptographic primitives used by the backend.

This project uses libsodium (via PyNaCl bindings) to work with Ed25519 group
operations. The browser computes a Schnorr-style ZKP and the server verifies it
using only the user's public key.

Note: We intentionally use *no-clamp* scalar multiplication in verification to
match the frontend's behavior.
"""

from __future__ import annotations

import logging
from typing import Union

import nacl.bindings


def clamp_scalar(scalar_bytes: Union[str, bytes]) -> bytes:
    """Clamp scalar for Ed25519 per RFC 8032."""
    if isinstance(scalar_bytes, str):
        scalar_bytes = bytes.fromhex(scalar_bytes)

    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def bytes_to_int(b: bytes, order: int | None = None) -> int:
    """Convert bytes to integer (little-endian)."""
    result = 0
    for i in range(len(b)):
        result |= b[i] << (8 * i)
    if order:
        result = result % order
    return result


def int_to_bytes(n: int, length: int = 32) -> bytes:
    """Convert integer to bytes (little-endian)."""
    result = bytearray(length)
    for i in range(length):
        result[i] = (n >> (8 * i)) & 0xFF
    return bytes(result)


def verify_schnorr_zkp(V_hex: str, c_hex: str, r_hex: str, A_hex: str, logger: logging.Logger) -> bool:
    """Verify Schnorr ZKP: [r]G + [c]A == V using Ed25519 group operations."""
    try:
        V = bytes.fromhex(V_hex)
        c = bytes.fromhex(c_hex)
        r = bytes.fromhex(r_hex)
        A = bytes.fromhex(A_hex)

        # All values are 32-byte compressed Edwards points/scalars.
        if len(V) != 32 or len(c) != 32 or len(r) != 32 or len(A) != 32:
            logger.warning("Invalid proof dimensions")
            return False

        # Check if points are valid Ed25519 points
        if not nacl.bindings.crypto_core_ed25519_is_valid_point(V):
            logger.warning("Invalid V point")
            return False
        if not nacl.bindings.crypto_core_ed25519_is_valid_point(A):
            logger.warning("Invalid A point")
            return False

        # Compute [r]G (base point multiplication)
        r_G = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r)

        # Compute [c]A (no clamp; must match frontend)
        c_A = nacl.bindings.crypto_scalarmult_ed25519_noclamp(c, A)

        # Add points: [r]G + [c]A
        V_computed = nacl.bindings.crypto_core_ed25519_add(r_G, c_A)

        is_valid = V == V_computed

        logger.info(f"ZKP verification: {'PASS' if is_valid else 'FAIL'}")
        if not is_valid:
            logger.debug(f"  V expected: {V.hex()}")
            logger.debug(f"  V computed: {V_computed.hex()}")

        return is_valid

    except Exception as e:
        logger.error(f"Verification error: {str(e)}", exc_info=True)
        return False
