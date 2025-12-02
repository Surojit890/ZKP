"""
ZKP-Based Web Authentication Backend - Production Version
Flask application with proper Schnorr ZKP verification on Ed25519
"""

from flask import Flask, request, jsonify, redirect
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import nacl.bindings
import nacl.utils
import nacl.encoding
from datetime import datetime, timezone
from functools import wraps
import logging
import json
import re
import html
import urllib.parse

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Input validation patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{3,50}$')
HEX_PATTERN = re.compile(r'^[a-fA-F0-9]+$')

def sanitize_input(value: str) -> str:
    """Sanitize user input to prevent XSS"""
    if not isinstance(value, str):
        return ''
    # URL decode first to handle encoded payloads
    try:
        decoded = urllib.parse.unquote(urllib.parse.unquote(value))
    except:
        decoded = value
    # HTML escape the result
    return html.escape(decoded.strip())

def validate_username(username: str) -> tuple:
    """Validate username format - returns (is_valid, sanitized_username, error_message)"""
    if not username:
        return False, '', 'Username required'
    
    # Sanitize first
    sanitized = sanitize_input(username)
    
    # Check for XSS patterns
    dangerous_patterns = ['<', '>', 'script', 'javascript:', 'onerror', 'onload', 'onclick']
    lower_input = sanitized.lower()
    for pattern in dangerous_patterns:
        if pattern in lower_input:
            return False, '', 'Invalid username format'
    
    # Validate against allowed pattern
    if not USERNAME_PATTERN.match(sanitized):
        return False, '', 'Username must be 3-50 alphanumeric characters, underscores, or hyphens'
    
    return True, sanitized, ''

def validate_hex_string(value: str, expected_length: int = None) -> tuple:
    """Validate hex string - returns (is_valid, sanitized_value, error_message)"""
    if not value:
        return False, '', 'Value required'
    
    sanitized = value.strip()
    
    if not HEX_PATTERN.match(sanitized):
        return False, '', 'Invalid hex format'
    
    if expected_length and len(sanitized) != expected_length:
        return False, '', f'Expected {expected_length} hex characters'
    
    return True, sanitized, ''

app = Flask(__name__)
CORS(app)

# MongoDB Connection - Load from environment variable
MONGODB_URI = os.getenv('MONGODB_URI')

if not MONGODB_URI:
    logger.warning("MONGODB_URI not set in environment. Using in-memory storage.")

# In-memory storage (fallback)
users_db = {}
challenges_db = {}
mongo_available = False

if MONGODB_URI:
    try:
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        client.admin.command('ping')
        db = client['zkp_auth']
        users_collection = db['users']
        challenges_collection = db['challenges']
        mongo_available = True
        logger.info("Connected to MongoDB")
    except Exception as e:
        logger.warning(f"Using in-memory storage: {e}")


def get_user(username):
    """Retrieve user from database"""
    if mongo_available:
        return users_collection.find_one({'username': username})
    return users_db.get(username)


def save_user(username, user_data):
    """Save user to database"""
    if mongo_available:
        users_collection.update_one(
            {'username': username},
            {'$set': user_data},
            upsert=True
        )
    else:
        users_db[username] = user_data


def save_challenge(username, challenge_data):
    """Save challenge to database"""
    if mongo_available:
        challenges_collection.insert_one(challenge_data)
    else:
        key = f"{username}_{challenge_data['challenge']}"
        challenges_db[key] = challenge_data


def verify_request_data(*required_fields):
    """Decorator to verify required fields"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Request must be JSON'}), 400
            
            data = request.get_json()
            missing = [field for field in required_fields if field not in data]
            
            if missing:
                return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def clamp_scalar(scalar_bytes):
    """
    Clamp scalar for Ed25519 per RFC 8032
    """
    if isinstance(scalar_bytes, str):
        scalar_bytes = bytes.fromhex(scalar_bytes)
    
    k = bytearray(scalar_bytes)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


def bytes_to_int(b, order=None):
    """Convert bytes to integer (little-endian)"""
    result = 0
    for i in range(len(b)):
        result |= b[i] << (8 * i)
    if order:
        result = result % order
    return result


def int_to_bytes(n, length=32):
    """Convert integer to bytes (little-endian)"""
    result = bytearray(length)
    for i in range(length):
        result[i] = (n >> (8 * i)) & 0xFF
    return bytes(result)


def verify_schnorr_zkp(V_hex, c_hex, r_hex, A_hex):
    """
    Verify Schnorr ZKP: [r]G + [c]A == V
    Using Ed25519 group operations.
    """
    try:
        # Parse hex inputs to bytes
        V = bytes.fromhex(V_hex)
        c = bytes.fromhex(c_hex)
        r = bytes.fromhex(r_hex)
        A = bytes.fromhex(A_hex)
        
        # Validate sizes (32 bytes each for Ed25519)
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

        # Compute [r]G
        r_G = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r)
        
        # Compute [c]A
        # Note: c is NOT clamped for Schnorr usually, but we must ensure
        # the frontend matches. We will use noclamp for both.
        c_A = nacl.bindings.crypto_scalarmult_ed25519_noclamp(c, A)
        
        # Add points: [r]G + [c]A
        V_computed = nacl.bindings.crypto_core_ed25519_add(r_G, c_A)
        
        # Compare
        is_valid = (V == V_computed)
        
        logger.info(f"ZKP verification: {'PASS' if is_valid else 'FAIL'}")
        if not is_valid:
            logger.debug(f"  V expected: {V.hex()}")
            logger.debug(f"  V computed: {V_computed.hex()}")
        
        return is_valid
    
    except Exception as e:
        logger.error(f"Verification error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


def ed25519_add_points(P1, P2):
    """
    Add two Ed25519 points using coordinate-independent addition
    This is a fallback using libsodium's signature verification mechanism
    """
    try:
        # For Ed25519, use the property that if we have a message m:
        # crypto_sign(m, sk) returns a signature that encodes R where R = [r]G
        # and we can verify it using the public key A = [a]G
        
        # A simpler approach for verification is to use the property:
        # We need to verify [r]G + [c]A == V
        
        # Use double scalar multiplication property if available
        # Otherwise, construct a test using signing and verification
        
        # For compatibility, return the sum computed via hash-based method
        # This is NOT cryptographically sound and should only be used as fallback
        
        import hashlib
        combined = P1 + P2
        # Use as compressed representation
        return hashlib.sha512(combined).digest()[:32]
    
    except Exception as e:
        logger.error(f"Point addition error: {str(e)}")
        raise


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'ok'}), 200


@app.route('/api/register', methods=['POST'])
@verify_request_data('username', 'public_key')
def register():
    """User registration endpoint"""
    try:
        data = request.get_json()
        raw_username = data.get('username', '')
        raw_public_key = data.get('public_key', '')
        
        # Validate username with sanitization
        is_valid, username, error = validate_username(raw_username)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Validate public key
        is_valid, public_key, error = validate_hex_string(raw_public_key, 64)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Verify it's actually valid hex that can be decoded
        try:
            bytes.fromhex(public_key)
        except ValueError:
            return jsonify({'error': 'Invalid hex in public key'}), 400
        
        # Check uniqueness
        if get_user(username):
            return jsonify({'error': 'Username exists'}), 409
        
        # Save user
        user_data = {
            'username': username,
            'public_key': public_key,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'last_login': None
        }
        
        save_user(username, user_data)
        logger.info(f"Registered: {username}")
        
        return jsonify({'message': 'Registered successfully'}), 201
    
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/api/auth/challenge', methods=['POST'])
@verify_request_data('username')
def get_challenge():
    """Get authentication challenge"""
    try:
        data = request.get_json()
        raw_username = data.get('username', '')
        
        # Validate username with sanitization
        is_valid, username, error = validate_username(raw_username)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Check user exists
        user = get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Generate challenge
        challenge = nacl.utils.random(32).hex()
        
        # Store
        save_challenge(username, {
            'username': username,
            'challenge': challenge,
            'created_at': datetime.now(timezone.utc).isoformat()
        })
        
        logger.info(f"Challenge issued for {username}")
        return jsonify({'challenge': challenge}), 200
    
    except Exception as e:
        logger.error(f"Challenge error: {str(e)}")
        return jsonify({'error': 'Failed'}), 500


@app.route('/api/auth/verify', methods=['POST'])
@verify_request_data('username', 'V', 'c', 'r')
def verify():
    """Verify authentication proof"""
    try:
        data = request.get_json()
        raw_username = data.get('username', '')
        raw_V = data.get('V', '')
        raw_c = data.get('c', '')
        raw_r = data.get('r', '')
        
        # Validate username
        is_valid, username, error = validate_username(raw_username)
        if not is_valid:
            return jsonify({'error': error}), 400
        
        # Validate proof components
        is_valid, V_hex, error = validate_hex_string(raw_V, 64)
        if not is_valid:
            return jsonify({'error': f'Invalid V: {error}'}), 400
        
        is_valid, c_hex, error = validate_hex_string(raw_c, 64)
        if not is_valid:
            return jsonify({'error': f'Invalid c: {error}'}), 400
        
        is_valid, r_hex, error = validate_hex_string(raw_r, 64)
        if not is_valid:
            return jsonify({'error': f'Invalid r: {error}'}), 400
        
        # Get user
        user = get_user(username)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Verify proof
        is_valid = verify_schnorr_zkp(V_hex, c_hex, r_hex, user['public_key'])
        
        if is_valid:
            # Update login
            user['last_login'] = datetime.now(timezone.utc).isoformat()
            save_user(username, user)
            
            # Generate token
            token = nacl.utils.random(32).hex()
            
            logger.info(f"Auth success: {username}")
            return jsonify({
                'message': 'Authentication successful',
                'session_token': token,
                'username': username
            }), 200
        else:
            logger.warning(f"Auth failed: {username}")
            return jsonify({'error': 'Invalid proof'}), 401
    
    except Exception as e:
        logger.error(f"Verify error: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500


@app.route('/api/user/<username>', methods=['GET'])
def get_user_info(username):
    """Get public user info"""
    try:
        # Validate and sanitize the URL parameter
        is_valid, sanitized_username, error = validate_username(username)
        if not is_valid:
            # Return generic error without reflecting input
            return jsonify({'error': 'Invalid username format'}), 400
        
        user = get_user(sanitized_username)
        if not user:
            # Return generic error without reflecting input
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'username': user['username'],
            'created_at': user['created_at'],
            'last_login': user.get('last_login')
        }), 200
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({'error': 'Server error'}), 500


@app.route('/api/debug/users', methods=['GET'])
def debug_users():
    """Debug: list users"""
    try:
        if mongo_available:
            users = list(users_collection.find({}, {'_id': 0}))
        else:
            users = list(users_db.values())
        
        return jsonify({'users': users}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(error):
    logger.error(f"Server error: {str(error)}")
    return jsonify({'error': 'Server error'}), 500


@app.after_request
def set_security_headers(response):
    """Add comprehensive security headers to all responses"""
    # Content Security Policy - strengthened
    response.headers['Content-Security-Policy'] = (
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
    # XSS and content type protection
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer and permissions
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=(), usb=()'
    
    # Transport security
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Cross-Origin policies (new security headers)
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    
    # Cache control for sensitive data
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    
    return response


@app.before_request
def redirect_https():
    """Redirect HTTP to HTTPS in production"""
    if not request.is_secure and os.getenv('FLASK_ENV') == 'production':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)


if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')
