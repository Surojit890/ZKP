"""
Example Python Client for ZKP Authentication
Demonstrates how to use the authentication system programmatically
"""

import requests
import json
import hashlib
import os
from typing import Optional, Dict, Tuple
from urllib.parse import urljoin

# Try to import PyNaCl for crypto operations
try:
    import nacl.utils
    import nacl.bindings
    import nacl.encoding
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: PyNaCl not installed. Crypto features will be limited.")


class ZKPAuthClient:
    """Client for ZKP Authentication"""
    
    def __init__(self, base_url: str = 'http://localhost:5000'):
        """
        Initialize client
        
        Args:
            base_url: Base URL of the authentication server
        """
        self.base_url = base_url
        self.api_url = urljoin(base_url, '/api')
        self.session_token = None
        self.username = None
    
    def _request(self, method: str, endpoint: str, data: Dict = None) -> Tuple[int, Dict]:
        """
        Make HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint (relative to api_url)
            data: Request body (for POST)
        
        Returns:
            Tuple of (status_code, response_json)
        """
        url = urljoin(self.api_url, endpoint)
        headers = {'Content-Type': 'application/json'}
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=5)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=5)
            else:
                raise ValueError(f"Unsupported method: {method}")
            
            return response.status_code, response.json()
        
        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            return 500, {'error': str(e)}
    
    def register(self, username: str, password: str) -> bool:
        """
        Register a new user
        
        Args:
            username: Username
            password: Password
        
        Returns:
            True if registration successful
        """
        if not CRYPTO_AVAILABLE:
            print("Error: Crypto features not available")
            return False
        
        try:
            # Derive private key from password
            private_key = self._derive_private_key(username, password)
            
            # Generate public key
            public_key = self._generate_public_key(private_key)
            
            # Send registration request
            status, response = self._request('POST', 'register', {
                'username': username,
                'public_key': public_key
            })
            
            if status == 201:
                print(f"✓ Registered user: {username}")
                return True
            else:
                print(f"✗ Registration failed: {response.get('error', 'Unknown error')}")
                return False
        
        except Exception as e:
            print(f"Registration error: {e}")
            return False
    
    def login(self, username: str, password: str) -> bool:
        """
        Authenticate user with ZKP
        
        Args:
            username: Username
            password: Password
        
        Returns:
            True if authentication successful
        """
        if not CRYPTO_AVAILABLE:
            print("Error: Crypto features not available")
            return False
        
        try:
            # Step 1: Get challenge
            status, response = self._request('POST', 'auth/challenge', {
                'username': username
            })
            
            if status != 200:
                print(f"✗ Failed to get challenge: {response.get('error')}")
                return False
            
            challenge = response['challenge']
            print(f"✓ Received challenge")
            
            # Step 2: Compute ZKP proof
            private_key = self._derive_private_key(username, password)
            proof = self._compute_proof(private_key, challenge)
            
            # Step 3: Send proof for verification
            status, response = self._request('POST', 'auth/verify', {
                'username': username,
                'V': proof['V'],
                'c': proof['c'],
                'r': proof['r']
            })
            
            if status == 200:
                self.session_token = response['session_token']
                self.username = username
                print(f"✓ Authentication successful")
                print(f"  Session token: {self.session_token[:16]}...")
                return True
            else:
                print(f"✗ Authentication failed: {response.get('error')}")
                return False
        
        except Exception as e:
            print(f"Login error: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_user_info(self, username: str) -> Optional[Dict]:
        """
        Get user information
        
        Args:
            username: Username
        
        Returns:
            User info dict or None if not found
        """
        status, response = self._request('GET', f'user/{username}')
        
        if status == 200:
            return response
        else:
            print(f"User not found: {username}")
            return None
    
    def _derive_private_key(self, username: str, password: str) -> bytes:
        """Derive private key from password"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Crypto not available")
        
        # Create salt from username
        salt_base = nacl.bindings.crypto_hash_sha256(
            f"{username}_salt".encode()
        )
        salt = salt_base[:16]  # Take first 16 bytes
        
        # Derive 32-byte key
        private_key = nacl.bindings.crypto_pwhash(
            32,
            password.encode(),
            salt,
            nacl.bindings.crypto_pwhash_OPSLIMIT_MODERATE,
            nacl.bindings.crypto_pwhash_MEMLIMIT_MODERATE,
            nacl.bindings.crypto_pwhash_ALG_DEFAULT
        )
        
        return private_key
    
    def _generate_public_key(self, private_key: bytes) -> str:
        """Generate public key from private key"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Crypto not available")
        
        key_pair = nacl.bindings.crypto_sign_seed_keypair(private_key)
        return nacl.encoding.HexEncoder.encode(key_pair[1]).decode()
    
    def _compute_proof(self, private_key: bytes, challenge_hex: str) -> Dict[str, str]:
        """Compute Schnorr ZKP proof"""
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("Crypto not available")
        
        # Clamp private key
        a = self._clamp_scalar(private_key)
        
        # Generate random nonce
        v = nacl.utils.random(32)
        
        # Compute commitment V = [v]G
        V = nacl.bindings.crypto_scalarmult_base(v)
        
        # Parse challenge
        c = bytes.fromhex(challenge_hex)
        
        # Compute response r = v - c*a mod q
        q = int('27742317777884353535851937790883648493') + (1 << 252)
        
        v_int = int.from_bytes(v, 'little')
        c_int = int.from_bytes(c, 'little')
        a_int = int.from_bytes(a, 'little')
        
        r_int = (v_int - c_int * a_int) % q
        r = int.to_bytes(r_int, 32, 'little')
        
        return {
            'V': nacl.encoding.HexEncoder.encode(V).decode(),
            'c': challenge_hex,
            'r': nacl.encoding.HexEncoder.encode(r).decode()
        }
    
    def _clamp_scalar(self, k: bytes) -> bytes:
        """Clamp scalar for Ed25519"""
        clamped = bytearray(k)
        clamped[0] &= 248
        clamped[31] &= 127
        clamped[31] |= 64
        return bytes(clamped)


def main():
    """Example usage"""
    
    # Create client
    client = ZKPAuthClient('http://localhost:5000')
    
    # Example user
    username = 'alice'
    password = 'MySecurePassword123'
    
    print("=" * 50)
    print("ZKP Authentication Client Example")
    print("=" * 50)
    
    # Test registration
    print("\n1. Testing Registration...")
    client.register(username, password)
    
    # Test login
    print("\n2. Testing Login...")
    client.login(username, password)
    
    # Test user info
    print("\n3. Retrieving User Info...")
    user_info = client.get_user_info(username)
    if user_info:
        print(f"  Username: {user_info['username']}")
        print(f"  Created: {user_info['created_at']}")
        print(f"  Last Login: {user_info.get('last_login', 'Never')}")
    
    print("\n" + "=" * 50)
    print("Example completed!")
    print("=" * 50)


if __name__ == '__main__':
    main()
