"""
Unit tests for ZKP Authentication Backend
"""

import pytest
import json
import sys
import os
from datetime import datetime

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

# Test fixtures
@pytest.fixture
def client():
    """Create Flask test client"""
    # Import here to avoid import errors if dependencies aren't installed
    try:
        from app_final import app
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    except ImportError:
        pytest.skip("Backend dependencies not installed")


class TestRegistration:
    """Test user registration"""
    
    def test_health_check(self, client):
        """Test health endpoint"""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'
    
    def test_register_success(self, client):
        """Test successful registration"""
        payload = {
            'username': 'testuser',
            'public_key': '0' * 64  # 32 bytes = 64 hex chars
        }
        response = client.post(
            '/api/register',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'message' in data
    
    def test_register_duplicate_user(self, client):
        """Test registering duplicate user"""
        payload = {
            'username': 'duplicate',
            'public_key': '0' * 64
        }
        # First registration
        response1 = client.post(
            '/api/register',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response1.status_code == 201
        
        # Second registration with same username
        response2 = client.post(
            '/api/register',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response2.status_code == 409
    
    def test_register_invalid_username(self, client):
        """Test registration with invalid username"""
        payload = {
            'username': 'ab',  # Too short
            'public_key': '0' * 64
        }
        response = client.post(
            '/api/register',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
    
    def test_register_invalid_pubkey(self, client):
        """Test registration with invalid public key"""
        payload = {
            'username': 'testuser2',
            'public_key': '0' * 63  # Too short
        }
        response = client.post(
            '/api/register',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400
    
    def test_register_missing_fields(self, client):
        """Test registration with missing fields"""
        payload = {'username': 'testuser3'}
        response = client.post(
            '/api/register',
            data=json.dumps(payload),
            content_type='application/json'
        )
        assert response.status_code == 400


class TestChallenge:
    """Test authentication challenge"""
    
    def test_get_challenge_success(self, client):
        """Test getting challenge for existing user"""
        # Register user first
        client.post(
            '/api/register',
            data=json.dumps({
                'username': 'chaltest',
                'public_key': '0' * 64
            }),
            content_type='application/json'
        )
        
        # Get challenge
        response = client.post(
            '/api/auth/challenge',
            data=json.dumps({'username': 'chaltest'}),
            content_type='application/json'
        )
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'challenge' in data
        assert len(data['challenge']) == 64  # 32 bytes hex
    
    def test_get_challenge_nonexistent_user(self, client):
        """Test getting challenge for non-existent user"""
        response = client.post(
            '/api/auth/challenge',
            data=json.dumps({'username': 'nonexistent'}),
            content_type='application/json'
        )
        assert response.status_code == 404


class TestVerification:
    """Test ZKP verification"""
    
    def test_verify_invalid_proof(self, client):
        """Test verification with invalid proof"""
        # Register user
        client.post(
            '/api/register',
            data=json.dumps({
                'username': 'verifytest',
                'public_key': 'a' * 64
            }),
            content_type='application/json'
        )
        
        # Send invalid proof
        response = client.post(
            '/api/auth/verify',
            data=json.dumps({
                'username': 'verifytest',
                'V': '0' * 64,
                'c': '0' * 64,
                'r': '0' * 64
            }),
            content_type='application/json'
        )
        # Should fail verification
        assert response.status_code in [401, 400]
    
    def test_verify_nonexistent_user(self, client):
        """Test verification for non-existent user"""
        response = client.post(
            '/api/auth/verify',
            data=json.dumps({
                'username': 'nonexistent',
                'V': '0' * 64,
                'c': '0' * 64,
                'r': '0' * 64
            }),
            content_type='application/json'
        )
        assert response.status_code == 404
    
    def test_verify_invalid_proof_format(self, client):
        """Test verification with invalid format"""
        # Register user
        client.post(
            '/api/register',
            data=json.dumps({
                'username': 'formattest',
                'public_key': '0' * 64
            }),
            content_type='application/json'
        )
        
        # Send proof with wrong size
        response = client.post(
            '/api/auth/verify',
            data=json.dumps({
                'username': 'formattest',
                'V': '0' * 62,  # Too short
                'c': '0' * 64,
                'r': '0' * 64
            }),
            content_type='application/json'
        )
        assert response.status_code == 400


class TestUserInfo:
    """Test user info endpoint"""
    
    def test_get_user_info(self, client):
        """Test retrieving user info"""
        # Register
        client.post(
            '/api/register',
            data=json.dumps({
                'username': 'infotest',
                'public_key': 'b' * 64
            }),
            content_type='application/json'
        )
        
        # Get info
        response = client.get('/api/user/infotest')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['username'] == 'infotest'
        assert 'created_at' in data
    
    def test_get_user_info_nonexistent(self, client):
        """Test getting info for non-existent user"""
        response = client.get('/api/user/nonexistent')
        assert response.status_code == 404


class TestDebugEndpoints:
    """Test debug endpoints"""
    
    def test_debug_users(self, client):
        """Test debug users endpoint"""
        # Register a user
        client.post(
            '/api/register',
            data=json.dumps({
                'username': 'debugtest',
                'public_key': 'c' * 64
            }),
            content_type='application/json'
        )
        
        # Get users
        response = client.get('/api/debug/users')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'users' in data


# Crypto utility tests
class TestCryptoUtilities:
    """Test cryptographic utilities"""
    
    def test_bytes_to_int(self):
        """Test bytes to int conversion"""
        try:
            from zkp_auth.crypto import bytes_to_int
            
            # Test basic conversion
            b = bytes([1, 2, 3, 4])
            result = bytes_to_int(b)
            assert result == 0x04030201  # Little-endian
        except ImportError:
            pytest.fail("Backend not available")
    
    def test_int_to_bytes(self):
        """Test int to bytes conversion"""
        try:
            from zkp_auth.crypto import int_to_bytes
            
            # Test conversion
            n = 0x04030201
            result = int_to_bytes(n, 4)
            assert result == bytes([1, 2, 3, 4])
        except ImportError:
            pytest.fail("Backend not available")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
