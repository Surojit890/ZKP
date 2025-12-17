"""
Pytest configuration for ZKP Authentication tests
"""

import pytest
import json
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
BACKEND_PATH = PROJECT_ROOT / 'backend'

# pytest options - Registers custom pytest markers: @integration - marks tests as integration tests @unit - marks tests as unit tests
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )


@pytest.fixture(scope="session")
def test_config():
    """Load test configuration"""
    return {
        'api_base_url': 'http://localhost:5000/api',
        'timeout': 5,
        'debug': True
    }


@pytest.fixture
def mock_user_data():
    """Mock user data for testing"""
    return {
        'username': 'testuser',
        'public_key': 'a' * 64,  # 32 bytes hex
        'private_key': 'b' * 64,
        'password': 'testpassword123'
    }


@pytest.fixture
def mock_proof():
    """Mock ZKP proof"""
    return {
        'V': 'c' * 64,      # Commitment
        'c': 'd' * 64,      # Challenge
        'r': 'e' * 64       # Response
    }


@pytest.fixture(autouse=True)
def clear_test_db():
    """Clear MongoDB test database before each test"""
    import sys
    sys.path.insert(0, str(BACKEND_PATH))
    
    try:
        from pymongo import MongoClient
        import os
        
        # Use same MongoDB URI as app
        MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
        
        client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        db = client['zkp_auth']
        
        # Clear collections before each test
        db['users'].delete_many({})
        db['challenges'].delete_many({})
        
        yield
        
        # Cleanup after test (optional)
        # db['users'].delete_many({})
        # db['challenges'].delete_many({})
        
    except Exception as e:
        # If MongoDB not available, tests will use in-memory storage
        yield
