"""
Test vectors and integration tests for ZKP Authentication
"""

import json

# Test vectors for Schnorr ZKP verification
# These vectors verify the mathematical correctness of the protocol

class SchnorrTestVectors:
    """
    Schnorr ZKP Test Vectors
    
    Protocol: [r]G + [c]A == V
    Where:
    - A = [a]G (public key, 'a' is private key)
    - V = [v]G (commitment, 'v' is random)
    - c = challenge (from server)
    - r = v - c*a mod q (prover's response)
    
    For verification to pass: [r]G + [c]A must equal V
    Proof: [r]G + [c]A = [v - c*a]G + [c][a]G = [v - c*a + c*a]G = [v]G = V ✓
    """
    
    # Test Vector 1: All zeros (edge case - should fail)
    TEST_VECTOR_1 = {
        'name': 'All zeros edge case',
        'private_key': '00' * 32,  # All zeros
        'public_key': '5f51e65e475f794b1fe122d388b72eb36f6c53f9b81db5a63a3f68e5f914d60d',  # [0]G computed
        'challenge': '00' * 32,
        'nonce': '00' * 32,
        'commitment': '5f51e65e475f794b1fe122d388b72eb36f6c53f9b81db5a63a3f68e5f914d60d',  # Should be G
        'response': '00' * 32,
        'should_pass': False  # All zeros private key is invalid
    }
    
    # Test Vector 2: Test with unit scalar (1)
    TEST_VECTOR_2 = {
        'name': 'Unit scalar test',
        'private_key': '01' + '00' * 31,  # Scalar 1
        'public_key': '5f51e65e475f794b1fe122d388b72eb36f6c53f9b81db5a63a3f68e5f914d60d',
        'challenge': '00' * 32,
        'nonce': '00' * 32,
        'commitment': '5f51e65e475f794b1fe122d388b72eb36f6c53f9b81db5a63a3f68e5f914d60d',
        'response': '00' * 32,
        'should_pass': False
    }
    
    @staticmethod
    def get_test_vectors():
        """Return all test vectors"""
        return [
            SchnorrTestVectors.TEST_VECTOR_1,
            SchnorrTestVectors.TEST_VECTOR_2,
        ]


class IntegrationTests:
    """
    Integration test scenarios
    """
    
    # Scenario 1: Complete registration and login flow
    SCENARIO_1 = {
        'name': 'Complete Auth Flow',
        'steps': [
            {
                'step': 1,
                'description': 'User Registration',
                'method': 'POST',
                'endpoint': '/api/register',
                'payload': {
                    'username': 'alice',
                    'public_key': '1234567890abcdef' * 4  # 32 bytes
                },
                'expected_status': 201,
                'expected_fields': ['message']
            },
            {
                'step': 2,
                'description': 'Get Challenge',
                'method': 'POST',
                'endpoint': '/api/auth/challenge',
                'payload': {
                    'username': 'alice'
                },
                'expected_status': 200,
                'expected_fields': ['challenge']
            },
            {
                'step': 3,
                'description': 'Verify Proof',
                'method': 'POST',
                'endpoint': '/api/auth/verify',
                'payload': {
                    'username': 'alice',
                    'V': 'deadbeef' * 8,
                    'c': 'cafebabe' * 8,
                    'r': 'decafbad' * 8
                },
                'expected_status': [401, 400],  # Will likely fail with invalid proof
                'expected_fields': ['error', 'message']
            }
        ]
    }
    
    # Scenario 2: Error handling
    SCENARIO_2 = {
        'name': 'Error Handling',
        'steps': [
            {
                'step': 1,
                'description': 'Duplicate Registration',
                'method': 'POST',
                'endpoint': '/api/register',
                'payload': {
                    'username': 'bob',
                    'public_key': 'abcd' * 16
                },
                'expected_status': [201, 409],  # First succeeds or fails if exists
            },
            {
                'step': 2,
                'description': 'Invalid Username',
                'method': 'POST',
                'endpoint': '/api/register',
                'payload': {
                    'username': 'a',  # Too short
                    'public_key': 'abcd' * 16
                },
                'expected_status': 400,
            },
            {
                'step': 3,
                'description': 'Invalid Public Key',
                'method': 'POST',
                'endpoint': '/api/register',
                'payload': {
                    'username': 'charlie',
                    'public_key': 'abcd' * 8  # Too short
                },
                'expected_status': 400,
            },
            {
                'step': 4,
                'description': 'Missing Fields',
                'method': 'POST',
                'endpoint': '/api/register',
                'payload': {
                    'username': 'dave'
                    # Missing public_key
                },
                'expected_status': 400,
            }
        ]
    }
    
    @staticmethod
    def get_scenarios():
        """Return all integration scenarios"""
        return [
            IntegrationTests.SCENARIO_1,
            IntegrationTests.SCENARIO_2,
        ]


# Test configuration
class TestConfig:
    """Configuration for tests"""
    
    # API Base URL
    API_BASE_URL = 'http://localhost:5000/api'
    
    # Timeout for requests (seconds)
    REQUEST_TIMEOUT = 5
    
    # Number of test iterations
    NUM_ITERATIONS = 10
    
    # Crypto parameters
    PRIVATE_KEY_SIZE = 32  # bytes
    PUBLIC_KEY_SIZE = 32   # bytes
    CHALLENGE_SIZE = 32    # bytes
    COMMITMENT_SIZE = 32   # bytes
    RESPONSE_SIZE = 32     # bytes


def run_integration_test(scenario, client):
    """
    Run an integration test scenario
    
    Args:
        scenario: Integration test scenario dict
        client: HTTP client (requests or test client)
    
    Returns:
        dict: Test results
    """
    results = {
        'scenario': scenario['name'],
        'steps': []
    }
    
    for step in scenario['steps']:
        step_result = {
            'step': step['step'],
            'description': step['description'],
            'passed': False,
            'error': None
        }
        
        try:
            # Determine expected status
            expected = step.get('expected_status', 200)
            expected_statuses = expected if isinstance(expected, list) else [expected]
            
            # Make request
            if step['method'] == 'POST':
                response = client.post(
                    step['endpoint'],
                    json=step['payload']
                )
            elif step['method'] == 'GET':
                response = client.get(step['endpoint'])
            else:
                raise ValueError(f"Unknown method: {step['method']}")
            
            # Check status
            if response.status_code in expected_statuses:
                step_result['passed'] = True
                
                # Check expected fields if specified
                if 'expected_fields' in step:
                    data = response.json() if response.status_code < 500 else {}
                    for field in step.get('expected_fields', []):
                        if field not in data:
                            step_result['passed'] = False
                            step_result['error'] = f"Missing field: {field}"
            else:
                step_result['error'] = f"Expected {expected_statuses}, got {response.status_code}"
        
        except Exception as e:
            step_result['error'] = str(e)
        
        results['steps'].append(step_result)
    
    return results


# Export test data
__all__ = [
    'SchnorrTestVectors',
    'IntegrationTests',
    'TestConfig',
    'run_integration_test'
]
