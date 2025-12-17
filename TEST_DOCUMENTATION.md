# ZKP Authentication - Comprehensive Test Documentation

## Table of Contents

1. [Overview](#overview)
2. [Testing Philosophy](#testing-philosophy)
3. [Test Organization](#test-organization)
4. [Backend Unit Tests](#backend-unit-tests)
5. [Test Vectors & Integration Tests](#test-vectors--integration-tests)
6. [Replay Attack Tests](#replay-attack-tests)
7. [MITM Attack Tests](#mitm-attack-tests)
8. [XSS Security Tests](#xss-security-tests)
9. [Running Tests](#running-tests)
10. [Troubleshooting](#troubleshooting)

---

## Overview

This document provides comprehensive documentation for all test cases in the ZKP Authentication System. The test suite covers:

- **Backend Unit Tests**: Core API functionality and validation
- **Test Vectors**: Mathematical correctness of Schnorr ZKP protocol
- **Security Tests**: Replay attacks, MITM attacks, and XSS vulnerabilities
- **Integration Tests**: End-to-end authentication flows

**Total Test Coverage**: 40+ test cases across 5 test files

---

## Testing Philosophy

### Goals

1. **Correctness**: Verify cryptographic protocol implementation
2. **Security**: Test against common attack vectors
3. **Robustness**: Validate input handling and error cases
4. **Reliability**: Ensure consistent behavior across scenarios

### Approach

- **Unit Testing**: Isolated component testing
- **Integration Testing**: Full authentication flow testing
- **Security Testing**: Attack simulation and vulnerability assessment
- **Regression Testing**: Prevent introduction of bugs

---

## Test Organization

```
tests/
├── test_backend.py          # Backend unit tests (15 tests)
├── test_vectors.py          # Test vectors & integration (multiple scenarios)
├── test_replay_attacks.py   # Replay attack security (8 tests)
├── test_mitm_vectors.py     # MITM attack simulation (7 tests)
└── test_xss_vectors.py      # XSS security testing (5 tests)
```

---

## Backend Unit Tests

**File**: [`test_backend.py`](file:///c:/Users/Soujatya/Desktop/ZKP/tests/test_backend.py)

### 1. Health Check Tests

#### `test_health_check`

- **What**: Verifies the health endpoint is responsive
- **How**: Sends GET request to `/health` endpoint
- **Why**: Ensures backend is running and accessible before running other tests
- **Expected**: HTTP 200 with `{"status": "ok"}`

---

### 2. Registration Tests (5 tests)

#### `test_register_success`

- **What**: Tests successful user registration
- **How**:
  - Sends POST to `/api/register` with valid username and 64-char hex public key
  - Validates response status and message
- **Why**: Verifies core registration functionality works correctly
- **Expected**: HTTP 201 with success message

#### `test_register_duplicate_user`

- **What**: Tests duplicate username prevention
- **How**:
  - Registers a user successfully
  - Attempts to register same username again
- **Why**: Ensures username uniqueness constraint is enforced
- **Expected**: First registration succeeds (201), second fails (409 Conflict)

#### `test_register_invalid_username`

- **What**: Tests username validation
- **How**: Attempts registration with username "ab" (too short, minimum is 3 chars)
- **Why**: Validates input sanitization prevents invalid usernames
- **Expected**: HTTP 400 Bad Request

#### `test_register_invalid_pubkey`

- **What**: Tests public key format validation
- **How**: Sends 63-character hex string instead of required 64 characters
- **Why**: Ensures cryptographic parameters meet Ed25519 requirements (32 bytes = 64 hex)
- **Expected**: HTTP 400 Bad Request

#### `test_register_missing_fields`

- **What**: Tests required field validation
- **How**: Sends registration request with only username, missing public_key
- **Why**: Validates API rejects incomplete requests
- **Expected**: HTTP 400 Bad Request

---

### 3. Challenge Tests (2 tests)

#### `test_get_challenge_success`

- **What**: Tests challenge generation for authentication
- **How**:
  - Registers a user first
  - Requests challenge via POST to `/api/auth/challenge`
  - Validates challenge is 64 hex characters (32 bytes)
- **Why**: Verifies server generates cryptographically random challenges for ZKP
- **Expected**: HTTP 200 with 64-character hex challenge

#### `test_get_challenge_nonexistent_user`

- **What**: Tests challenge request for non-existent user
- **How**: Requests challenge for username that doesn't exist
- **Why**: Prevents information leakage about registered usernames
- **Expected**: HTTP 404 Not Found

---

### 4. Verification Tests (3 tests)

#### `test_verify_invalid_proof`

- **What**: Tests ZKP verification with invalid proof
- **How**:
  - Registers user with public key 'a' \* 64
  - Sends proof with all zeros (V='0'*64, c='0'*64, r='0'\*64)
  - This proof won't satisfy [r]G + [c]A == V
- **Why**: Ensures cryptographic verification correctly rejects invalid proofs
- **Expected**: HTTP 401 Unauthorized or 400 Bad Request

#### `test_verify_nonexistent_user`

- **What**: Tests verification for non-registered user
- **How**: Sends valid-format proof for username that doesn't exist
- **Why**: Validates user existence check before verification
- **Expected**: HTTP 404 Not Found

#### `test_verify_invalid_proof_format`

- **What**: Tests proof format validation
- **How**: Sends proof with V component of 62 characters instead of 64
- **Why**: Ensures all proof components meet Ed25519 size requirements
- **Expected**: HTTP 400 Bad Request

---

### 5. User Info Tests (2 tests)

#### `test_get_user_info`

- **What**: Tests retrieving user information
- **How**:
  - Registers a user
  - Fetches user info via GET `/api/user/{username}`
- **Why**: Validates public user data retrieval
- **Expected**: HTTP 200 with username and created_at timestamp

#### `test_get_user_info_nonexistent`

- **What**: Tests user info for non-existent user
- **How**: Requests info for username that doesn't exist
- **Why**: Validates proper error handling
- **Expected**: HTTP 404 Not Found

---

### 6. Debug Endpoint Tests (1 test)

#### `test_debug_users`

- **What**: Tests debug endpoint for listing users
- **How**:
  - Registers a user
  - Fetches all users via GET `/api/debug/users`
- **Why**: Provides debugging capability during development
- **Expected**: HTTP 200 with users array

---

### 7. Crypto Utility Tests (2 tests)

#### `test_bytes_to_int`

- **What**: Tests byte array to integer conversion
- **How**: Converts `bytes([1, 2, 3, 4])` and validates result is `0x04030201`
- **Why**: Verifies little-endian byte order used in Ed25519
- **Expected**: Correct integer representation

#### `test_int_to_bytes`

- **What**: Tests integer to byte array conversion
- **How**: Converts `0x04030201` to bytes and validates `bytes([1, 2, 3, 4])`
- **Why**: Ensures bidirectional conversion for cryptographic operations
- **Expected**: Correct byte array

---

## Test Vectors & Integration Tests

**File**: [`test_vectors.py`](file:///c:/Users/Soujatya/Desktop/ZKP/tests/test_vectors.py)

### Schnorr Protocol Test Vectors

#### Purpose

Validates mathematical correctness of Schnorr ZKP implementation: **[r]G + [c]A == V**

#### Test Vectors Included

1. **Valid Proof Vector**

   - **What**: Tests a mathematically valid Schnorr proof
   - **How**: Provides known valid values for private key, nonce, challenge, commitment, and response
   - **Why**: Ensures verification accepts valid proofs
   - **Expected**: Verification passes

2. **Invalid Proof Vector**

   - **What**: Tests proof with incorrect response value
   - **How**: Uses response that doesn't satisfy the Schnorr equation
   - **Why**: Ensures verification rejects invalid proofs
   - **Expected**: Verification fails

3. **Zero Values Vector**
   - **What**: Tests edge case with all-zero values
   - **How**: Sets nonce, commitment, and response to zero
   - **Why**: Validates handling of edge cases
   - **Expected**: Verification fails (invalid proof)

### Integration Test Scenarios

#### Scenario 1: Complete Authentication Flow

- **What**: End-to-end test of registration → challenge → verification
- **How**:
  1. Register user with username and public key
  2. Request authentication challenge
  3. Submit ZKP proof
  4. Verify authentication succeeds
- **Why**: Validates entire authentication workflow
- **Expected**: All steps succeed with correct status codes

#### Scenario 2: Invalid Credentials

- **What**: Tests authentication with wrong credentials
- **How**: Attempts to verify with incorrect proof
- **Why**: Ensures system rejects invalid authentication attempts
- **Expected**: Verification fails

#### Scenario 3: Missing Fields

- **What**: Tests API with incomplete requests
- **How**: Sends requests missing required fields
- **Why**: Validates input validation across all endpoints
- **Expected**: HTTP 400 for all incomplete requests

---

## Replay Attack Tests

**File**: [`test_replay_attacks.py`](file:///c:/Users/Soujatya/Desktop/ZKP/tests/test_replay_attacks.py)

### Overview

Tests 8 different replay attack scenarios to ensure the system is protected against proof reuse attacks.

---

### Test 1: Proof Replay - Same Challenge

#### `test_proof_replay_same_challenge`

- **What**: Tests if the same proof can be replayed immediately with the same challenge
- **How**:
  1. Register user `testuser_replay_1`
  2. Get authentication challenge
  3. Create and send proof (V, c, r)
  4. Immediately replay the exact same proof
- **Why**: Attackers might capture valid proofs and replay them to gain unauthorized access
- **Vulnerability**: If replay succeeds, system is vulnerable to immediate replay attacks
- **Expected Behavior**: Second attempt should be rejected (proof should be single-use)
- **Severity**: MEDIUM if vulnerable

---

### Test 2: Proof Replay - Different Challenge

#### `test_proof_replay_different_challenge`

- **What**: Tests if a proof from one challenge works with a different challenge
- **How**:
  1. Get challenge1, create proof, verify
  2. Get challenge2 (different value)
  3. Replay same proof with challenge2
- **Why**: Tests if proof is cryptographically bound to the specific challenge
- **Vulnerability**: If proof works with different challenge, the challenge mechanism is broken
- **Expected Behavior**: Proof should fail with different challenge (cryptographic binding)
- **Severity**: HIGH if vulnerable
- **Note**: Schnorr protocol inherently prevents this via the equation [r]G + [c]A == V

---

### Test 3: Proof Replay - Time Delayed

#### `test_proof_replay_time_delayed`

- **What**: Tests if proof can be replayed after a time delay (5 seconds)
- **How**:
  1. Get challenge and verify proof immediately
  2. Wait 5 seconds
  3. Replay same proof
  4. Get new challenge and replay proof again
- **Why**: Tests if challenges/proofs have time-based expiration
- **Vulnerability**: If old proofs work indefinitely, attackers have unlimited time to replay
- **Expected Behavior**: Old proofs should expire after reasonable timeout
- **Severity**: MEDIUM if vulnerable
- **Mitigation**: Implement challenge expiration (e.g., 1-minute timeout)

---

### Test 4: Proof Replay - Session Reuse

#### `test_proof_replay_session_reuse`

- **What**: Tests if proof from one HTTP session works in a different session
- **How**:
  1. Create Session1, get challenge, verify proof
  2. Create Session2 (new HTTP session)
  3. Replay proof from Session1 in Session2
- **Why**: Tests if proofs are bound to specific sessions
- **Vulnerability**: If proof works across sessions, session isolation is broken
- **Expected Behavior**: Proof should be bound to originating session
- **Severity**: HIGH if vulnerable
- **Mitigation**: Bind proof to session token or request signature

---

### Test 5: Challenge Replay

#### `test_challenge_replay`

- **What**: Tests if server reuses challenges (generates duplicate challenges)
- **How**:
  1. Request 5 challenges sequentially
  2. Check if any challenges are duplicated
- **Why**: Challenge reuse enables replay attacks
- **Vulnerability**: If challenges repeat, attacker can prepare proofs in advance
- **Expected Behavior**: All challenges should be unique (cryptographically random)
- **Severity**: HIGH if vulnerable
- **Mitigation**: Use cryptographically secure random number generator

---

### Test 6: Partial Proof Replay (Modified Components)

#### `test_partial_proof_replay`

- **What**: Tests if modifying individual proof components (V, c, or r) is accepted
- **How**:
  1. Create original proof (V, c, r)
  2. Test modified V with original c, r
  3. Test modified c with original V, r
  4. Test modified r with original V, c
- **Why**: Tests cryptographic integrity of proof components
- **Vulnerability**: If modified proofs work, cryptographic verification is broken
- **Expected Behavior**: Any modification should cause verification failure
- **Severity**: MEDIUM if vulnerable
- **Note**: Ed25519 is deterministic, preventing component substitution

---

### Test 7: Concurrent Replay Attacks

#### `test_concurrent_replay`

- **What**: Tests if multiple simultaneous replay attempts succeed
- **How**:
  1. Get challenge and create proof
  2. Send 3 identical proof submissions concurrently
  3. Check how many succeed
- **Why**: Tests race conditions in proof validation
- **Vulnerability**: If multiple replays succeed, there's a race condition
- **Expected Behavior**: Only first attempt should succeed (or all should fail)
- **Severity**: HIGH if vulnerable
- **Mitigation**: Implement atomic nonce-per-request validation and rate limiting

---

### Test 8: Replay with Modified Username

#### `test_replay_with_modified_username`

- **What**: Tests if proof from one user works for a different user
- **How**:
  1. Register user1 and user2
  2. Get challenge for user1, create proof
  3. Replay proof but change username to user2
- **Why**: Tests if proof is bound to specific username
- **Vulnerability**: CRITICAL - if successful, any user can impersonate any other user
- **Expected Behavior**: Proof should fail for different username
- **Severity**: CRITICAL if vulnerable
- **Note**: Username should be part of ZKP computation

---

## MITM Attack Tests

**File**: [`test_mitm_vectors.py`](file:///c:/Users/Soujatya/Desktop/ZKP/tests/test_mitm_vectors.py)

### Overview

Simulates Man-in-the-Middle attacks to test transport security and data integrity.

---

### Test 1: HTTP Traffic Interception

#### `test_http_traffic_interception`

- **What**: Tests if traffic is readable when intercepted
- **How**:
  1. Perform registration over HTTP
  2. Capture and inspect request/response
  3. Check if sensitive data is visible
- **Why**: HTTP traffic is unencrypted and readable by attackers
- **Vulnerability**: If using HTTP, all data (including proofs) is visible
- **Expected Behavior**: System should require HTTPS in production
- **Severity**: CRITICAL if HTTP is used in production
- **Mitigation**: Enforce HTTPS, use HSTS headers

---

### Test 2: Authentication Proof Tampering

#### `test_authentication_proof_tampering`

- **What**: Tests if MITM can modify proof components in transit
- **How**:
  1. Intercept authentication request
  2. Modify proof values (V, c, r)
  3. Forward modified request to server
- **Why**: Tests integrity protection of authentication data
- **Vulnerability**: If modified proofs are accepted, integrity is compromised
- **Expected Behavior**: Modified proofs should fail cryptographic verification
- **Severity**: HIGH if vulnerable
- **Note**: Cryptographic verification provides integrity even over HTTP

---

### Test 3: Session Token Hijacking

#### `test_session_token_hijacking`

- **What**: Tests if session tokens can be stolen and reused
- **How**:
  1. User authenticates successfully
  2. Capture session token from response
  3. Use captured token in new session
- **Why**: Session tokens grant access; if stolen, attacker gains access
- **Vulnerability**: If tokens work when stolen, session hijacking is possible
- **Expected Behavior**: Tokens should be protected (HttpOnly, Secure flags)
- **Severity**: HIGH if vulnerable
- **Mitigation**: Use secure cookies, implement token binding, short expiration

---

### Test 4: Response Injection

#### `test_response_injection`

- **What**: Tests if MITM can inject fake server responses
- **How**:
  1. Intercept server response
  2. Modify response to indicate success when it failed
  3. Check if client accepts modified response
- **Why**: MITM could fake authentication success
- **Vulnerability**: Without HTTPS, responses can be modified
- **Expected Behavior**: HTTPS prevents response tampering
- **Severity**: CRITICAL if vulnerable
- **Mitigation**: Enforce HTTPS with certificate pinning

---

### Test 5: Replay Attack Detection

#### `test_replay_attack_detection`

- **What**: Tests if MITM-captured proofs can be replayed
- **How**:
  1. Capture valid authentication proof
  2. Replay proof after original session ends
- **Why**: MITM might capture and replay valid proofs
- **Vulnerability**: If replays succeed, authentication is compromised
- **Expected Behavior**: Proofs should be single-use with nonces
- **Severity**: HIGH if vulnerable
- **Mitigation**: Implement nonce validation, challenge expiration

---

### Test 6: Request Injection/Modification

#### `test_request_injection`

- **What**: Tests if MITM can inject or modify requests
- **How**:
  1. Intercept legitimate request
  2. Modify parameters (username, public_key, etc.)
  3. Forward to server
- **Why**: MITM could alter user registration or authentication
- **Vulnerability**: Without integrity protection, requests can be modified
- **Expected Behavior**: HTTPS provides integrity protection
- **Severity**: HIGH if vulnerable
- **Mitigation**: Use HTTPS, implement request signing

---

### Test 7: Security Headers Verification

#### `test_security_headers`

- **What**: Tests if proper security headers are present
- **How**:
  1. Make requests to all endpoints
  2. Check for security headers:
     - `Strict-Transport-Security` (HSTS)
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `Content-Security-Policy`
- **Why**: Security headers provide defense-in-depth
- **Vulnerability**: Missing headers increase attack surface
- **Expected Behavior**: All security headers should be present
- **Severity**: MEDIUM if missing
- **Mitigation**: Configure Flask to send security headers

---

## XSS Security Tests

**File**: [`test_xss_vectors.py`](file:///c:/Users/Soujatya/Desktop/ZKP/tests/test_xss_vectors.py)

### Overview

Tests Cross-Site Scripting (XSS) vulnerabilities across all input fields.

---

### Test 1: Registration Username Injection

#### `test_register_username_injection`

- **What**: Tests XSS via username field during registration
- **How**:
  1. Attempt registration with XSS payloads as username:
     - `<script>alert('XSS')</script>`
     - `<img src=x onerror="alert('XSS')">`
     - `<svg onload="alert('XSS')">`
  2. Check if payload is reflected in response
  3. Verify if JavaScript would execute
- **Why**: Usernames might be displayed in UI; XSS could steal sessions
- **Vulnerability**: If payload is reflected unescaped, XSS is possible
- **Expected Behavior**: Input should be sanitized or rejected
- **Severity**: HIGH if vulnerable
- **Mitigation**: Input validation, output encoding, CSP headers

---

### Test 2: Challenge Endpoint Injection

#### `test_challenge_endpoint_injection`

- **What**: Tests XSS via username in challenge request
- **How**:
  1. Request challenge with XSS payload as username
  2. Check if payload appears in error messages
- **Why**: Error messages might reflect input unsafely
- **Vulnerability**: Reflected XSS in error messages
- **Expected Behavior**: Input should be sanitized in all responses
- **Severity**: MEDIUM if vulnerable
- **Mitigation**: Sanitize all user input before reflection

---

### Test 3: Verify Endpoint Injection

#### `test_verify_endpoint_injection`

- **What**: Tests XSS via proof parameters (V, c, r, username)
- **How**:
  1. Send verification request with XSS payloads in all fields
  2. Check if any payload is reflected
- **Why**: Proof parameters might be logged or displayed
- **Vulnerability**: XSS via proof parameters
- **Expected Behavior**: All inputs should be validated and sanitized
- **Severity**: MEDIUM if vulnerable
- **Mitigation**: Strict input validation (hex format only)

---

### Test 4: CSP Headers Verification

#### `test_csp_headers`

- **What**: Tests if Content Security Policy headers are present
- **How**:
  1. Make requests to all endpoints
  2. Check for `Content-Security-Policy` header
  3. Verify CSP is restrictive (e.g., `default-src 'self'`)
- **Why**: CSP prevents XSS execution even if injection occurs
- **Vulnerability**: Missing CSP allows XSS execution
- **Expected Behavior**: Strict CSP should be enforced
- **Severity**: MEDIUM if missing
- **Mitigation**: Implement CSP: `default-src 'self'; script-src 'self'`

---

### Test 5: Input Validation & Format Enforcement

#### `test_input_validation`

- **What**: Tests if input validation prevents malicious input
- **How**:
  1. Test various invalid inputs:
     - SQL injection attempts
     - Path traversal attempts
     - Special characters
     - Extremely long strings
  2. Verify all are rejected with 400 Bad Request
- **Why**: Strict validation is first line of defense
- **Vulnerability**: Weak validation allows various attacks
- **Expected Behavior**: Only valid formats should be accepted
- **Severity**: HIGH if weak
- **Mitigation**: Whitelist validation (alphanumeric + hex only)

---

## Running Tests

### Prerequisites

```bash
# Ensure backend is running
cd backend
python app_final.py

# Backend should be accessible at http://localhost:5000
```

### Run All Tests

```bash
# From project root
pytest tests/ -v
```

### Run Specific Test Suites

#### Backend Unit Tests

```bash
pytest tests/test_backend.py -v
```

#### Test Vectors & Integration

```bash
pytest tests/test_vectors.py -v
```

#### Replay Attack Tests

```bash
pytest tests/test_replay_attacks.py -v

# Or run individual test
pytest tests/test_replay_attacks.py::TestReplayAttacks::test_proof_replay_time_delayed -v
```

#### MITM Attack Tests

```bash
pytest tests/test_mitm_vectors.py -v
```

#### XSS Security Tests

```bash
pytest tests/test_xss_vectors.py -v
```

### Run with Detailed Output

```bash
# Show print statements and detailed output
pytest tests/ -v -s

# Show full traceback on failures
pytest tests/ -v --tb=long
```

### Run with Coverage

```bash
# Install coverage
pip install pytest-cov

# Run with coverage report
pytest tests/ --cov=backend --cov-report=html
```

---

## Troubleshooting

### Common Issues

#### 1. Backend Not Reachable

**Error**: `Backend not reachable at http://localhost:5000`

**Solution**:

```bash
# Start backend server
cd backend
python app_final.py
```

#### 2. Import Errors

**Error**: `ModuleNotFoundError: No module named 'app_final'`

**Solution**:

```bash
# Install backend dependencies
cd backend
pip install -r requirements.txt
```

#### 3. Test Timeouts

**Error**: `requests.exceptions.Timeout`

**Solution**:

- Backend might be slow or overloaded
- Increase timeout in test files (default is 5 seconds)
- Check backend logs for errors

#### 4. Database Conflicts

**Error**: `Username already exists` or `409 Conflict`

**Solution**:

- Tests use unique usernames per test
- If running tests multiple times, restart backend to clear in-memory database
- Or use unique username prefixes with timestamps

#### 5. Pytest Not Found

**Error**: `pytest: command not found`

**Solution**:

```bash
pip install pytest pytest-timeout
```

---

## Test Execution Summary

### Quick Reference

| Test Suite     | File                     | Tests    | Purpose            |
| -------------- | ------------------------ | -------- | ------------------ |
| Backend Unit   | `test_backend.py`        | 15       | API functionality  |
| Test Vectors   | `test_vectors.py`        | Multiple | Crypto correctness |
| Replay Attacks | `test_replay_attacks.py` | 8        | Replay protection  |
| MITM Attacks   | `test_mitm_vectors.py`   | 7        | Transport security |
| XSS Security   | `test_xss_vectors.py`    | 5        | Input sanitization |

### Expected Results

- **All tests should PASS** in a properly configured system
- **Security tests** may show vulnerabilities that need mitigation
- **Replay attack tests** assess vulnerability levels (LOW/MEDIUM/HIGH/CRITICAL)

---

## Additional Resources

- [Main README](file:///c:/Users/Soujatya/Desktop/ZKP/README.md) - Project overview
- [Security Testing Methodology](file:///c:/Users/Soujatya/Desktop/ZKP/SECURITY_TESTING_METHODOLOGY.md) - Security testing details
- [Replay Attack Documentation](file:///c:/Users/Soujatya/Desktop/ZKP/REPLAY_ATTACK_DOCUMENTATION.md) - Detailed replay attack analysis

---

**Last Updated**: 2025-12-18
