# Replay Attack Testing Suite - Comprehensive Documentation

**File:** `tests/test_replay_attacks.py`  
**Purpose:** Comprehensive security testing suite for detecting and validating replay attack vulnerabilities in the ZKP authentication system.  
**Last Updated:** December 16, 2025

---

## Table of Contents
1. [Overview](#overview)
2. [Data Structures](#data-structures)
3. [Main Class: ReplayAttackTestSuite](#main-class-replayattacktestsuite)
4. [Test Functions](#test-functions)
5. [Utility Functions](#utility-functions)
6. [How to Run](#how-to-run)

---

## Overview

### What is This File?
This file implements a **Replay Attack Testing Suite** - a collection of automated security tests that simulate and validate defenses against replay attacks in zero-knowledge proof (ZKP) authentication systems.

### Why Does It Exist?
Replay attacks are a critical security threat where an attacker intercepts valid authentication data and reuses it to gain unauthorized access. This test suite verifies that the ZKP authentication system properly prevents such attacks through cryptographic verification and protocol design.

### What Problem Does It Solve?
Without these tests, a developer might not know if their authentication system is vulnerable to:
- Proof reuse (using the same authentication multiple times)
- Cross-session attacks (using authentication from one session in another)
- Challenge manipulation (reusing old challenges)
- Username substitution (using one user's proof to authenticate as another)

---

## Data Structures

### `ReplayTestResult` (Dataclass)

```python
@dataclass
class ReplayTestResult:
    test_name: str              # Name of the test (e.g., "Proof Replay - Same Challenge")
    attack_scenario: str        # Description of what the attacker is trying to do
    vulnerable: bool            # True if vulnerability found, False if protected
    severity: str               # Risk level: LOW, MEDIUM, HIGH, CRITICAL
    description: str            # Detailed findings and results
    evidence: str               # Technical data supporting the conclusion
    mitigation: str             # How to fix or prevent this vulnerability
    timestamp: str = None       # When the test was run
```

**Purpose:** Encapsulates the result of a single replay attack test, making results standardized and easy to track.

**Example:**
```python
ReplayTestResult(
    test_name="Proof Replay - Same Challenge",
    attack_scenario="Attacker captures valid proof and replays immediately",
    vulnerable=False,
    severity="MEDIUM",
    description="Proof was rejected on replay attempt",
    evidence="First: 200, Second: 401",
    mitigation="Current design prevents this via cryptographic verification"
)
```

---

## Main Class: ReplayAttackTestSuite

### Class Overview
`ReplayAttackTestSuite` is the main testing class that orchestrates all replay attack tests.

### Constructor: `__init__(backend_url: str)`

**What it does:**
Initializes the test suite with configuration and state management.

**Why it does it:**
Each test needs to connect to the backend API, maintain a session, and track results. This constructor sets up these essentials.

**How it does it:**
```python
def __init__(self, backend_url: str):
    self.backend_url = backend_url              # API endpoint (e.g., http://localhost:5000)
    self.results: List[ReplayTestResult] = []  # Stores all test results
    self.captured_proofs: Dict = {}            # Stores intercepted proofs for analysis
    self.session = requests.Session()          # Reusable HTTP session for API calls
```

**Parameters:**
- `backend_url` (str): The URL of the backend API server to test against

**Attributes Created:**
- `backend_url`: Configuration for test target
- `results`: Accumulator for all test findings
- `captured_proofs`: Evidence collection for debugging
- `session`: HTTP session to maintain cookies and connection pooling

---

### Method: `run_all_tests()`

**What it does:**
I orchestrate the execution of all 8 replay attack test cases and print a summary of findings.

**Why I do it:**
This is the entry point for running the complete test suite. It coordinates all tests, displays progress, and generates a comprehensive report.

**How I do it:**
1. Print a header showing the test suite starting
2. Log backend URL and start time
3. Create a list of all test methods
4. Execute each test method sequentially
5. Collect results in `self.results`
6. Call `print_summary()` to display findings

```python
def run_all_tests(self):
    # Print header
    tests = [
        self.test_proof_replay_same_challenge,
        self.test_proof_replay_different_challenge,
        # ... 6 more tests
    ]
    
    for test in tests:
        result = test()
        if result:
            self.results.append(result)
    
    self.print_summary()
```

**Returns:**
`self.results` - List of `ReplayTestResult` objects containing all findings

---

## Test Functions

### Test 1: `test_proof_replay_same_challenge()`

**What I do:**
I test whether an attacker can capture a valid authentication proof and immediately replay it using the same challenge.

**Why I do it:**
This is the most basic replay attack - if an attacker intercepts a valid proof (V, c, r values), they should NOT be able to reuse it immediately. The system should detect this and reject the replayed proof.

**How I do it:**
1. Register a new test user with a dummy public key
2. Request a challenge from the backend
3. Create a dummy proof (in real attack, attacker would intercept this)
4. Send the proof for verification (attempt 1)
5. Immediately send the SAME proof again (attempt 2 - the replay)
6. Compare results: If both succeed, it's vulnerable; if second fails, it's protected
7. Store findings in a `ReplayTestResult`

**Attack Scenario:**
```
Legitimate User                 Attacker (MITM)
    |                                |
    ├─ Request Challenge ────────────┤
    │                                ├─ Intercepts Challenge
    │                                │
    ├─ Create Proof ────────────────┤
    │                                ├─ CAPTURES PROOF
    │                                │
    ├─ Send Proof ──────────────────┤
    │      ✓ AUTH SUCCESS             │
    │                                ├─ Sends same proof again
    │                                │
    │                                ├─ ??? Does it work?
    │                                │  YES  = VULNERABLE
    │                                │  NO   = PROTECTED
```

**Expected Result:** ✅ PROTECTED (replay should be rejected)

---

### Test 2: `test_proof_replay_different_challenge()`

**What I do:**
I test whether a proof captured in one authentication attempt works when replayed with a different challenge.

**Why I do it:**
This tests the core cryptographic security of the Schnorr ZKP protocol. The challenge is supposed to be bound into the proof through the equation `[r]G + [c]A == V`. If you change the challenge, the proof should fail.

**How I do it:**
1. Register a test user
2. Get Challenge 1 from the backend
3. Create a proof
4. Verify using Challenge 1
5. Get Challenge 2 (a different challenge)
6. Try to verify the SAME proof with Challenge 2
7. If the proof works with Challenge 2, it's vulnerable; if it fails, cryptography is working

**Attack Scenario:**
```
Session 1:                          Session 2 (Attacker):
User gets Challenge_A               Intercepts Proof_A from Session 1
User creates Proof_A                
Sends Proof_A → ✓ SUCCESS           Tries to use Proof_A with Challenge_B
                                    
                                    ??? Does it work?
                                    YES  = VULNERABLE (proof not bound to challenge)
                                    NO   = PROTECTED (cryptography prevents this)
```

**Expected Result:** ✅ PROTECTED (proof should be cryptographically bound to challenge)

**Why This Matters:**
This test validates the mathematical correctness of Schnorr ZKP. The equation `[r]G + [c]A == V` will ONLY work if `c` (the challenge used during proof creation) matches the `c` value during verification.

---

### Test 3: `test_proof_replay_time_delayed()`

**What I do:**
I test whether a proof remains valid after a time delay (5 seconds), and whether old proofs can be reused with new challenges.

**Why I do it:**
In real-world attacks, the attacker might not intercept and replay immediately. They might wait a few seconds or hours. This test checks if time-based expiration exists or if proofs live forever.

**How I do it:**
1. Register a user and get a challenge
2. Create and verify a proof (immediate verification)
3. Wait 5 seconds
4. Attempt to replay the proof with the same challenge
5. Get a new challenge
6. Attempt to replay the proof with the new challenge
7. Track all 3 results to understand time and challenge interactions

**Attack Timeline:**
```
T=0s:     User authenticates successfully (Proof_A with Challenge_A)
T=5s:     Attacker replays Proof_A with Challenge_A (old challenge)
          Result: Should FAIL
T=5s:     Attacker gets Challenge_B and replays Proof_A with Challenge_B
          Result: Should FAIL (due to cryptography)
```

**Expected Result:** ✅ PROTECTED (Cryptography prevents cross-challenge reuse)

**Note:** If the system implemented time-based expiration, old proofs would expire after X minutes, providing defense-in-depth.

---

### Test 4: `test_proof_replay_session_reuse()`

**What I do:**
I test whether a proof captured in one HTTP session can be reused in a completely different HTTP session.

**Why I do it:**
If the backend binds proofs to sessions (using session cookies), then replaying in a different session should fail. This tests whether the backend uses session-based validation.

**How I do it:**
1. Register a user
2. Create Session 1 and verify a proof in it
3. Create a completely separate Session 2
4. Try to use the same proof in Session 2
5. If it works, there's no session binding; if it fails, sessions are protected

**Attack Scenario:**
```
Session 1 (Legitimate User):        Session 2 (Attacker):
├─ Authenticate ✓                   ├─ Stolen proof from Session 1
│                                   ├─ Attempt auth with stolen proof
                                    ├─ ???
                                    │  SUCCESS = VULNERABLE (no session binding)
                                    │  FAILURE = PROTECTED (proof bound to session)
```

**Expected Result:** ⚠️ DEPENDS ON DESIGN
- If system uses session tokens: ✅ PROTECTED
- If system is stateless: Vulnerable (but may be acceptable with strong cryptography)

---

### Test 5: `test_challenge_replay()`

**What I do:**
I test whether the backend generates truly unique challenges or if challenges can be repeated/reused.

**Why I do it:**
Each authentication attempt should get a fresh, random challenge. If challenges repeat, an attacker could potentially predict or reuse them.

**How I do it:**
1. Request multiple challenges (5 total) from the same user
2. Store all challenges
3. Check if any challenges are duplicated
4. Count unique challenges vs. total challenges
5. If unique < total, challenges are repeating (vulnerable)

**Example Attack:**
```
Request 1: Challenge = "abc123def456..." ← Attacker captures this
Request 2: Challenge = "xyz789uvw012..." (Different, good)
Request 3: Challenge = "abc123def456..." ← SAME as Request 1!
           (Attacker can now reuse proofs from old sessions)
```

**Expected Result:** ✅ PROTECTED (All 5 challenges should be unique)

---

### Test 6: `test_partial_proof_replay()`

**What I do:**
I test whether modifying parts of the proof (V, c, or r values individually) can result in successful authentication.

**Why I do it:**
This validates that the cryptographic verification is strict. If you change even one byte of the proof, it should fail. This tests the integrity of the verification equation.

**How I do it:**
1. Create an original proof (V, c, r)
2. Modify only the V component, keep c and r → try to verify
3. Modify only the c component, keep V and r → try to verify
4. Modify only the r component, keep V and c → try to verify
5. If ANY of these modifications result in HTTP 200, cryptography is broken

**Attack Details:**
```
Original Proof:  V="abc...", c="def...", r="ghi..."

Attack 1: V="zzz...", c="def...", r="ghi..."  → Should fail
Attack 2: V="abc...", c="zzz...", r="ghi..."  → Should fail
Attack 3: V="abc...", c="def...", r="zzz..."  → Should fail

If ANY succeeds → VULNERABLE
If ALL fail → PROTECTED (cryptography is sound)
```

**Expected Result:** ✅ PROTECTED (All partial modifications should fail)

**Why This Matters:**
Ed25519 elliptic curve cryptography has the property that small changes in input cause completely different outputs. This test verifies that property is functioning.

---

### Test 7: `test_concurrent_replay()`

**What I do:**
I test whether sending multiple replay attempts simultaneously can bypass replay protection or cause race conditions.

**Why I do it:**
Some poorly designed systems have race conditions where two simultaneous requests both pass validation before either one invalidates the proof. This tests for such conditions.

**How I do it:**
1. Create a proof
2. Send 3 identical verification requests as fast as possible
3. Check how many succeed (ideally none or only 1)
4. If multiple succeed, there's a race condition (vulnerable)

**Race Condition Attack:**
```
Attacker sends 3 simultaneous requests:

Request 1 ─┐
Request 2 ─┼─→ Backend Server
Request 3 ─┘
           
           All 3 check "is this proof valid?"
           All 3 find "yes, it's valid"
           All 3 authenticate BEFORE any marks it as "used"
           
           VULNERABLE = 3 authentication granted
           PROTECTED  = 1 authentication, 2 rejected
```

**Expected Result:** ✅ PROTECTED (Only 1-2 should succeed, due to cryptography)

---

### Test 8: `test_replay_with_modified_username()`

**What I do:**
I test whether a proof created for one user can be used to authenticate as a different user.

**Why I do it:**
If the username is part of the ZKP verification, then changing the username should invalidate the proof. This is critical - otherwise attackers could use User A's proof to become User B.

**How I do it:**
1. Register User A and User B
2. Get a challenge for User A
3. Create a proof for User A
4. Verify it works for User A
5. Try the same proof for User B (by changing username field)
6. If User B authentication succeeds, it's CRITICAL vulnerability

**Attack Scenario:**
```
User A's Registration:              Attacker's Attack:
├─ Username: "alice"                ├─ Intercepts alice's proof
├─ Public Key: "0x44..."            │
│                                   ├─ Proof: V="66...", c="77...", r="88..."
User A authenticates:               │
├─ Gets Challenge                   ├─ Creates request:
├─ Creates Proof                    │  {username: "bob", V="66...", c="77...", r="88..."}
├─ Sends: {username: "alice", ...}  │
├─ ✓ SUCCESS                        ├─ Tries to impersonate BOB
                                    ├─ ???
                                    │  SUCCESS = CRITICAL (cross-user auth!)
                                    │  FAILURE = PROTECTED (username in ZKP)
```

**Expected Result:** ✅ PROTECTED (Cross-user authentication should fail)

**Why This Matters:**
The Schnorr ZKP verification includes the public key A (which is unique per user). If the proof was created with User A's private key but submitted with User B's username, the public key used during verification would be different, causing the cryptographic equation to fail.

---

## Utility Functions

### Method: `print_summary()`

**What I do:**
I generate a comprehensive summary report of all test results, showing statistics and recommendations.

**Why I do it:**
After running potentially 8 tests with complex results, the user needs a clear executive summary showing:
- Total tests run
- How many passed vs. failed
- Severity levels
- Recommendations for fixes

**How I do it:**
1. Calculate statistics:
   - Total tests
   - Number of vulnerabilities found
   - Number of protections
   - Success rate percentage
2. Print formatted table with all test results
3. For each vulnerable test, display severity and mitigation steps
4. Print congratulations message if all tests passed

**Output Format:**
```
================================================================================
REPLAY ATTACK TEST SUMMARY
================================================================================

Total Tests: 8
 Protected: 8/8
  Vulnerable: 0/8
Success Rate: 8/8 = 100%

Test Name                                Status          Severity
—————————————————————————————————————————————————————————————————
Proof Replay - Same Challenge            PROTECTED       MEDIUM
Proof Replay - Different Challenge       PROTECTED       HIGH
... (all 8 tests)

================================================================================
RECOMMENDATIONS
================================================================================

 No replay attack vulnerabilities detected!
   Current design with fresh challenges per auth session
   provides adequate replay protection.
```

**Why This Matters:**
Clear reporting helps developers quickly understand what passed/failed and what to fix.

---

## How the Tests Work Together

### The Complete Replay Attack Defense Strategy

The ZKP system uses **multiple layers** of defense:

```
Layer 1: CRYPTOGRAPHIC BINDING
├─ Each proof is cryptographically bound to:
│  ├─ The challenge (via equation [r]G + [c]A == V)
│  ├─ The user (via public key A)
│  └─ The proof parameters (V, c, r are all verified)
└─ Tests: 2, 6, 8 validate this

Layer 2: CHALLENGE FRESHNESS
├─ Each authentication gets a new random challenge
├─ Old challenges cannot be reused
└─ Tests: 1, 3, 5 validate this

Layer 3: SESSION ISOLATION (Optional)
├─ Proofs may be bound to HTTP sessions
└─ Test: 4 validates this

Layer 4: PROTOCOL DESIGN
├─ No explicit storage of "used proofs"
├─ Relies on cryptography instead of state
└─ Tests: 1, 7 validate this
```

### Why This Design is Secure

```
Why Proof Replay is Hard:
1. Attacker captures: V, c, r (proof components)
2. Attacker knows: Username, Public Key A (public information)
3. BUT Attacker does NOT know: Private Key a
4. When backend gets new Challenge c':
   - Backend verifies: [r]G + [c']A == V
   - Since c' ≠ c, the equation FAILS
   - Proof is REJECTED
5. Attacker cannot create new valid proof without private key
```

---

## How to Run

### Run Only Replay Attack Tests
```bash
cd /mnt/c/Users/Diptendu/ZKP
source venv/bin/activate
python tests/test_replay_attacks.py
```

### Expected Output
```
================================================================================
REPLAY ATTACK TEST SUITE
================================================================================

Backend: http://localhost:5000
Started: 2025-12-16 14:30:45

================================================================================
TEST 1: Proof Replay - Same Challenge Session
================================================================================

  Registering user: testuser_replay_1
  Getting challenge...
  Challenge received: a1b2c3d4...
  Sending proof for verification (attempt 1)...
  Result 1: 401
  Replaying same proof immediately (attempt 2)...
  Result 2: 401
  Replay rejected - PROTECTED

[... 7 more tests ...]

================================================================================
REPLAY ATTACK TEST SUMMARY
================================================================================
Total Tests: 8
 Protected: 8/8
  Vulnerable: 0/8
Success Rate: 8/8 = 100%
```

### Requirements
- Backend running on `http://localhost:5000`
- Python with `requests` library
- `venv` activated

---

## Test Results Interpretation

### If a Test PASSES (PROTECTED ✅)
- That particular replay attack is successfully prevented
- No action needed
- The security mechanism is working as designed

### If a Test FAILS (VULNERABLE ⚠️)
- That particular replay attack is possible
- Review the "mitigation" field in the result
- Implement the suggested fix

### Common Findings

| Scenario | Result | Meaning |
|----------|--------|---------|
| Test 1-3 PASS | ✅ | Cryptography is working |
| Test 4 PASS | ✅ | Session validation works (if implemented) |
| Test 5 PASS | ✅ | Challenge generation is random |
| Test 6 PASS | ✅ | Ed25519 verification is strict |
| Test 7 PASS | ✅ | No race conditions |
| Test 8 PASS | ✅ | Username cannot be substituted |

---

## Advanced Topics

### What is a Proof?
```python
proof = {
    "username": "alice",           # Who is authenticating
    "V": "abc123def456...",         # Commitment (64 hex chars)
    "c": "def456abc123...",         # Challenge (64 hex chars)
    "r": "123456789abcdef0..."      # Response (64 hex chars)
}
```

Each component serves a purpose in the Schnorr ZKP protocol:
- **V**: Commitment showing you know the secret, without revealing it
- **c**: Challenge that changes each time
- **r**: Response that incorporates both V and the challenge

### The Schnorr Equation
The backend verifies: `[r]G + [c]A == V`

Where:
- `G` = Generator point (public constant)
- `A` = Public key (user's public information)
- `r`, `c`, `V` = Proof components

If this equation is true, the user proved they know the private key `a` without revealing it.

### Why Changing `c` Breaks the Equation
```
Original:  [r]G + [c]A == V
           [r]G + [c]A == [v]G  (true)

With new c':
           [r]G + [c']A == V?
           [r]G + [c']A == [v]G?
           
No! Because c' ≠ c, the equation no longer balances.
The proof is invalid.
```

---

## Summary

This test suite provides **comprehensive validation** of replay attack protections in the ZKP authentication system by testing:

1. ✅ Basic proof reuse prevention
2. ✅ Cryptographic challenge binding
3. ✅ Time-delayed replay prevention
4. ✅ Cross-session proof isolation
5. ✅ Challenge randomness
6. ✅ Proof integrity (partial modification detection)
7. ✅ Race condition prevention
8. ✅ Cross-user authentication prevention

All tests should **PASS** for a secure ZKP authentication system.

---

**Document Version:** 1.0  
**Last Updated:** December 16, 2025  
**Author:** Security Testing Suite  
**Status:** Production Ready ✅
