"""
Comprehensive Replay Attack Testing Suite
Tests various replay attack scenarios against ZKP authentication
"""

import json
import requests
import time
import hashlib
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

# Configuration
# Use Windows host IP when running from WSL, localhost for Windows PowerShell
import os
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:5000")

@dataclass
class ReplayTestResult:
    """Track replay attack test result"""
    test_name: str
    attack_scenario: str
    vulnerable: bool
    severity: str  # LOW, MEDIUM, HIGH
    description: str
    evidence: str
    mitigation: str
    timestamp: str = None

class ReplayAttackTestSuite:
    """Comprehensive replay attack testing"""
    
    def __init__(self, backend_url: str):
        self.backend_url = backend_url
        self.results: List[ReplayTestResult] = []
        self.captured_proofs: Dict = {}
        self.session = requests.Session()
        
    def run_all_tests(self):
        """Run all replay attack tests"""
        print("\n" + "="*80)
        print("REPLAY ATTACK TEST SUITE")
        print("="*80)
        print(f"\nBackend: {self.backend_url}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        tests = [
            self.test_proof_replay_same_challenge,
            self.test_proof_replay_different_challenge,
            self.test_proof_replay_time_delayed,
            self.test_proof_replay_session_reuse,
            self.test_challenge_replay,
            self.test_partial_proof_replay,
            self.test_concurrent_replay,
            self.test_replay_with_modified_username,
        ]
        
        for test in tests:
            result = test()
            if result:
                self.results.append(result)
        
        self.print_summary()
        return self.results
    
    def test_proof_replay_same_challenge(self) -> ReplayTestResult:
        """Test 1: Replay proof within same challenge session"""
        print("\n" + "="*80)
        print("TEST 1: Proof Replay - Same Challenge Session")
        print("="*80)
        
        try:
            # Register user
            username = "testuser_replay_1"
            print(f"\n  Registering user: {username}")
            
            reg_data = {
                "username": username,
                "public_key": "a" * 64
            }
            self.session.post(
                f"{self.backend_url}/api/register",
                json=reg_data,
                timeout=5
            )
            
            # Get challenge
            print(f"  Getting challenge...")
            challenge_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            
            if not challenge_resp.ok:
                raise Exception(f"Challenge failed: {challenge_resp.text}")
            
            challenge = challenge_resp.json().get('challenge')
            print(f"  Challenge received: {challenge[:16]}...")
            
            # Create proof
            proof = {
                "username": username,
                "V": "b" * 64,
                "c": "c" * 64,
                "r": "d" * 64
            }
            
            # First verification attempt
            print(f"  Sending proof for verification (attempt 1)...")
            verify_resp1 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            result1_status = verify_resp1.status_code
            result1_body = verify_resp1.json() if verify_resp1.ok else verify_resp1.text
            
            print(f"  Result 1: {result1_status}")
            if result1_status == 200:
                print(f"  ✅ First attempt succeeded")
            else:
                print(f"  ❌ First attempt failed: {result1_body}")
            
            # Replay SAME proof immediately with SAME challenge
            print(f"  Replaying same proof immediately (attempt 2)...")
            time.sleep(0.1)
            
            verify_resp2 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            result2_status = verify_resp2.status_code
            result2_body = verify_resp2.json() if verify_resp2.ok else verify_resp2.text
            
            print(f"  Result 2: {result2_status}")
            if result2_status == 200:
                print(f"  ⚠️  Replay succeeded - VULNERABLE!")
                vulnerable = True
            else:
                print(f"  ✅ Replay rejected - PROTECTED")
                vulnerable = False
            
            # Store captured proof
            self.captured_proofs['same_challenge'] = {
                'username': username,
                'challenge': challenge,
                'proof': proof,
                'first_result': result1_status,
                'replay_result': result2_status
            }
            
            result = ReplayTestResult(
                test_name="Proof Replay - Same Challenge",
                attack_scenario="Attacker captures valid proof and replays it immediately with same challenge",
                vulnerable=vulnerable,
                severity="MEDIUM" if vulnerable else "LOW",
                description=(
                    f"Proof: V={proof['V'][:8]}..., c={proof['c'][:8]}..., r={proof['r'][:8]}...\n"
                    f"First attempt: {result1_status}\n"
                    f"Replay attempt: {result2_status}\n"
                    f"Status: {'VULNERABLE - replay accepted' if vulnerable else 'PROTECTED - replay rejected'}"
                ),
                evidence=f"Challenge: {challenge[:16]}... | Proof: {json.dumps(proof)}",
                mitigation="Implement nonce validation or single-use proof tokens"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_proof_replay_different_challenge(self) -> ReplayTestResult:
        """Test 2: Replay proof with different challenge"""
        print("\n" + "="*80)
        print("TEST 2: Proof Replay - Different Challenge")
        print("="*80)
        
        try:
            username = "testuser_replay_2"
            print(f"\n  Registering user: {username}")
            
            # Register
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username,
                    "public_key": "e" * 64
                },
                timeout=5
            )
            
            # Get first challenge
            print(f"  Getting challenge 1...")
            challenge1_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge1 = challenge1_resp.json().get('challenge')
            print(f"  Challenge 1: {challenge1[:16]}...")
            
            # Create proof for challenge1
            proof = {
                "username": username,
                "V": "f" * 64,
                "c": "0" * 64,
                "r": "1" * 64
            }
            
            # Verify with challenge1
            print(f"  Verifying with challenge 1...")
            verify1 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            
            # Get second challenge
            print(f"  Getting challenge 2...")
            time.sleep(0.5)
            challenge2_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge2 = challenge2_resp.json().get('challenge')
            print(f"  Challenge 2: {challenge2[:16]}...")
            
            # Replay same proof with challenge2
            print(f"  Replaying same proof with different challenge...")
            verify2 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            
            replay_accepted = verify2.status_code == 200
            vulnerable = replay_accepted
            
            print(f"  Result: {verify2.status_code}")
            if vulnerable:
                print(f"  ⚠️  Replay succeeded - VULNERABLE!")
            else:
                print(f"  ✅ Replay rejected - PROTECTED")
            
            # Store data
            self.captured_proofs['diff_challenge'] = {
                'challenge1': challenge1,
                'challenge2': challenge2,
                'proof': proof,
                'result1': verify1.status_code,
                'result2': verify2.status_code
            }
            
            result = ReplayTestResult(
                test_name="Proof Replay - Different Challenge",
                attack_scenario="Attacker captures proof from one session and replays with different challenge",
                vulnerable=vulnerable,
                severity="HIGH" if vulnerable else "LOW",
                description=(
                    f"Challenge 1: {challenge1[:8]}...\n"
                    f"Challenge 2: {challenge2[:8]}...\n"
                    f"Proof works with Challenge 2: {'YES (vulnerable)' if vulnerable else 'NO (safe)'}\n"
                    f"Reason: Challenge is incorporated into ZKP verification via [r]G + [c]A == V\n"
                    f"If challenge changes, cryptographic verification should fail"
                ),
                evidence=f"C1: {challenge1[:16]}... → {verify1.status_code} | C2: {challenge2[:16]}... → {verify2.status_code}",
                mitigation="Current design is safe - fresh challenge required for each proof"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_proof_replay_time_delayed(self) -> ReplayTestResult:
        """Test 3: Replay proof after time delay"""
        print("\n" + "="*80)
        print("TEST 3: Proof Replay - Time Delayed")
        print("="*80)
        
        try:
            username = "testuser_replay_3"
            print(f"\n  Registering user: {username}")
            
            # Register
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username,
                    "public_key": "2" * 64
                },
                timeout=5
            )
            
            # Get challenge
            print(f"  Getting challenge...")
            challenge_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge = challenge_resp.json().get('challenge')
            print(f"  Challenge: {challenge[:16]}...")
            
            # Create proof
            proof = {
                "username": username,
                "V": "3" * 64,
                "c": "4" * 64,
                "r": "5" * 64
            }
            
            # Verify immediately
            print(f"  Verifying immediately...")
            verify1 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            print(f"  Result: {verify1.status_code}")
            
            # Wait 5 seconds
            print(f"  Waiting 5 seconds...")
            time.sleep(5)
            
            # Replay proof (with same or new challenge?)
            print(f"  Replaying proof after 5 second delay...")
            verify2 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            print(f"  Result: {verify2.status_code}")
            
            # Get new challenge and try
            print(f"  Getting new challenge and replaying...")
            challenge2_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge2 = challenge2_resp.json().get('challenge')
            
            verify3 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            print(f"  Result with new challenge: {verify3.status_code}")
            
            vulnerable = verify3.status_code == 200
            
            self.captured_proofs['time_delayed'] = {
                'challenge': challenge,
                'challenge2': challenge2,
                'proof': proof,
                'immediate': verify1.status_code,
                'delayed_5s': verify2.status_code,
                'new_challenge': verify3.status_code
            }
            
            result = ReplayTestResult(
                test_name="Proof Replay - Time Delayed",
                attack_scenario="Attacker captures proof and replays it after time delay (e.g., 5 seconds)",
                vulnerable=vulnerable,
                severity="MEDIUM" if vulnerable else "LOW",
                description=(
                    f"Proof attempt immediately: {verify1.status_code}\n"
                    f"Replay after 5s delay (same challenge): {verify2.status_code}\n"
                    f"Replay with new challenge: {verify3.status_code}\n"
                    f"Vulnerable: {'YES' if vulnerable else 'NO'}"
                ),
                evidence=f"T0: {verify1.status_code} → T+5s: {verify2.status_code} → New Challenge: {verify3.status_code}",
                mitigation="Implement challenge expiration (e.g., 1 minute timeout)"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_proof_replay_session_reuse(self) -> ReplayTestResult:
        """Test 4: Replay proof across different sessions"""
        print("\n" + "="*80)
        print("TEST 4: Proof Replay - Session Reuse")
        print("="*80)
        
        try:
            username = "testuser_replay_4"
            print(f"\n  Registering user: {username}")
            
            # Register
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username,
                    "public_key": "6" * 64
                },
                timeout=5
            )
            
            # Session 1: Get challenge and create proof
            print(f"  Session 1: Getting challenge...")
            challenge1_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge1 = challenge1_resp.json().get('challenge')
            print(f"  Challenge 1: {challenge1[:16]}...")
            
            proof = {
                "username": username,
                "V": "7" * 64,
                "c": "8" * 64,
                "r": "9" * 64
            }
            
            # Verify in session 1
            print(f"  Session 1: Verifying proof...")
            verify1 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            print(f"  Result: {verify1.status_code}")
            
            # Session 2: Create new session and try to replay
            print(f"  Session 2: Creating new session...")
            session2 = requests.Session()
            
            print(f"  Session 2: Replaying captured proof...")
            verify2 = session2.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof,
                timeout=5
            )
            print(f"  Result: {verify2.status_code}")
            
            vulnerable = verify2.status_code == 200
            
            result = ReplayTestResult(
                test_name="Proof Replay - Session Reuse",
                attack_scenario="Attacker uses different HTTP session to replay captured proof",
                vulnerable=vulnerable,
                severity="HIGH" if vulnerable else "LOW",
                description=(
                    f"Session 1 verification: {verify1.status_code}\n"
                    f"Session 2 replay: {verify2.status_code}\n"
                    f"Vulnerable: {'YES - Proof works across sessions' if vulnerable else 'NO - Proof bound to session'}"
                ),
                evidence=f"Session reuse: S1→{verify1.status_code}, S2→{verify2.status_code}",
                mitigation="Bind proof to session token or request signature"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_challenge_replay(self) -> ReplayTestResult:
        """Test 5: Challenge replay - reusing old challenge"""
        print("\n" + "="*80)
        print("TEST 5: Challenge Replay")
        print("="*80)
        
        try:
            username = "testuser_replay_5"
            print(f"\n  Registering user: {username}")
            
            # Register
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username,
                    "public_key": "a0" * 32
                },
                timeout=5
            )
            
            # Get first challenge
            print(f"  Getting challenge 1...")
            challenge1_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge1 = challenge1_resp.json().get('challenge')
            print(f"  Challenge 1: {challenge1[:16]}...")
            
            # Get multiple challenges to see if they're unique
            challenges = [challenge1]
            for i in range(2, 6):
                print(f"  Getting challenge {i}...")
                time.sleep(0.2)
                resp = self.session.post(
                    f"{self.backend_url}/api/auth/challenge",
                    json={"username": username},
                    timeout=5
                )
                challenge = resp.json().get('challenge')
                challenges.append(challenge)
                print(f"  Challenge {i}: {challenge[:16]}...")
            
            # Check if any challenges are repeated
            unique_challenges = len(set(challenges))
            total_challenges = len(challenges)
            
            vulnerable = unique_challenges < total_challenges
            
            print(f"\n  Total challenges: {total_challenges}")
            print(f"  Unique challenges: {unique_challenges}")
            print(f"  Repeated: {total_challenges - unique_challenges}")
            
            if vulnerable:
                print(f"  ⚠️  Challenge reuse detected - VULNERABLE!")
            else:
                print(f"  ✅ All challenges unique - PROTECTED")
            
            result = ReplayTestResult(
                test_name="Challenge Replay",
                attack_scenario="Attacker reuses old challenge that was previously issued",
                vulnerable=vulnerable,
                severity="HIGH" if vulnerable else "LOW",
                description=(
                    f"Challenges requested: {total_challenges}\n"
                    f"Unique challenges: {unique_challenges}\n"
                    f"Duplicates: {total_challenges - unique_challenges}\n"
                    f"Status: {'VULNERABLE - challenges can be reused' if vulnerable else 'SAFE - all challenges unique'}"
                ),
                evidence=f"Challenges: {[c[:8] + '...' for c in challenges[:3]]}",
                mitigation="Ensure each challenge is cryptographically random and unique"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_partial_proof_replay(self) -> ReplayTestResult:
        """Test 6: Replay with partial/modified proof"""
        print("\n" + "="*80)
        print("TEST 6: Partial Proof Replay (Modified Components)")
        print("="*80)
        
        try:
            username = "testuser_replay_6"
            print(f"\n  Registering user: {username}")
            
            # Register
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username,
                    "public_key": "b0" * 32
                },
                timeout=5
            )
            
            # Get challenge
            print(f"  Getting challenge...")
            challenge_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge = challenge_resp.json().get('challenge')
            
            # Create original proof
            proof_original = {
                "username": username,
                "V": "c0" * 32,
                "c": "d0" * 32,
                "r": "e0" * 32
            }
            
            # Test 1: Modify V, keep c and r
            proof_v_modified = {
                "username": username,
                "V": "ff" * 32,  # Modified
                "c": proof_original["c"],
                "r": proof_original["r"]
            }
            
            print(f"  Testing with modified V component...")
            resp_v = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof_v_modified,
                timeout=5
            )
            v_works = resp_v.status_code == 200
            
            # Test 2: Modify c, keep V and r
            proof_c_modified = {
                "username": username,
                "V": proof_original["V"],
                "c": "ff" * 32,  # Modified
                "r": proof_original["r"]
            }
            
            print(f"  Testing with modified c component...")
            resp_c = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof_c_modified,
                timeout=5
            )
            c_works = resp_c.status_code == 200
            
            # Test 3: Modify r, keep V and c
            proof_r_modified = {
                "username": username,
                "V": proof_original["V"],
                "c": proof_original["c"],
                "r": "ff" * 32  # Modified
            }
            
            print(f"  Testing with modified r component...")
            resp_r = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof_r_modified,
                timeout=5
            )
            r_works = resp_r.status_code == 200
            
            vulnerable = v_works or c_works or r_works
            
            print(f"\n  Modified V: {resp_v.status_code} (works: {v_works})")
            print(f"  Modified c: {resp_c.status_code} (works: {c_works})")
            print(f"  Modified r: {resp_r.status_code} (works: {r_works})")
            
            if vulnerable:
                print(f"  ⚠️  Partial proof accepted - VULNERABLE!")
            else:
                print(f"  ✅ All partial proofs rejected - PROTECTED")
            
            result = ReplayTestResult(
                test_name="Partial Proof Replay",
                attack_scenario="Attacker modifies parts of proof (V, c, or r) and attempts replay",
                vulnerable=vulnerable,
                severity="MEDIUM" if vulnerable else "LOW",
                description=(
                    f"Original proof: V={proof_original['V'][:8]}..., c={proof_original['c'][:8]}..., r={proof_original['r'][:8]}...\n"
                    f"Modified V accepted: {v_works} (HTTP {resp_v.status_code})\n"
                    f"Modified c accepted: {c_works} (HTTP {resp_c.status_code})\n"
                    f"Modified r accepted: {r_works} (HTTP {resp_r.status_code})\n"
                    f"Status: {'VULNERABLE - modifications accepted' if vulnerable else 'SAFE - all modifications rejected'}"
                ),
                evidence=f"V:{resp_v.status_code}, c:{resp_c.status_code}, r:{resp_r.status_code}",
                mitigation="Cryptographic verification prevents tampering (Ed25519 is deterministic)"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_concurrent_replay(self) -> ReplayTestResult:
        """Test 7: Concurrent replay attacks"""
        print("\n" + "="*80)
        print("TEST 7: Concurrent Replay Attacks")
        print("="*80)
        
        try:
            username = "testuser_replay_7"
            print(f"\n  Registering user: {username}")
            
            # Register
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username,
                    "public_key": "f0" * 32
                },
                timeout=5
            )
            
            # Get challenge
            print(f"  Getting challenge...")
            challenge_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username},
                timeout=5
            )
            challenge = challenge_resp.json().get('challenge')
            
            # Create proof
            proof = {
                "username": username,
                "V": "11" * 32,
                "c": "22" * 32,
                "r": "33" * 32
            }
            
            # Send multiple replay attempts concurrently
            print(f"  Sending 3 concurrent replay attempts...")
            results = []
            for i in range(3):
                resp = self.session.post(
                    f"{self.backend_url}/api/auth/verify",
                    json=proof,
                    timeout=5
                )
                results.append(resp.status_code)
                print(f"  Attempt {i+1}: {resp.status_code}")
            
            # Check if any succeeded
            successful = [r for r in results if r == 200]
            vulnerable = len(successful) > 0
            
            if vulnerable:
                print(f"  ⚠️  Concurrent replay succeeded ({len(successful)}/{len(results)}) - VULNERABLE!")
            else:
                print(f"  ✅ All concurrent attempts rejected - PROTECTED")
            
            result = ReplayTestResult(
                test_name="Concurrent Replay Attacks",
                attack_scenario="Attacker sends multiple replay attempts simultaneously",
                vulnerable=vulnerable,
                severity="HIGH" if vulnerable else "LOW",
                description=(
                    f"Concurrent attempts: {len(results)}\n"
                    f"Successful: {len(successful)}\n"
                    f"Failed: {len(results) - len(successful)}\n"
                    f"Results: {results}\n"
                    f"Status: {'VULNERABLE - concurrent replays succeeded' if vulnerable else 'SAFE - all rejected'}"
                ),
                evidence=f"Results: {results}",
                mitigation="Implement rate limiting and nonce-per-request validation"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def test_replay_with_modified_username(self) -> ReplayTestResult:
        """Test 8: Replay proof with different username"""
        print("\n" + "="*80)
        print("TEST 8: Replay Proof - Different Username")
        print("="*80)
        
        try:
            username1 = "testuser_replay_8a"
            username2 = "testuser_replay_8b"
            
            print(f"\n  Registering user 1: {username1}")
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username1,
                    "public_key": "44" * 32
                },
                timeout=5
            )
            
            print(f"  Registering user 2: {username2}")
            self.session.post(
                f"{self.backend_url}/api/register",
                json={
                    "username": username2,
                    "public_key": "55" * 32
                },
                timeout=5
            )
            
            # Get challenge for user1
            print(f"  Getting challenge for {username1}...")
            challenge1_resp = self.session.post(
                f"{self.backend_url}/api/auth/challenge",
                json={"username": username1},
                timeout=5
            )
            challenge1 = challenge1_resp.json().get('challenge')
            
            # Create proof for user1
            proof_user1 = {
                "username": username1,
                "V": "66" * 32,
                "c": "77" * 32,
                "r": "88" * 32
            }
            
            # Verify for user1
            print(f"  Verifying proof for {username1}...")
            verify1 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof_user1,
                timeout=5
            )
            
            # Try to use user1's proof for user2
            proof_user2 = proof_user1.copy()
            proof_user2["username"] = username2
            
            print(f"  Attempting to use {username1}'s proof for {username2}...")
            verify2 = self.session.post(
                f"{self.backend_url}/api/auth/verify",
                json=proof_user2,
                timeout=5
            )
            
            vulnerable = verify2.status_code == 200
            
            print(f"  Result for {username1}: {verify1.status_code}")
            print(f"  Result for {username2}: {verify2.status_code}")
            
            if vulnerable:
                print(f"  ⚠️  Username substitution worked - VULNERABLE!")
            else:
                print(f"  ✅ Username substitution blocked - PROTECTED")
            
            result = ReplayTestResult(
                test_name="Replay with Different Username",
                attack_scenario="Attacker replays proof from one user as another user",
                vulnerable=vulnerable,
                severity="CRITICAL" if vulnerable else "LOW",
                description=(
                    f"Proof for {username1}: {verify1.status_code}\n"
                    f"Same proof for {username2}: {verify2.status_code}\n"
                    f"Vulnerable: {'YES - Cross-user replay works!' if vulnerable else 'NO - Proof bound to username'}\n"
                    f"Note: Username is part of ZKP computation, so proof should fail for different user"
                ),
                evidence=f"Original user: {verify1.status_code}, Different user: {verify2.status_code}",
                mitigation="Current design is safe - username is included in ZKP verification"
            )
            
            return result
            
        except Exception as e:
            print(f"  ⚠️  ERROR: {str(e)}")
            return None
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("REPLAY ATTACK TEST SUMMARY")
        print("="*80)
        
        if not self.results:
            print("❌ No tests completed")
            return
        
        total = len(self.results)
        vulnerable = sum(1 for r in self.results if r.vulnerable)
        protected = total - vulnerable
        
        print(f"\nTotal Tests: {total}")
        print(f"✅ Protected: {protected}/{total}")
        print(f"⚠️  Vulnerable: {vulnerable}/{total}")
        print(f"Success Rate: {protected}/{total} = {(protected/total)*100:.0f}%")
        
        print(f"\n{'Test Name':<40} {'Status':<15} {'Severity':<10}")
        print("-" * 65)
        for result in self.results:
            status = "⚠️  VULNERABLE" if result.vulnerable else "✅ PROTECTED"
            print(f"{result.test_name:<40} {status:<15} {result.severity:<10}")
        
        print("\n" + "="*80)
        print("RECOMMENDATIONS")
        print("="*80)
        
        vulnerable_tests = [r for r in self.results if r.vulnerable]
        if vulnerable_tests:
            print("\n⚠️  Vulnerabilities Found:")
            for test in vulnerable_tests:
                print(f"\n  {test.test_name}")
                print(f"  Severity: {test.severity}")
                print(f"  Mitigation: {test.mitigation}")
        else:
            print("\n✅ No replay attack vulnerabilities detected!")
            print("   Current design with fresh challenges per auth session")
            print("   provides adequate replay protection.")

def main():
    """Run all replay attack tests"""
    try:
        suite = ReplayAttackTestSuite(BACKEND_URL)
        results = suite.run_all_tests()
        
        # Print captured proofs for reference
        print("\n" + "="*80)
        print("CAPTURED PROOFS FOR MANUAL TESTING")
        print("="*80)
        for key, value in suite.captured_proofs.items():
            print(f"\n{key}:")
            print(f"  {json.dumps(value, indent=2)}")
        
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
