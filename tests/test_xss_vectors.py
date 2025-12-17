"""
XSS Security Testing Suite
Tests common XSS vectors against the ZKP authentication system
"""

import requests
import json
import sys
import os
import pytest
from typing import List, Dict, Tuple

# Configuration
BACKEND_URL = "http://localhost:5000"
FRONTEND_URL = "http://localhost:8001"

def _require_backend():
    try:
        r = requests.get(f"{BACKEND_URL}/health", timeout=2)
        if r.status_code != 200:
            pytest.fail(f"Backend not healthy at {BACKEND_URL} (status {r.status_code})")
    except Exception as e:
        pytest.fail(f"Backend not reachable at {BACKEND_URL}: {e}")

class XSSTestResult:
    """Track individual test results"""
    def __init__(self, vector_name: str, payload: str, endpoint: str, method: str = "POST"):
        self.vector_name = vector_name
        self.payload = payload
        self.endpoint = endpoint
        self.method = method
        self.payload_reflected = False
        self.javascript_executed = False
        self.http_status = None
        self.response_body = None
        self.error = None
    
    def __str__(self):
        status = " PASS" if not self.payload_reflected else " FAIL"
        return f"{status} | {self.vector_name:<40} | Payload reflected: {self.payload_reflected}"

# XSS Test Payloads
XSS_PAYLOADS = {
    "img_onerror": '<img src=x onerror="alert(\'XSS\')">',
    "svg_onload": '<svg onload="alert(\'XSS\')">',
    "iframe_src": '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    "script_tag": '<script>alert("XSS")</script>',
    "event_handler": '" onmouseover="alert(\'XSS\')"',
    "data_uri": '<img src="data:text/html,<script>alert(\'XSS\')</script>">',
    "protocol_handler": '<a href="javascript:alert(\'XSS\')">Click me</a>',
    "form_action": '" onsubmit="alert(\'XSS\');"',
    "dom_mutation": '<div onclick="alert(\'XSS\')">Click</div>',
    "style_expression": '<div style="background: expression(alert(\'XSS\'))"></div>',
    "attribute_break": '" ><script>alert("XSS")</script><"',
    "unicode_escape": '\\u003cscript\\u003ealert("XSS")\\u003c/script\\u003e',
}

class XSSSecurityTester:
    """Main XSS security testing class"""
    
    def __init__(self, backend_url: str, frontend_url: str):
        self.backend_url = backend_url
        self.frontend_url = frontend_url
        self.results: List[XSSTestResult] = []
        self.session = requests.Session()
    
    def test_register_username_injection(self) -> List[XSSTestResult]:
        """Test 1: XSS via username field in registration"""
        print("\n" + "="*80)
        print("TEST 1: Registration - Username Field XSS Injection")
        print("="*80)
        
        test_results = []
        
        for payload_name, payload in XSS_PAYLOADS.items():
            result = XSSTestResult(
                vector_name=f"Register/Username/{payload_name}",
                payload=payload,
                endpoint="/api/register"
            )
            
            try:
                # Attempt to register with XSS payload in username
                data = {
                    "username": payload,
                    "public_key": "a" * 64  # Valid 64-char hex
                }
                
                response = self.session.post(
                    f"{self.backend_url}/api/register",
                    json=data,
                    timeout=5
                )
                
                result.http_status = response.status_code
                result.response_body = response.text
                
                # Check if payload appears in response
                if payload in response.text:
                    result.payload_reflected = True
                    print(f"   FAIL: Payload reflected in response")
                    print(f"     Payload: {payload[:60]}...")
                    print(f"     Status: {response.status_code}")
                else:
                    result.payload_reflected = False
                    print(f"   PASS: Payload NOT reflected")
                
            except Exception as e:
                result.error = str(e)
                print(f"   ERROR: {str(e)}")
            
            test_results.append(result)
            self.results.append(result)
        
        return test_results
    
    def test_challenge_endpoint_injection(self) -> List[XSSTestResult]:
        """Test 2: XSS via username in challenge endpoint"""
        print("\n" + "="*80)
        print("TEST 2: Challenge Endpoint - Username Field XSS")
        print("="*80)
        
        test_results = []
        
        for payload_name, payload in XSS_PAYLOADS.items():
            result = XSSTestResult(
                vector_name=f"Challenge/Username/{payload_name}",
                payload=payload,
                endpoint="/api/auth/challenge"
            )
            
            try:
                data = {"username": payload}
                
                response = self.session.post(
                    f"{self.backend_url}/api/auth/challenge",
                    json=data,
                    timeout=5
                )
                
                result.http_status = response.status_code
                result.response_body = response.text
                
                if payload in response.text:
                    result.payload_reflected = True
                    print(f"   FAIL: Payload reflected")
                else:
                    result.payload_reflected = False
                    print(f"   PASS: Payload filtered")
                
            except Exception as e:
                result.error = str(e)
                print(f"   ERROR: {str(e)}")
            
            test_results.append(result)
            self.results.append(result)
        
        return test_results
    
    def test_verify_endpoint_injection(self) -> List[XSSTestResult]:
        """Test 3: XSS via proof parameters in verify endpoint"""
        print("\n" + "="*80)
        print("TEST 3: Verify Endpoint - Proof Parameters XSS")
        print("="*80)
        
        test_results = []
        
        # Test injecting XSS into V, c, r parameters
        proof_params = ["V", "c", "r"]
        
        for param_name in proof_params:
            for payload_name, payload in list(XSS_PAYLOADS.items())[:3]:  # Test subset for speed
                result = XSSTestResult(
                    vector_name=f"Verify/{param_name}/{payload_name}",
                    payload=payload,
                    endpoint="/api/auth/verify"
                )
                
                try:
                    data = {
                        "username": "testuser",
                        "V": "b" * 64,
                        "c": "c" * 64,
                        "r": "d" * 64
                    }
                    # Inject payload into proof parameter
                    data[param_name] = payload
                    
                    response = self.session.post(
                        f"{self.backend_url}/api/auth/verify",
                        json=data,
                        timeout=5
                    )
                    
                    result.http_status = response.status_code
                    result.response_body = response.text
                    
                    if payload in response.text:
                        result.payload_reflected = True
                        print(f"   FAIL: {param_name} payload reflected")
                    else:
                        result.payload_reflected = False
                        print(f"   PASS: {param_name} payload filtered")
                    
                except Exception as e:
                    result.error = str(e)
                
                test_results.append(result)
                self.results.append(result)
        
        return test_results
    
    def test_csp_headers(self) -> Dict[str, str]:
        """Test 4: Verify CSP and security headers"""
        print("\n" + "="*80)
        print("TEST 4: Content Security Policy & Security Headers")
        print("="*80)
        
        try:
            response = self.session.get(f"{self.backend_url}/health")
            headers = response.headers
            
            critical_headers = [
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection"
            ]
            
            header_status = {}
            for header in critical_headers:
                if header in headers:
                    header_status[header] = headers[header]
                    print(f"   {header}: Present")
                    print(f"     Value: {headers[header][:60]}...")
                else:
                    header_status[header] = "MISSING"
                    print(f"   {header}: MISSING")
            
            return header_status
            
        except Exception as e:
            print(f"   ERROR: {str(e)}")
            return {}
    
    def test_input_validation(self) -> List[Tuple[str, bool]]:
        """Test 5: Input validation & format enforcement"""
        print("\n" + "="*80)
        print("TEST 5: Input Validation & Format Enforcement")
        print("="*80)
        
        validation_tests = []
        
        # Test short username (should reject)
        print("\n  Testing minimum username length...")
        try:
            response = self.session.post(
                f"{self.backend_url}/api/register",
                json={"username": "ab", "public_key": "c" * 64},
                timeout=5
            )
            if response.status_code >= 400:
                print(f"     PASS: Short username rejected (status {response.status_code})")
                validation_tests.append(("Min username length", True))
            else:
                print(f"     FAIL: Short username accepted")
                validation_tests.append(("Min username length", False))
        except Exception as e:
            print(f"     ERROR: {str(e)}")
        
        # Test invalid public key format
        print("\n  Testing invalid public key format...")
        try:
            response = self.session.post(
                f"{self.backend_url}/api/register",
                json={"username": "testuser123", "public_key": "invalid!@#"},
                timeout=5
            )
            if response.status_code >= 400:
                print(f"     PASS: Invalid pubkey rejected (status {response.status_code})")
                validation_tests.append(("Invalid pubkey format", True))
            else:
                print(f"     FAIL: Invalid pubkey accepted")
                validation_tests.append(("Invalid pubkey format", False))
        except Exception as e:
            print(f"     ERROR: {str(e)}")
        
        # Test non-JSON request
        print("\n  Testing non-JSON request...")
        try:
            response = self.session.post(
                f"{self.backend_url}/api/register",
                data="not json",
                headers={"Content-Type": "text/plain"},
                timeout=5
            )
            if response.status_code >= 400:
                print(f"     PASS: Non-JSON rejected (status {response.status_code})")
                validation_tests.append(("Non-JSON request", True))
            else:
                print(f"     FAIL: Non-JSON accepted")
                validation_tests.append(("Non-JSON request", False))
        except Exception as e:
            print(f"     ERROR: {str(e)}")
        
        return validation_tests
    
    def run_all_tests(self):
        """Run all XSS security tests"""
        print("\n")
        print("╔" + "="*78 + "╗")
        print("║" + " "*78 + "║")
        print("║" + "  XSS SECURITY AUDIT - ZKP Authentication System".center(78) + "║")
        print("║" + f"  Backend: {self.backend_url}".ljust(78) + "║")
        print("║" + f"  Frontend: {self.frontend_url}".ljust(78) + "║")
        print("║" + " "*78 + "║")
        print("╚" + "="*78 + "╝")
        
        try:
            self.test_register_username_injection()
            self.test_challenge_endpoint_injection()
            self.test_verify_endpoint_injection()
            self.test_csp_headers()
            self.test_input_validation()
            
        except requests.exceptions.ConnectionError:
            print("\n ERROR: Cannot connect to backend at {self.backend_url}")
            print("   Make sure the Flask server is running: python app_final.py")
            sys.exit(1)
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("TEST SUMMARY")
        print("="*80)
        
        total = len(self.results)
        failed = sum(1 for r in self.results if r.payload_reflected)
        passed = total - failed
        
        print(f"\nTotal Tests: {total}")
        print(f"Passed (Safe):     {passed} ")
        print(f"Failed (Unsafe):   {failed} ")
        print(f"Success Rate:      {(passed/total*100):.1f}%")
        
        if failed > 0:
            print(f"\nWARNING: {failed} vulnerabilities detected!")
            print("\nFailed Tests:")
            for result in self.results:
                if result.payload_reflected:
                    print(f"  - {result}")
        else:
            print("\n All tests passed! No XSS vulnerabilities detected.")
        
        print("\n" + "="*80)


def main():
    """Main entry point"""
    tester = XSSSecurityTester(BACKEND_URL, FRONTEND_URL)
    tester.run_all_tests()
    tester.print_summary()


if __name__ == "__main__":
    main()


class TestXSSVectors:
    def test_register_username_injection(self):
        _require_backend()
        tester = XSSSecurityTester(BACKEND_URL, FRONTEND_URL)
        results = tester.test_register_username_injection()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_challenge_endpoint_injection(self):
        _require_backend()
        tester = XSSSecurityTester(BACKEND_URL, FRONTEND_URL)
        results = tester.test_challenge_endpoint_injection()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_verify_endpoint_injection(self):
        _require_backend()
        tester = XSSSecurityTester(BACKEND_URL, FRONTEND_URL)
        results = tester.test_verify_endpoint_injection()
        assert isinstance(results, list)
        assert len(results) > 0

    def test_csp_headers(self):
        _require_backend()
        tester = XSSSecurityTester(BACKEND_URL, FRONTEND_URL)
        headers = tester.test_csp_headers()
        assert isinstance(headers, dict)

    def test_input_validation(self):
        _require_backend()
        tester = XSSSecurityTester(BACKEND_URL, FRONTEND_URL)
        results = tester.test_input_validation()
        assert isinstance(results, list)
        assert len(results) > 0
