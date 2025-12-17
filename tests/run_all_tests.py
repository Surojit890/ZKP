#!/usr/bin/env python3
"""
Master Test Runner for ZKP Authentication System
Runs all tests (unit tests + security tests) in sequence
"""

import subprocess
import sys
import os
from datetime import datetime
from pathlib import Path

# Colors for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    """Print formatted header"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{text.center(80)}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*80}{Colors.ENDC}\n")

def print_section(text):
    """Print section header"""
    print(f"\n{Colors.BOLD}{Colors.OKBLUE}{text}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}{'-'*80}{Colors.ENDC}")

def run_command(cmd, description, cwd=None):
    """Run a command and return success status"""
    print(f"\n{Colors.OKCYAN}Running: {description}{Colors.ENDC}")
    print(f"Command: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=False,  # Show output in real-time
            text=True
        )
        
        if result.returncode == 0:
            print(f"{Colors.OKGREEN}✓ {description} - PASSED{Colors.ENDC}")
            return True
        else:
            print(f"{Colors.FAIL}✗ {description} - FAILED (exit code: {result.returncode}){Colors.ENDC}")
            return False
            
    except Exception as e:
        print(f"{Colors.FAIL}✗ {description} - ERROR: {str(e)}{Colors.ENDC}")
        return False

def check_server_running():
    """Check if backend server is running"""
    import requests
    try:
        response = requests.get('http://localhost:5000/health', timeout=2)
        return response.status_code == 200
    except:
        return False

def main():
    """Main test runner"""
    start_time = datetime.now()
    
    print_header("ZKP Authentication System - Complete Test Suite")
    print(f"Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Get project root
    project_root = Path(__file__).parent.parent
    tests_dir = Path(__file__).parent
    
    # Track results
    results = {}
    
    # 1. Run pytest unit tests
    print_section("1. Unit Tests (pytest)")
    results['unit_tests'] = run_command(
        [sys.executable, '-m', 'pytest', 'tests/test_backend.py', '-v'],
        "Backend Unit Tests",
        cwd=project_root
    )
    
    # 2. Check if server is running for integration tests
    print_section("2. Checking Backend Server Status")
    server_running = check_server_running()
    
    if server_running:
        print(f"{Colors.OKGREEN}✓ Backend server is running on http://localhost:5000{Colors.ENDC}")
    else:
        print(f"{Colors.WARNING}⚠ Backend server is NOT running{Colors.ENDC}")
        print(f"{Colors.WARNING}  Security tests require the backend server to be running.{Colors.ENDC}")
        print(f"{Colors.WARNING}  Start it with: python backend/app_final.py{Colors.ENDC}")
        
        response = input(f"\n{Colors.BOLD}Continue with security tests anyway? (y/n): {Colors.ENDC}")
        if response.lower() != 'y':
            print(f"\n{Colors.WARNING}Skipping security tests.{Colors.ENDC}")
            print_summary(results, start_time, skipped_security=True)
            return
    
    # 3. Run MITM attack tests
    print_section("3. MITM Attack Simulation Tests")
    results['mitm_tests'] = run_command(
        [sys.executable, 'test_mitm_vectors.py'],
        "MITM Security Tests",
        cwd=tests_dir
    )
    
    # 4. Run replay attack tests
    print_section("4. Replay Attack Tests")
    results['replay_tests'] = run_command(
        [sys.executable, 'test_replay_attacks.py'],
        "Replay Attack Tests",
        cwd=tests_dir
    )
    
    # 5. Run XSS security tests
    print_section("5. XSS Security Tests")
    results['xss_tests'] = run_command(
        [sys.executable, 'test_xss_vectors.py'],
        "XSS Security Tests",
        cwd=tests_dir
    )
    
    # Print summary
    print_summary(results, start_time)

def print_summary(results, start_time, skipped_security=False):
    """Print test summary"""
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print_header("Test Summary")
    
    total_suites = len(results)
    passed_suites = sum(1 for v in results.values() if v)
    failed_suites = total_suites - passed_suites
    
    print(f"Total Test Suites: {total_suites}")
    print(f"{Colors.OKGREEN}Passed: {passed_suites}{Colors.ENDC}")
    if failed_suites > 0:
        print(f"{Colors.FAIL}Failed: {failed_suites}{Colors.ENDC}")
    
    if skipped_security:
        print(f"{Colors.WARNING}Skipped: Security tests (server not running){Colors.ENDC}")
    
    print(f"\nDuration: {duration:.2f} seconds")
    print(f"Completed: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Detailed results
    print(f"\n{Colors.BOLD}Detailed Results:{Colors.ENDC}")
    print("-" * 80)
    
    test_names = {
        'unit_tests': 'Backend Unit Tests',
        'mitm_tests': 'MITM Attack Tests',
        'replay_tests': 'Replay Attack Tests',
        'xss_tests': 'XSS Security Tests'
    }
    
    for key, name in test_names.items():
        if key in results:
            status = f"{Colors.OKGREEN}✓ PASSED{Colors.ENDC}" if results[key] else f"{Colors.FAIL}✗ FAILED{Colors.ENDC}"
            print(f"{name:.<50} {status}")
    
    print("=" * 80)
    
    # Overall status
    if failed_suites == 0 and not skipped_security:
        print(f"\n{Colors.BOLD}{Colors.OKGREEN}🎉 ALL TESTS PASSED! 🎉{Colors.ENDC}")
        sys.exit(0)
    elif failed_suites == 0 and skipped_security:
        print(f"\n{Colors.BOLD}{Colors.WARNING}⚠ UNIT TESTS PASSED (Security tests skipped){Colors.ENDC}")
        sys.exit(0)
    else:
        print(f"\n{Colors.BOLD}{Colors.FAIL}❌ SOME TESTS FAILED{Colors.ENDC}")
        sys.exit(1)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Tests interrupted by user{Colors.ENDC}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Colors.FAIL}Unexpected error: {str(e)}{Colors.ENDC}")
        sys.exit(1)
