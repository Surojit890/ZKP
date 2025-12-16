# ZKP Security Test Execution Walkthrough  
### A Complete, User-Friendly Guide to Running All Security Tests (Windows Only)

---

## 1. Introduction

This walkthrough explains how to run:

- XSS Tests  
- MITM Tests  
- Replay Attack Tests  
- Browser-Based XSS Console  
- Manual Penetration Checks  

All steps are consolidated from:  
- TEST_EXECUTION_GUIDE.md  
- WALKTHROUGH_TUTORIAL.md  

---

# 2. Prerequisites

| Component | Requirement |
|----------|-------------|
| Python | 3.8+ |
| Browser | Chrome / Firefox / Edge |
| Terminal | PowerShell / CMD |
| Project Structure | backend/, frontend/, tests/ |

Verify Python installation:

```powershell
python --version
```

---

# 3. Initial Setup (One-Time)

## 3.1 Navigate to Project Root

```powershell
cd C:\Downloads\ZKP\ZKP
```

---

## 3.2 Create Virtual Environment

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
```

---

## 3.3 Install Dependencies

```powershell
pip install -r backend/requirements.txt
```

---

# 4. Starting All Servers

## 4.1 Backend Server (Terminal #1)

```powershell
cd backend
.\venv\Scripts\Activate.ps1
python app_final.py
```

Expected output:

```
Running on http://127.0.0.1:5000
```

Leave this terminal running.

---

## 4.2 Frontend Server (Terminal #2)

```powershell
cd C:\Downloads\ZKP\ZKP\frontend
python -m http.server 8001
```

Expected output:

```
Serving HTTP on port 8001...
```

---

# 5. Running Automated Test Suites

Open a third PowerShell window for executing tests.

---

## 5.1 Run XSS Test Suite

```powershell
cd C:\Downloads\ZKP\ZKP
.\backend\venv\Scripts\Activate.ps1
python tests/test_xss_vectors.py
```

Expected summary:

```
Total Tests: 33
XSS Payloads Tested: 12
Endpoints Tested: 3
All Tests Passed: 33/33
Success Rate: 100%
```

---

## 5.2 Run MITM Tests

```powershell
python tests/test_mitm_vectors.py
```

Expected:

```
Total Tests: 7
HTTP Traffic Interception: HIGH (expected)
Proof Tampering: PROTECTED
Session Token Hijacking: MITIGATED
Response Injection: PROTECTED
Replay Attack: PREVENTED
Request Injection: PROTECTED
Security Headers: VERIFIED
```

---

## 5.3 Run Replay Attack Tests

```powershell
python tests/test_replay_attacks.py
```

Expected:

```
Total Tests: 8
Same Challenge Replay: PROTECTED
Different Challenge Replay: PROTECTED
Time Delayed Replay: PROTECTED
Cross-Session Replay: PROTECTED
Challenge Uniqueness: VERIFIED
Partial Proof Replay: PROTECTED
Concurrent Replays: PROTECTED
Cross-User Replay: PROTECTED
Success Rate: 8/8
```

---

# 6. Interactive XSS Console (Browser-Based)

Open the following URL in your browser:

```
http://localhost:8001/xss-testing-console.html
```

You should see:

- System status  
- Payload list  
- Live test output  
- Pass/Fail summary  

Click the "Run All Tests" button.

---

# 7. Manual XSS Testing (Optional)

Open:

```
http://localhost:8001
```

Then try entering this payload in any text field:

```html
<script>alert('XSS')</script>
```

Expected behavior:

- No popup appears  
- Input is rejected or sanitized  
- No HTML or JavaScript executes  

---

# 8. Troubleshooting

| Issue | Solution |
|------|----------|
| Backend fails to start | Verify virtual environment is activated: .\backend\venv\Scripts\Activate.ps1 |
| Port 5000 already in use | Kill existing process: netstat -ano \| findstr :5000 then taskkill /PID <PID> /F |
| Port 8001 already in use | Use different port: python -m http.server 8002 |
| HTTP traffic interception test fails | This is expected for HTTP; enable HTTPS in production |
| Tests cannot connect to backend | Ensure both backend and frontend servers are running before tests |
| XSS console shows no results | Refresh browser and verify backend is responding at http://localhost:5000/health |

---

# 9. Running All Tests Sequentially (Recommended)

For a complete security audit, run tests in this order:

```powershell
cd C:\Downloads\ZKP\ZKP
.\backend\venv\Scripts\Activate.ps1

echo "Running XSS Tests..."
python tests/test_xss_vectors.py

echo "Running MITM Tests..."
python tests/test_mitm_vectors.py

echo "Running Replay Attack Tests..."
python tests/test_replay_attacks.py

echo "All security tests completed"
```

---

# 10. Conclusion

This walkthrough provides a complete, reproducible setup for:

- 33 XSS security tests
- 7 MITM attack scenarios
- 8 Replay attack vectors
- Interactive browser-based testing console
- Real-time security validation

Your ZKP authentication system can now be tested thoroughly and consistently on any Windows machine with Python 3.8+.

