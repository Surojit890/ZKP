# ZKP-Based Web Authentication System
## Zero-Knowledge Proof Authentication with WebAssembly

A modern web authentication system where user secrets never leave their device. Uses libsodium compiled to WebAssembly for cryptographic operations in the browser, with a Python Flask backend for registration and Schnorr ZKP verification.

### Features

- **Zero-Knowledge Proof**: Schnorr protocol ensures user knows their password without revealing it
- **Client-Side Crypto**: All cryptographic operations (key derivation, ZKP computation) happen in the browser using WebAssembly
- **Ed25519 Elliptic Curve**: State-of-the-art elliptic curve cryptography
- **Password Hashing**: PBKDF2 (Argon2) key derivation prevents dictionary attacks
- **Server-Side Verification**: Backend validates proofs using only public keys, never stores passwords

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Browser (Client)                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  HTML/JavaScript UI                                      │  │
│  │  - Registration Form                                     │  │
│  │  - Login Form                                            │  │
│  │  - Status Messages                                       │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                           │                                     │
│  ┌────────────────────────▼─────────────────────────────────┐  │
│  │  libsodium.wasm (WebAssembly)                            │  │
│  │  - PBKDF2 Password Hashing (Argon2)                      │  │
│  │  - Ed25519 Key Pair Generation                           │  │
│  │  - Schnorr ZKP Computation                               │  │
│  │  - Random Number Generation                              │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                           │                                     │
│                    HTTPS REST API                               │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────────┐
│              Python Flask Backend (Server)                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  REST API Endpoints                                      │  │
│  │  - POST /api/register        (User registration)         │  │
│  │  - POST /api/auth/challenge  (Issue challenge)           │  │
│  │  - POST /api/auth/verify     (Verify proof)              │  │
│  │  - GET  /api/user/<username> (Get user info)             │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                           │                                     │
│  ┌────────────────────────▼─────────────────────────────────┐  │
│  │  Schnorr ZKP Verification                                │  │
│  │  Verifies: [r]G + [c]A == V                              │  │
│  └────────────────────────┬─────────────────────────────────┘  │
│                           │                                     │
│  ┌────────────────────────▼─────────────────────────────────┐  │
│  │  MongoDB Database                                        │  │
│  │  - Users (username, public_key, created_at)              │  │
│  │  - Challenges (username, challenge, timestamp)           │  │
│  └──────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Protocol Flow

#### Registration

1. User enters username and password
2. Browser (WASM):
   - Hash password using PBKDF2 with Argon2 → private key
   - Generate Ed25519 public key from private key
3. Send to server:
   - Username
   - Public key (hex-encoded)
4. Server stores: `{username, public_key}`

#### Login (Schnorr ZKP)

1. User enters username and password
2. Browser derives private key (same as registration)
3. Browser requests challenge from server
4. Server generates random 32-byte challenge
5. Browser computes ZKP:
   - Random nonce: `v ∈ [0, q)`
   - Commitment: `V = [v]G`
   - Response: `r = v - c*a mod q`
   - Sends to server: `{V, c, r}`
6. Server verifies: `[r]G + [c]A == V`
   - If true: User knows the private key → Authentication successful
   - If false: Invalid proof → Authentication failed

**Why it works:**
- If prover has private key `a` with public key `A = [a]G`
- And creates commitment `V = [v]G`
- And computes `r = v - c*a mod q`
- Then: `[r]G + [c]A = [v - c*a]G + [c][a]G = [v - c*a + c*a]G = [v]G = V` ✓

### Installation

#### Prerequisites
- Python 3.8+
- Node.js (for serving frontend)
- MongoDB (or use in-memory fallback)

#### Backend Setup

```bash
cd backend
pip install -r requirements.txt
```

Set environment variable:
```bash
$env:MONGODB_URI="mongodb+srv://admin:H9skGpb6jYa%2AMb%24@soujatya.gjxsm.mongodb.net"
```

Run the server:
```bash
python app_final.py
```

The backend will start on `http://localhost:5000`

#### Frontend Setup

Serve the frontend from the `frontend/` directory using any HTTP server:

```bash
cd frontend
python -m http.server 8000
```

Open `http://localhost:8000` in your browser.

### API Endpoints

#### POST /api/register
Register a new user

**Request:**
```json
{
  "username": "alice",
  "public_key": "a1b2c3d4...(64 hex chars)"
}
```

**Response (201):**
```json
{
  "message": "User registered successfully"
}
```

**Errors:**
- 400: Invalid input
- 409: Username already exists
- 500: Server error

---

#### POST /api/auth/challenge
Get authentication challenge

**Request:**
```json
{
  "username": "alice"
}
```

**Response (200):**
```json
{
  "challenge": "deadbeef...(64 hex chars)"
}
```

**Errors:**
- 404: User not found
- 500: Server error

---

#### POST /api/auth/verify
Verify ZKP authentication proof

**Request:**
```json
{
  "username": "alice",
  "V": "commitment_hex(64 chars)",
  "c": "challenge_hex(64 chars)",
  "r": "response_hex(64 chars)"
}
```

**Response (200):**
```json
{
  "message": "Authentication successful",
  "session_token": "token_hex...",
  "username": "alice"
}
```

**Errors:**
- 401: Invalid proof
- 404: User not found
- 500: Server error

---

#### GET /api/user/<username>
Get public user information

**Response (200):**
```json
{
  "username": "alice",
  "created_at": "2024-11-24T10:30:00",
  "last_login": "2024-11-24T10:35:00"
}
```

### Testing

#### Run Backend Tests

```bash
cd tests
pytest test_backend.py -v
```

#### Test Integration

```bash
pytest tests/ -v
```

### Security Considerations

1. **HTTPS Required**: Always use HTTPS in production (not HTTP)
2. **Secure Transport**: All API calls must use encrypted connections
3. **No Password Storage**: Server never stores passwords or private keys
4. **Random Nonces**: Each ZKP uses a fresh random nonce
5. **Challenge Entropy**: Server generates cryptographically secure challenges
6. **Input Validation**: All inputs are validated before use

### Limitations & Future Improvements

1. **Point Addition**: Current fallback uses hash-based verification. Production should use proper Edwards curve arithmetic library
2. **Session Management**: Implement proper JWT/session tokens with expiration
3. **Rate Limiting**: Add rate limiting to prevent brute force attacks
4. **Multi-factor Auth**: Combine with additional security factors
5. **Non-Interactive ZKP**: Implement Fiat-Shamir transformation for non-interactive proofs
6. **Database**: Migrate from in-memory to persistent MongoDB

### Project Structure

```
ZKP/
├── backend/
│   ├── app.py                 # Original Flask app
│   ├── app_v2.py              # Improved version
│   ├── app_final.py           # Production version
│   ├── requirements.txt        # Python dependencies
│   └── .env                    # Environment variables
├── frontend/
│   ├── index.html             # Main UI
│   ├── zkp-auth.js            # JavaScript logic
│   ├── styles.css             # Styling
│   └── libsodium.wasm         # (Downloaded at runtime)
├── tests/
│   ├── test_backend.py        # Backend unit tests
│   ├── test_vectors.py        # Test vectors & integration tests
│   └── conftest.py            # Pytest configuration
└── README.md                  # This file
```

### Cryptographic Details

#### Ed25519
- **Curve**: Twisted Edwards curve `a*x^2 + y^2 = 1 + d*x^2*y^2`
- **Parameters**: `a = -1`, `d = -121665/121666`
- **Order**: `q = 2^252 + 27742317777884353535851937790883648493`
- **Base Point**: `G` (standard generator)

#### Schnorr Signature Scheme (adapted for ZKP)
- **Prover**: Has private key `a`, public key `A = [a]G`
- **Commitment**: `V = [v]G` where `v` is random
- **Challenge**: `c` from verifier
- **Response**: `r = v - c*a mod q`
- **Verification**: `[r]G + [c]A == V`

#### Key Derivation
- **Function**: PBKDF2 with Argon2
- **Input**: Password (user-provided)
- **Salt**: SHA256(username + "_salt")[:16]
- **Output**: 32 bytes (Ed25519 private key seed)
- **Time Cost**: MODERATE (2^3 = 8 iterations)
- **Memory Cost**: MODERATE (65536 KB)

### References

- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [libsodium Documentation](https://doc.libsodium.org/)
- [Schnorr Signature Scheme](https://en.wikipedia.org/wiki/Schnorr_signature)
- [Zero-Knowledge Proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof)

### License

MIT License - See LICENSE file for details

### Contact

For questions or issues, please refer to the project documentation.
