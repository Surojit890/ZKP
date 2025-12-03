/**
 * ZKP Authentication Client
 * Implements Schnorr ZKP on Ed25519 using libsodium
 */

// UI State Management
function showTab(tabId) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });

    // Show selected tab
    document.getElementById(tabId).classList.add('active');
    document.getElementById(`nav-${tabId}`).classList.add('active');

    // Clear messages
    document.getElementById('status').textContent = '';
    document.getElementById('status').className = 'status-message';
}

function showStatus(message, type = 'info') {
    const statusEl = document.getElementById('status');
    statusEl.textContent = message;
    statusEl.className = `status-message ${type}`;
}

function debug(area, message) {
    const debugEl = document.getElementById(`${area}-debug`);
    if (debugEl) {
        const line = document.createElement('div');
        line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        debugEl.appendChild(line);
        debugEl.scrollTop = debugEl.scrollHeight;
    }
    console.log(`[${area}] ${message}`);
}

// Crypto Functions
const API_BASE_URL = 'http://localhost:5000';
let sodium;

async function initSodium() {
    try {
        await sodium.ready;
        document.getElementById('status-info').textContent = 'Libsodium initialized successfully';
        console.log('Libsodium ready');
    } catch (e) {
        document.getElementById('status-info').textContent = 'Error initializing libsodium';
        console.error(e);
        showStatus('Failed to load cryptographic library', 'error');
    }
}

// Initialize when window loads
window.onload = async function () {
    if (window.sodium) {
        sodium = window.sodium;
        await initSodium();
    } else {
        // Wait for script to load
        setTimeout(async () => {
            if (window.sodium) {
                sodium = window.sodium;
                await initSodium();
            } else {
                showStatus('Could not load libsodium. Please check your connection or local files.', 'error');
            }
        }, 1000);
    }
};

async function derivePrivateKey(username, password) {
    // 1. Create salt from username (deterministic)
    const saltInput = username + "_salt";
    // Use SHA-256 if available, otherwise SHA-512 (crypto_hash)
    const hashFunction = sodium.crypto_hash_sha256 ? sodium.crypto_hash_sha256 : sodium.crypto_hash;
    const saltHash = hashFunction(sodium.from_string(saltInput));
    const salt = saltHash.slice(0, 16); // First 16 bytes for Argon2 salt

    // 2. Derive key using Argon2 (via crypto_pwhash)
    // Output: 32 bytes (Ed25519 seed)
    const privateKey = sodium.crypto_pwhash(
        32,                             // Output length
        sodium.from_string(password),   // Password
        salt,                           // Salt
        sodium.crypto_pwhash_OPSLIMIT_MODERATE,
        sodium.crypto_pwhash_MEMLIMIT_MODERATE,
        sodium.crypto_pwhash_ALG_DEFAULT
    );

    return privateKey;
}

async function handleRegister(event) {
    event.preventDefault();
    const form = event.target;
    const username = form.username.value;
    const password = form.password.value;
    const confirm = form['password-confirm'].value;

    if (password !== confirm) {
        showStatus('Passwords do not match', 'error');
        return;
    }

    try {
        showStatus('Generating keys...', 'info');
        debug('register', 'Deriving private key...');

        const privateKey = await derivePrivateKey(username, password);

        // Generate public key
        const keyPair = sodium.crypto_sign_seed_keypair(privateKey);
        const publicKey = sodium.to_hex(keyPair.publicKey);

        debug('register', `Public Key: ${publicKey.substring(0, 16)}...`);

        // Send to server
        const response = await fetch(`${API_BASE_URL}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                public_key: publicKey
            })
        });

        const data = await response.json();

        if (response.ok) {
            showStatus('Registration successful! You can now login.', 'success');
            form.reset();
            setTimeout(() => showTab('login'), 1500);
        } else {
            showStatus(`Registration failed: ${data.error}`, 'error');
        }

    } catch (e) {
        console.error(e);
        showStatus(`Error: ${e.message}`, 'error');
    }
}

async function handleLogin(event) {
    event.preventDefault();
    const form = event.target;
    const username = form.username.value;
    const password = form.password.value;

    try {
        showStatus('Starting authentication...', 'info');
        debug('login', 'Requesting challenge...');

        // 1. Get Challenge
        const challengeRes = await fetch(`${API_BASE_URL}/api/auth/challenge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        const challengeData = await challengeRes.json();

        if (!challengeRes.ok) {
            throw new Error(challengeData.error || 'Failed to get challenge');
        }

        const challengeHex = challengeData.challenge;
        debug('login', `Challenge: ${challengeHex.substring(0, 16)}...`);

        // 2. Compute ZKP
        debug('login', 'Computing Zero-Knowledge Proof...');

        const privateKey = await derivePrivateKey(username, password);

        // Clamp private key (a)
        // or rely on libsodium if it exposes scalar arithmetic.
        // libsodium.js exposes `crypto_core_ed25519_scalar_sub` etc.

        // Generate random nonce (v)
        // We use a seed to generate an Ed25519 point V = [v]G
        // This ensures V is a valid Ed25519 point.
        const v_seed = sodium.randombytes_buf(32);
        const V_pair = sodium.crypto_sign_seed_keypair(v_seed);
        const V = V_pair.publicKey;
        const V_hex = sodium.to_hex(V);

        // Derive scalar v from seed (same logic as private key)
        const h_v = sodium.crypto_hash_sha512(v_seed);
        const v = h_v.slice(0, 32);
        v[0] &= 248;
        v[31] &= 127;
        v[31] |= 64;

        // Parse challenge (c)
        const c = sodium.from_hex(challengeHex);

        // a = clamped private key
        // We need to derive the scalar 'a' from the seed 'privateKey'
        // Ed25519 private key is H(seed)[:32] with clamping
        const h = sodium.crypto_hash_sha512(privateKey);
        const a_bytes = h.slice(0, 32);
        a_bytes[0] &= 248;
        a_bytes[31] &= 127;
        a_bytes[31] |= 64;

        // r = v - c*a
        // We use crypto_core_ed25519_scalar_* functions

        // c * a
        const ca = sodium.crypto_core_ed25519_scalar_mul(c, a_bytes);

        // v - ca
        const r = sodium.crypto_core_ed25519_scalar_sub(v, ca);
        const r_hex = sodium.to_hex(r);

        debug('login', 'Proof computed. Sending to server...');

        // 3. Verify
        const verifyRes = await fetch(`${API_BASE_URL}/api/auth/verify`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username: username,
                V: V_hex,
                c: challengeHex,
                r: r_hex
            })
        });

        const verifyData = await verifyRes.json();

        if (verifyRes.ok) {
            showStatus('Authentication Successful!', 'success');
            debug('login', `Session Token: ${verifyData.session_token.substring(0, 16)}...`);
            // Store token if needed
        } else {
            showStatus(`Authentication Failed: ${verifyData.error}`, 'error');
        }

    } catch (e) {
        console.error(e);
        showStatus(`Error: ${e.message}`, 'error');
    }
}
