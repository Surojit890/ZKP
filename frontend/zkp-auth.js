/**
 * ZKP Authentication Client
 * Implements Schnorr ZKP on Ed25519 using libsodium
 *
 * Note: `index.html` calls `showTab`, `handleRegister`, and `handleLogin` directly.
 * This file intentionally keeps those functions on `window` for compatibility.
 */

(function () {
    'use strict';

    // ----------------------------
    // Configuration + state
    // ----------------------------
    const API_BASE_URL = 'http://localhost:5000';
    let sodium = null;

    const dom = {
        status: () => document.getElementById('status'),
        statusInfo: () => document.getElementById('status-info'),
        tabContent: () => document.querySelectorAll('.tab-content'),
        navButtons: () => document.querySelectorAll('.nav-btn'),
        tab: (tabId) => document.getElementById(tabId),
        navBtn: (tabId) => document.getElementById(`nav-${tabId}`),
        debugArea: (area) => document.getElementById(`${area}-debug`)
    };

    // ----------------------------
    // UI helpers
    // ----------------------------
    function showTab(tabId, options = {}) {
        dom.tabContent().forEach(tab => tab.classList.remove('active'));
        dom.navButtons().forEach(btn => btn.classList.remove('active'));

        dom.tab(tabId).classList.add('active');
        dom.navBtn(tabId).classList.add('active');

        const statusEl = dom.status();
        statusEl.textContent = '';
        statusEl.className = 'status-message';

        const syncLogs = options.syncLogs !== false;
        if (syncLogs && typeof window.showLogTab === 'function') {
            if (!window.__tabSyncGuard) {
                window.__tabSyncGuard = true;
                try {
                    window.showLogTab(tabId, { syncAuth: false });
                } finally {
                    window.__tabSyncGuard = false;
                }
            }
        }
    }

    function showStatus(message, type = 'info') {
        const statusEl = dom.status();
        statusEl.textContent = message;
        statusEl.className = `status-message ${type}`;
    }

    function debug(area, message, level = 'info') {
        const debugEl = dom.debugArea(area);
        if (debugEl) {
            const line = document.createElement('div');
            line.classList.add('log-line');
            if (level) {
                line.classList.add(level);
            }
            line.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
            debugEl.appendChild(line);
            debugEl.scrollTop = debugEl.scrollHeight;
        }
        console.log(`[${area}] ${level}: ${message}`);
    }

    // ----------------------------
    // libsodium initialization
    // ----------------------------
    async function initSodium() {
        try {
            await sodium.ready;
            dom.statusInfo().textContent = 'Libsodium initialized successfully';
            console.log('Libsodium ready');
        } catch (e) {
            dom.statusInfo().textContent = 'Error initializing libsodium';
            console.error(e);
            showStatus('Failed to load cryptographic library', 'error');
        }
    }

    async function boot() {
        if (window.sodium) {
            sodium = window.sodium;
            await initSodium();
            return;
        }

        // Wait for script to load (same behavior as before: one retry after 1s)
        setTimeout(async () => {
            if (window.sodium) {
                sodium = window.sodium;
                await initSodium();
            } else {
                showStatus('Could not load libsodium. Please check your connection or local files.', 'error');
            }
        }, 1000);
    }

    // Initialize when window loads
    window.onload = boot;

    function requireSodium() {
        if (!sodium) {
            throw new Error('Cryptographic library not initialized yet');
        }
        return sodium;
    }

    // ----------------------------
    // Crypto helpers
    // ----------------------------
    function clampEd25519Scalar(bytes32) {
        const out = bytes32.slice(0, 32);
        out[0] &= 248;
        out[31] &= 127;
        out[31] |= 64;
        return out;
    }

    async function derivePrivateKey(username, password) {
        const s = requireSodium();

        // 1. Create salt from username (deterministic)
        const saltInput = `${username}_salt`;
        const hashFunction = s.crypto_hash_sha256 ? s.crypto_hash_sha256 : s.crypto_hash;
        const saltHash = hashFunction(s.from_string(saltInput));
        const salt = saltHash.slice(0, 16); // First 16 bytes for Argon2 salt

        // 2. Derive key using Argon2 (via crypto_pwhash)
        // Output: 32 bytes (Ed25519 seed)
        return s.crypto_pwhash(
            32,
            s.from_string(password),
            salt,
            s.crypto_pwhash_OPSLIMIT_MODERATE,
            s.crypto_pwhash_MEMLIMIT_MODERATE,
            s.crypto_pwhash_ALG_DEFAULT
        );
    }

    function computeProof(privateKeySeed, challengeHex) {
        const s = requireSodium();

        // Generate random nonce seed, then use it to produce a valid Ed25519 point V
        const vSeed = s.randombytes_buf(32);
        const Vpair = s.crypto_sign_seed_keypair(vSeed);
        const Vhex = s.to_hex(Vpair.publicKey);

        // Derive scalar v from seed (Ed25519 seed hashing + clamping)
        const v = clampEd25519Scalar(s.crypto_hash_sha512(vSeed).slice(0, 32));

        // Parse challenge scalar c
        const c = s.from_hex(challengeHex);

        // Derive scalar a from private key seed (Ed25519: H(seed)[:32] with clamping)
        const a = clampEd25519Scalar(s.crypto_hash_sha512(privateKeySeed).slice(0, 32));

        // r = v - c*a
        const ca = s.crypto_core_ed25519_scalar_mul(c, a);
        const r = s.crypto_core_ed25519_scalar_sub(v, ca);
        const rHex = s.to_hex(r);

        return { Vhex, rHex };
    }

    // ----------------------------
    // Network helpers
    // ----------------------------
    async function postJson(path, body) {
        const response = await fetch(`${API_BASE_URL}${path}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        let data = null;
        try {
            data = await response.json();
        } catch {
            data = null;
        }
        return { response, data };
    }

    // ----------------------------
    // Public handlers (called by HTML)
    // ----------------------------
    async function handleRegister(event) {
        event.preventDefault();

        const form = event.target;
        const username = form.username.value;
        const password = form.password.value;
        const confirm = form['password-confirm'].value;

        if (password !== confirm) {
            showStatus('Passwords do not match', 'error');
            debug('register', 'Registration failed: passwords do not match', 'error');
            return;
        }

        try {
            showStatus('Generating keys...', 'info');
            debug('register', 'Deriving private key...', 'info');

            const s = requireSodium();
            const privateKey = await derivePrivateKey(username, password);

            const keyPair = s.crypto_sign_seed_keypair(privateKey);
            const publicKey = s.to_hex(keyPair.publicKey);
            debug('register', `Public Key: ${publicKey.substring(0, 16)}...`, 'info');

            const { response, data } = await postJson('/api/register', {
                username: username,
                public_key: publicKey
            });

            if (response.ok) {
                showStatus('Registration successful! You can now login.', 'success');
                debug('register', 'Registration successful.', 'success');
                form.reset();
                setTimeout(() => showTab('login'), 1500);
            } else {
                const reason = data?.error || `HTTP ${response.status}`;
                showStatus(`Registration failed: ${reason}`, 'error');
                debug('register', `Registration failed: ${reason}`, 'error');
            }
        } catch (e) {
            console.error(e);
            showStatus(`Error: ${e.message}`, 'error');
            debug('register', `Error: ${e.message}`, 'error');
        }
    }

    async function handleLogin(event) {
        event.preventDefault();

        const form = event.target;
        const username = form.username.value;
        const password = form.password.value;

        try {
            showStatus('Starting authentication...', 'info');
            debug('login', 'Requesting challenge...', 'info');

            const { response: challengeRes, data: challengeData } = await postJson('/api/auth/challenge', { username });
            if (!challengeRes.ok) {
                const reason = challengeData?.error || `HTTP ${challengeRes.status}`;
                debug('login', `Challenge request failed: ${reason}`, 'error');
                throw new Error(reason);
            }

            const challengeHex = challengeData.challenge;
            debug('login', `Challenge: ${challengeHex.substring(0, 16)}...`, 'info');

            debug('login', 'Computing Zero-Knowledge Proof...', 'info');
            const privateKey = await derivePrivateKey(username, password);
            const { Vhex, rHex } = computeProof(privateKey, challengeHex);

            debug('login', 'Proof computed. Sending to server...', 'info');
            const { response: verifyRes, data: verifyData } = await postJson('/api/auth/verify', {
                username: username,
                V: Vhex,
                c: challengeHex,
                r: rHex
            });

            if (verifyRes.ok) {
                showStatus('Authentication Successful!', 'success');
                debug('login', 'Authentication successful.', 'success');
                if (verifyData?.session_token) {
                    debug('login', `Session Token: ${verifyData.session_token.substring(0, 16)}...`, 'success');
                }
            } else {
                const reason = verifyData?.error || `HTTP ${verifyRes.status}`;
                showStatus(`Authentication Failed: ${reason}`, 'error');
                debug('login', `Authentication failed: ${reason}`, 'error');
            }
        } catch (e) {
            console.error(e);
            showStatus(`Error: ${e.message}`, 'error');
            debug('login', `Error: ${e.message}`, 'error');
        }
    }

    // Keep global names for inline HTML event handlers
    window.showTab = showTab;
    window.showStatus = showStatus;
    window.debug = debug;
    window.handleRegister = handleRegister;
    window.handleLogin = handleLogin;
})();
