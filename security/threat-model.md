# Threat model

## Threat actors

| Actor | Capability |
|---|---|
| External attacker | No DB access, no Keypsafe infrastructure access |
| Supabase insider | Read/write access to the database |
| Keypsafe insider | Can modify server-served JS; has DB access |
| Malicious wallet developer | Can ship a malicious wallet that uses the Keypsafe SDK |
| Compromised Keypsafe infrastructure | Attacker who has gained control of Keypsafe's servers |
| User's own device | Malware, keylogger, compromised browser, or physical access |

---

## Threats and mitigations

### T1 — Database breach

**Attack:** An external attacker or Supabase insider exfiltrates the `vault` table.

**Impact without mitigations:** Full access to all user secrets.

**Mitigations:**
- All vault contents are AES-256-GCM encrypted before leaving the user's device
- The database contains only ciphertext, nonces, salts, and AADs, with no plaintext, no DEKs, no wrapping keys
- Supabase RLS restricts row access to the owning user at the DB layer

**Residual risk:** None for secrets. An attacker learns that a user has vaults and when they were created/accessed.

---

### T2 — Brute force on the password factor

**Attack:** An attacker who has the database dump attempts to brute-force a user's password to derive the `pwdpk` wrapping key.

**Impact without mitigations:** Recovery of the DEK and decryption of the vault.

**Mitigations:**
- The password is run through Argon2id (time=3, memory=64MiB) before use — making each guess computationally expensive
- The recovery key (256 bits of random entropy) is concatenated with the derived password key before HKDF, so an attacker must brute-force both simultaneously
- Without the recovery key, a correct password guess cannot unwrap the DEK

**Residual risk:** Low. A correct password guess is not sufficient to unwrap the DEK — the recovery key (256 bits of independent random entropy) must also be known. The two factors are combined before HKDF, so they must be brute-forced simultaneously. The only realistic attack requires both a weak password AND a separately compromised recovery key.

---

### T3 — Ciphertext tampering

**Attack:** An attacker with DB write access modifies a ciphertext, nonce, or swaps an envelope from one user's vault into another's.

**Impact without mitigations:** Could cause silent decryption of wrong data, or force errors that leak information.

**Mitigations:**
- AES-GCM authentication tag causes decryption to fail if ciphertext or AAD is modified
- AAD is bound to `userId` + `vaultId` + factor + version — cross-user or cross-vault transplants are rejected at the cryptographic level
- `kdf_salt` is stored both in the DB and encrypted inside the metadata envelope; a mismatch aborts decryption

**Residual risk:** An attacker can cause decryption failures (denial of service against a specific vault) but cannot silently substitute data.

---

### T4 — Malicious JS delivery

**Attack:** A Keypsafe insider or attacker who has compromised Keypsafe's infrastructure ships a modified version of the web app that exfiltrates plaintext after decryption, or captures passwords/PRF output before encryption.

**Impact without mitigations:** Full access to any secret a user decrypts during the attack window.

**Mitigations:**
- The attack requires active, ongoing compromise — it cannot retroactively decrypt historical vaults
- It is auditable: JS is served over HTTPS with observable network traffic; open-source code can be compared against what's deployed
- Only affects users who use the web app during the attack window

**Residual risk:** **This is the primary unmitigated risk in the current architecture.** Users must trust Keypsafe's JS delivery. This is a known limitation shared by all browser-based encryption products. The CLI eliminates this risk for the recovery path.

---

### T5 — Passkey credential theft

**Attack:** An attacker steals a user's WebAuthn passkey credential (e.g., via a compromised OS or authenticator).

**Impact without mitigations:** The attacker can derive `wrapKeyPK` and unwrap the DEK from the `pk_envelope`.

**Mitigations:**
- Passkey credentials are hardware-backed on most modern devices (Secure Enclave on Apple, TPM on Windows) — the private key cannot be exported
- PRF output requires a user gesture (biometric or PIN), so passive credential theft is insufficient
- Even with the PRF output, the attacker also needs the encrypted vault from the DB

**Residual risk:** A fully compromised device (OS-level) could intercept the PRF output at the moment it is used. Mitigated only by device security, not by Keypsafe.

---

### T6 — PRF delegation interception

**Attack:** An attacker intercepts the `PASSKEY_PRF_RESULT` postMessage between the Keypsafe bridge and an integrated wallet, capturing the value sent to the wallet.

**Impact without mitigations:** If the raw `userPrf` (user-scoped, unlocks all vaults) were sent, a compromised wallet or interceptor could unwrap the DEK of every vault. Combined with the encrypted vaults from the DB, the attacker would have full access.

**Mitigations:**
- The bridge **never** sends the raw `userPrf` across the postMessage boundary. Before responding, it derives a vault-scoped IKM: `vaultPrf = HKDF-SHA256(ikm=userPrf, salt=UTF8(vaultId), info="keypsafe/prf/vault/v1")`. The `userPrf` is zeroed immediately after derivation.
- The wallet receives only `vaultPrf`, which is cryptographically bound to a single `vaultId`. It cannot be used to derive keys for any other vault or to recover `userPrf`.
- `PASSKEY_PRF_REQUEST` requires a `vaultId` and the bridge shows a vault label to the user before triggering the passkey ceremony — the user can verify which vault is being accessed.
- postMessage is constrained to the extension/bridge pair; origin checking is enforced.
- The communication does not leave the device or traverse the network.

**Residual risk:** A third party on the same device — a malicious browser extension or browser plugin — could intercept the `vaultPrf` value in transit. The blast radius is bounded to one vault: the intercepted value cannot decrypt any other vault or recover `userPrf`. Interception by the wallet itself is not a distinct threat — a wallet that receives `vaultPrf` legitimately already uses it to decrypt the vault's plaintext. The real concern is an uninvited third party capturing postMessage traffic, which is constrained by origin-checking and cannot traverse the network.

---

### T7 — Malicious wallet integration

**Attack:** A malicious wallet developer uses the Keypsafe SDK to build a wallet that tricks users into backing up secrets, then exfiltrates them.

**Impact without mitigations:** A user who authorizes a malicious wallet integration could have their seed or private key stolen.

**Mitigations:**
- The wallet bridge requires user interaction — every backup requires a passkey ceremony and password entry; every restore requires a passkey ceremony
- Origin allowlisting restricts which wallets can communicate with the bridge
- Keypsafe does not control what wallets are built on top of the SDK — this is analogous to any open API being abused

**Residual risk:** Users must trust the wallets they authorize. Keypsafe can publish a registry of verified integrations.

---

### T8 — Compromised device

**Attack:** A user's device has malware, a keylogger, or a compromised browser. The attacker captures the password, recovery key, or decrypted plaintext directly from memory or input.

**Impact without mitigations:** Complete compromise regardless of cryptographic strength.

**Mitigations:** None. Client-side encryption cannot protect against a compromised client.

**Residual risk:** **Out of scope.** Device security is the user's responsibility. Keypsafe's security model assumes a trusted device.

---

### T9 — Supply chain compromise

**Attack:** A malicious or compromised npm package (e.g. `hash-wasm`) returns predictable or attacker-controlled output, weakening key derivation or encryption.

**Impact without mitigations:** A compromised `hash-wasm` could return a fixed Argon2 output, reducing the password factor to a known constant. A compromised browser vendor could weaken Web Crypto primitives.

**Mitigations:**
- `hash-wasm` is the only non-browser crypto dependency; AES-GCM and HKDF use the browser's native Web Crypto API (BoringSSL in Chrome, NSS in Firefox) which are outside npm's attack surface
- Lockfile pins exact dependency versions
- `hash-wasm` is a well-maintained library with a small, auditable WASM core

**Residual risk:** A compromised `hash-wasm` release between audits could weaken Argon2 output. However, even a fully broken Argon2 (e.g. fixed output) does not compromise vaults on its own — the recovery key (256 bits of independent random entropy) must also be known to unwrap the DEK.

---

### T10 — Side-channel attacks

**Attack:** An attacker with local code execution measures timing differences in cryptographic operations to infer key material.

**Impact without mitigations:** Partial or full key recovery.

**Mitigations:**
- AES-GCM, HKDF, and SHA-256 operations use the browser's native Web Crypto API, which are implemented in constant-time native code
- Argon2id runs in a WASM module which does not expose timing to JS
- The `kdfSalt` integrity check uses an XOR-based constant-time comparison rather than short-circuiting byte equality

**Residual risk:** JavaScript runtimes are not formally constant-time — JIT compilation and speculative execution mean timing guarantees are best-effort. A sophisticated attacker with local execution capability and many observations could potentially extract information. This risk is accepted as impractical for a browser-based application.

---

### T11 — Social engineering of Keypsafe employees

**Attack:** An attacker tricks a Keypsafe employee into granting DB access, credentials, or infrastructure access.

**Impact without mitigations:** Depends on what access is obtained.

**Mitigations:**
- DB access alone exposes only ciphertext — the same guarantee as T1. A socially engineered DB credential is no more useful than a direct breach.
- JS delivery access is the higher-value target. This maps to T4 — the mitigations and residual risk are the same.

**Residual risk:** Social engineering that results in JS delivery compromise is serious and mitigated only by auditability and open-source code, as in T4. Social engineering that results only in DB access is effectively harmless to vault contents.

---

### T12 — Physical access to an unlocked device

**Attack:** An attacker gains physical access to a device where the user is signed in to Keypsafe.

**Impact without mitigations:** Access to the Keypsafe UI and any stored session.

**Mitigations:**
- An active session alone is not sufficient to decrypt vaults. Every decryption requires either a fresh passkey gesture (biometric or PIN on a hardware-backed credential) or re-entry of the password and recovery key.
- A signed-in session only allows listing vault metadata — not reading secrets.

**Residual risk:** Low. An attacker with physical access could initiate a decryption attempt and prompt the passkey gesture, but they cannot complete it without the user's biometric data or PIN. The password+recovery key path requires both factors, neither of which is stored on the device.

### T13 — Quantum computing

#### T13a — Harvest-now-decrypt-later (HNDL)

**Attack:** An attacker exfiltrates the `vault` table today and archives it. When a sufficiently capable quantum computer becomes available, they attempt to decrypt the stored ciphertext offline. No ongoing access is required — the stolen data is enough.

**Why Keypsafe is less exposed than most systems:** Vault confidentiality does not rely on asymmetric cryptography. There is no RSA or ECC key wrapping vault secrets — the DEK is wrapped with symmetric keys derived from the passkey PRF output and the password+recovery key, both symmetric. Shor's algorithm (which breaks RSA/ECC) cannot directly decrypt vault contents from stolen DB data alone. The relevant quantum threat to ciphertext is Grover's algorithm, which attacks symmetric crypto by halving effective key length. AES-256 under Grover's retains ~128-bit post-quantum security, which NIST considers computationally infeasible.

**Mitigations:**
- All vault content is encrypted with AES-256-GCM. Grover's algorithm reduces this to an effective 128-bit security level — the NIST-recommended minimum for post-quantum symmetric encryption.
- The password+recovery key factor is fully quantum-resistant. Even if some future attack weakened the passkey path, vaults remain recoverable and re-encryptable via password+recovery key.
- The vault `suite` version field enables lazy migration — each vault can be re-encrypted with an updated algorithm on its next decryption without requiring an all-at-once migration.

**Residual risk:** Low. Symmetric encryption at AES-256 is the current NIST recommendation for quantum resistance. No action required until standards or threat landscape changes.

---

#### T13b — Passkey EC crypto broken by quantum computer

**Attack:** A sufficiently capable quantum computer uses Shor's algorithm to break the elliptic curve cryptography underlying WebAuthn passkey credentials, recovering the private key and with it the ability to forge passkey authentication.

**Impact without mitigations:** The passkey authentication mechanism is broken. A quantum attacker could impersonate users to the server, and — critically — could derive the PRF output used to wrap the `pk_envelope` DEK, decrypting any vault accessible via the passkey path.

**Mitigations:**
- The password+recovery key factor is unaffected by Shor's algorithm — Argon2id and AES-256 are both quantum-resistant. Any vault remains recoverable via this path even if the passkey factor is fully broken.
- Post-quantum passkey standards (NIST FIPS 203/204) are in active development. WebAuthn is expected to adopt them; Keypsafe's suite versioning supports algorithm migration without breaking existing vaults.

**Residual risk:** The passkey factor has a known future quantum vulnerability. The password+recovery key path provides a quantum-resistant recovery route in the interim. When post-quantum WebAuthn is available, vaults can be migrated lazily on next decryption.

---

## Summary

| Threat | Severity | Mitigated? |
|---|---|---|
| T1 — Database breach | Critical | Yes — ciphertext only in DB |
| T2 — Password brute force | High | Yes — Argon2id + recovery key |
| T3 — Ciphertext tampering | Medium | Yes — AES-GCM AAD binding |
| T4 — Malicious JS delivery | High | Partial — open source + auditability |
| T5 — Passkey credential theft | High | Partial — hardware backing; device compromise unmitigated |
| T6 — PRF delegation interception | Medium | Partial — origin checking; known design limitation |
| T7 — Malicious wallet integration | Medium | Partial — origin allowlist; user authorization required |
| T8 — Compromised device | Critical | No — out of scope |
| T9 — Supply chain compromise | High | Partial — lockfile; minimal deps; hash-wasm is only npm crypto dep |
| T10 — Side-channel attacks | Low | Partial — native crypto is constant-time; JS layer is best-effort |
| T11 — Social engineering of employees | Medium | Partial — DB access exposes only ciphertext; JS delivery access maps to T4 |
| T12 — Physical access to unlocked device | Low | Yes — decryption requires fresh passkey gesture or password + recovery key |
| T13a — Harvest-now-decrypt-later | Future | Yes — AES-256 retains 128-bit post-quantum security; no asymmetric key wrapping vault data |
| T13b — Passkey EC crypto broken | Future | Partial — password+recovery key path is quantum-resistant; passkey path requires post-quantum WebAuthn |
