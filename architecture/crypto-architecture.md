# Crypto architecture

This document describes the cryptographic design of Keypsafe: what keys exist, how they are derived, how data is encrypted, how the design resists tampering, key theft, and future algorithm changes.

---

## Design goals

- Secrets never leave the user's device in plaintext
- The database contains only ciphertext, so a full breach exposes nothing decryptable
- Two independent factors can each decrypt a vault: the passkey alone is sufficient for regular use; the password + recovery key together when the passkey is unavailable
- Every ciphertext is bound to its owner and purpose via authenticated data — transplanting an envelope into another user's vault causes decryption to fail at the cryptographic level
- The scheme is versioned so algorithm changes do not require re-encrypting all vaults at once

---

## Primitives

| Primitive | Algorithm | Implementation |
|---|---|---|
| Authenticated encryption | AES-256-GCM | Web Crypto API (`crypto.subtle`) |
| Key derivation (purpose separation) | HKDF-SHA256 | Web Crypto API (`crypto.subtle`) |
| Password key derivation | Argon2id v1.3 | `hash-wasm` (WASM module) |
| AAD hashing | SHA-256 | Web Crypto API (`crypto.subtle`) |
| Random generation | CSPRNG | `crypto.getRandomValues` |

All AES-GCM, HKDF, and SHA-256 operations use the browser's native Web Crypto API, which is implemented in constant-time native code (BoringSSL in Chrome, NSS in Firefox). Argon2id runs inside a WASM module and does not expose timing to JavaScript.

---

## Key hierarchy

The passkey factor derivation differs depending on the surface. The web app and CLI receive the raw PRF output directly from the WebAuthn ceremony and derive `wrapKeyPK` in one step. The wallet bridge adds an intermediate vault-scoped derivation before handing anything to the wallet.

**Web app / CLI**

```
passkey PRF output (userPrf)        password + recovery key
       │                                     │
       │ HKDF-SHA256                         │ Argon2id → kPwd
       │ info=keypsafe/kek/pk/v1             │ then concat: kPwd ‖ recoveryKey
       │ salt=kdfSalt                        │
       ▼                                     │ HKDF-SHA256
   wrapKeyPK                                 │ info=keypsafe/kek/pwdpk/v1
       │                                     │ salt=kdfSalt
       │                                     ▼
       │                                wrapKeyPWDPK
       │                                     │
       └──────────────┬──────────────────────┘
                      │ both wrap the same DEK
                      ▼
                     DEK  (32 bytes, random, per-vault)
                      │
              ┌───────┴────────┐
              │                │
              │ HKDF           │ HKDF
              │ info=.../meta  │ info=.../dek/payload
              │ salt=kdfSalt   │ salt=kdfSalt
              ▼                ▼
           metaKey          payloadKey
              │                │
              ▼                ▼
       META envelope     payload ciphertext
```

**Wallet bridge** (extra derivation step; `userPrf` never leaves the bridge)

```
passkey PRF output (userPrf)
       │
       │ HKDF-SHA256                    ← userPrf overwritten after this (best-effort)
       │ info=keypsafe/prf/vault/v1
       │ salt=UTF8(vaultId)
       ▼
  vaultPrf (vault-scoped IKM)           ← only this value crosses into wallet code
       │
       │ HKDF-SHA256
       │ info=keypsafe/kek/pk/v1
       │ salt=kdfSalt
       ▼
   wrapKeyPK
       │
       └──────── wraps DEK (same as above from here)
```

---

## DEK (data encryption key)

Each vault has a unique 32-byte DEK generated at creation time with `crypto.getRandomValues`. The DEK is the root key for everything in that vault:

- It wraps the vault payload via `payloadKey` (HKDF from DEK)
- It wraps the vault metadata via `metaKey` (HKDF from DEK)
- It is itself wrapped — never stored in plaintext — by two independent key-encryption keys (KEKs): one per factor (i.e. one passkey KEK, one password + recovery key KEK)

The DEK is overwritten in memory after use (best-effort in JavaScript — see [Zeroization](#zeroization)).

---

## kdfSalt

Each vault has a 32-byte `kdfSalt` generated at creation and stored in the database. Every HKDF derivation in that vault uses `kdfSalt` as the HKDF salt parameter. This means:

- Keys derived for one vault cannot be used to decrypt another vault's envelopes (different salt → different key)
- An attacker who steals a wrapping key cannot reuse it across vaults

The `kdfSalt` is also stored encrypted inside the META envelope and checked during decryption. A mismatch aborts decryption (see [Tampering protection](#tampering-protection) below).

---

## Factors

### Factor 1 — passkey PRF

WebAuthn's PRF extension produces a deterministic 32-byte output for a given passkey + salt combination. The PRF salt is `SHA-256("keypsafe/prf/{userId}")`, making it stable and user-specific.

The raw PRF output (`userPrf`) is **user-scoped** — identical for every vault. It is never given to wallets directly. Instead, the bridge derives a **vault-scoped IKM** for each vault before handing anything to the wallet:

```
vaultPrf = HKDF-SHA256(ikm=userPrf, salt=UTF8(vaultId), info="keypsafe/prf/vault/v1", len=32)
```

`vaultPrf` is the input keying material used for encryption and decryption of that vault:

```
wrapKeyPK = HKDF-SHA256(ikm=vaultPrf, salt=kdfSalt, info="keypsafe/kek/pk/v1")
DEK = AES-GCM-256-Decrypt(wrapKeyPK, pkEnvelope.ciphertext)
```

This two-layer derivation enforces a trust boundary:

- The `userPrf` (skeleton key for all vaults) stays inside the Keypsafe bridge and is overwritten after the per-vault derivation (best-effort)
- A wallet receives only `vaultPrf`, which can decrypt exactly the one vault it is scoped to
- Even a fully compromised wallet cannot derive the `userPrf` or decrypt any other vault

The WebAuthn ceremony remains a single user gesture — the per-vault HKDF runs locally inside the bridge with no additional user interaction.

The PRF output is hardware-backed on modern devices (Secure Enclave on Apple, TPM on Windows). It cannot be extracted from the authenticator and requires a user gesture (biometric data or PIN) to produce.

### Factor 2 — password + recovery key

The password is run through Argon2id to produce `kPwd`:

```
kPwd = Argon2id(password, argonSalt, time=3, mem=64MiB, parallelism=1, len=32)
```

`kPwd` is then concatenated with the recovery key (32 bytes of random entropy) to form the combined IKM:

```
pwdpkIKM = kPwd ‖ recoveryKey
wrapKeyPWDPK = HKDF-SHA256(ikm=pwdpkIKM, salt=kdfSalt, info="keypsafe/kek/pwdpk/v1")
DEK = AES-GCM-256-Decrypt(wrapKeyPWDPK, pwdpkEnvelope.ciphertext)
```

The Argon parameters (`argonSalt`, `time`, `memMiB`, `parallelism`, `version`) are stored per-vault in the database, so they can be migrated independently of the vault's encryption.

**The recovery key** is generated once at signup (32 random bytes) and stored in a dedicated system vault (`secret_type = 'paper_key'`, `vault_source = 'keypsafe'`). This vault is filtered out of all user-facing vault listings. In the wallet-bridge flow, the bridge decrypts this system vault internally during backup finalization; the recovery key never crosses into wallet code. Lost-passkey recovery happens in the Keypsafe web app or CLI rather than through the wallet bridge.

### Independence of the two factors

The two KEKs (`wrapKeyPK` and `wrapKeyPWDPK`) are derived from completely independent IKMs using different HKDF info strings, and each independently wraps the same DEK. They are alternative paths, not required together: the passkey alone can decrypt, and the password + recovery key together can decrypt. The security property is that compromising the password without the recovery key (or vice versa) leaves the pwdpk envelope unbreakable, and the two envelopes use entirely separate key material so a weakness in one path does not weaken the other.

---

## Envelopes

An **envelope** is the unit of wrapped key storage. Each vault has three:

| Envelope | Wraps | Unwrapped by |
|---|---|---|
| `pk_envelope` | DEK | passkey PRF → wrapKeyPK |
| `pwdpk_envelope` | DEK | password + recovery key → wrapKeyPWDPK |
| `meta_envelope` | Vault metadata (JSON) | DEK → metaKey |

Each envelope contains:
- `ciphertext` — the AES-GCM ciphertext (includes 16-byte auth tag)
- `nonce` — 12 bytes, randomly generated per encryption
- `aad` — authenticated additional data (see below)
- `version` — envelope format version

Envelopes are validated before decryption: version must match the expected value, nonce must be 12 bytes, and ciphertext must be at least 16 bytes (auth tag minimum).

---

## Additional authenticated data (AAD)

Every AES-GCM encryption includes AAD — data that is authenticated by the auth tag but not encrypted. If the AAD is tampered with or a ciphertext is moved to a different context, the auth tag fails and decryption is rejected.

For each envelope, the AAD is:

```
raw = "{userId}|{vaultId}|{factor}|{aadVersion}|aes-gcm-256"
AAD = SHA-256(raw)
```

Where `factor` is `"pk"`, `"pwdpk"`, `"meta"`, or `"payload"` depending on which envelope it is.

The AAD is hashed to a fixed 32 bytes before use. This means:

- A `pk_envelope` from user A cannot be transplanted into user B's vault — the userId in the AAD differs, so the auth tag fails
- A `pk_envelope` from one vault cannot be transplanted into another vault — the vaultId differs
- A `pk_envelope` cannot be substituted for a `pwdpk_envelope` — the factor label differs

The payload is bound to the META envelope's AAD (they share the same AAD bytes), so the payload and meta are cryptographically linked within a vault.

---

## Metadata envelope

The META envelope contains a JSON object with per-vault metadata:

```json
{
  "vault_label": "...",
  "created_at": "...",
  "pk_envelope_version": 1,
  "pwdpk_envelope_version": 1,
  "meta_envelope_version": 1,
  "paper_key_b64url": "...",
  "kdf_salt_b64url": "..."
}
```

Notable fields:

- `paper_key_b64url` — the vault's recovery key, stored encrypted inside the META envelope. This is how subsequent vaults recover the recovery key from the first vault during creation.
- `kdf_salt_b64url` — a copy of the per-vault KDF salt. During decryption, this value is compared to the `kdf_salt` stored in the database using a constant-time XOR comparison. A mismatch aborts decryption.

The META envelope is derived from the DEK (not from a factor directly), so it can only be decrypted after successfully unwrapping the DEK.

---

## Encryption flow (vault creation)

1. Generate `vaultId` (UUID) **before** any PRF ceremony — the vault-scoped PRF derivation needs it
2. Derive `vaultPrf = HKDF(userPrf, salt=UTF8(vaultId), info="keypsafe/prf/vault/v1")` — this is the IKM for the PK envelope
3. Overwrite `userPrf` (best-effort)
4. Generate `DEK` (32 random bytes), `kdfSalt` (32 random bytes), and `argonSalt` (16 random bytes)
5. Build AADs for each envelope from `userId` + `vaultId` + factor label
6. Derive `payloadKey` via HKDF(DEK, kdfSalt, `keypsafe/dek/payload/v1`) and encrypt plaintext
7. Derive `wrapKeyPK` via HKDF(vaultPrf, kdfSalt, `keypsafe/kek/pk/v1`) and encrypt DEK → `pk_envelope`
8. Derive `kPwd` via Argon2id(password, argonSalt); combine with `recoveryKey` → derive `wrapKeyPWDPK` via HKDF → encrypt DEK → `pwdpk_envelope`
9. Derive `metaKey` via HKDF(DEK, kdfSalt, `keypsafe/meta/v1`) and encrypt metadata JSON → `meta_envelope`
10. Overwrite DEK, vaultPrf, and intermediate keys (best-effort)
11. Persist all envelopes, nonces, AADs, Argon params, `kdfSalt`, and `suite` version to the database

---

## Decryption flow

1. Load the vault row from the database
2. Resolve the HKDF info strings from the vault's stored `suite` version (see [Suite versioning](#suite-versioning))
3. Attempt DEK unwrap via passkey path (if PRF output is available): derive `wrapKeyPK` → AES-GCM-Decrypt `pk_envelope`
4. If passkey path fails or is unavailable, attempt password+recovery key path: derive `wrapKeyPWDPK` → AES-GCM-Decrypt `pwdpk_envelope`
5. If both paths fail, throw `DECRYPT_FAIL`
6. Derive `metaKey` → decrypt `meta_envelope` → parse metadata JSON
7. Compare `meta.kdf_salt_b64url` against the database `kdf_salt` with a constant-time XOR comparison; abort if they differ
8. Derive `payloadKey` → decrypt payload ciphertext
9. Overwrite DEK (best-effort)

---

## Tampering protection

| Tamper attempt | How it is caught |
|---|---|
| Modify any ciphertext byte | AES-GCM auth tag fails |
| Modify or swap the AAD | AES-GCM auth tag fails |
| Transplant envelope from user A to user B | AAD contains userId; auth tag fails |
| Transplant envelope from vault X to vault Y | AAD contains vaultId; auth tag fails |
| Substitute a pk_envelope for a pwdpk_envelope | AAD contains factor label; auth tag fails |
| Replace kdfSalt in DB with a different value | Constant-time comparison against META copy aborts decryption |

An attacker with write access to the database can cause decryption failures (denial of service against a specific vault) but cannot silently substitute or tamper with data.

---

## Suite versioning

Every vault stores a `suite` version number in the database. All HKDF info strings and algorithm choices for that vault are resolved at runtime from a `HKDF_INFO_BY_SUITE` map keyed by suite number:

```
HKDF_INFO_BY_SUITE = {
  1: {
    KEK_PK:      "keypsafe/kek/pk/v1",
    KEK_PWDPK:   "keypsafe/kek/pwdpk/v1",
    DEK_PAYLOAD: "keypsafe/dek/payload/v1",
    META:        "keypsafe/meta/v1",
  }
}
```

This means:

- Info string changes in a future suite never break existing vaults — old vaults continue to look up suite 1 strings; new vaults use a higher-numbered suite
- Algorithm migrations are lazy: a vault is migrated on its next successful decryption (decrypt with old suite, re-encrypt with new suite)
- No big-bang migration is required; old and new suites coexist in the same database indefinitely
- An unknown suite version causes an explicit `BAD_SUITE` error rather than a silent wrong-key failure

---

## Zeroization

**JavaScript zeroization is best-effort.** The runtime does not guarantee memory layout, and the GC can copy buffers before they are overwritten. Zeroization cannot be relied upon as a hard security boundary in a JS environment.

That said, Keypsafe explicitly overwrites sensitive key material after use, which narrows the window during which an attacker reading process memory could recover key material. It is a defense-in-depth measure, not a guarantee.

| Material | Where overwritten |
|---|---|
| DEK | `decryptVault` finally block; `encryptVault` after envelope creation |
| `pwdpkKey` (kPwd ‖ recoveryKey) | `KeypsafeSDK.decryptVault` finally block |
| `recoveryKey` | `KeypsafeSDK.createVault` after encrypt completes |
| `kPwd` intermediate | `derivePwdpkKey` after combining with recovery key |
| META plaintext (during recovery key retrieval) | `recoverPaperKeyFromFirstVault` finally block |
| `userPrf` (raw WebAuthn PRF output) | Bridge `completePasskeyRequest` finally block, after vault-scoped derivation |
| `vaultPrf` (vault-scoped IKM) | Bridge after sending to wallet; `KeypsafeSDK.decryptVault` and `createVault` finally blocks |

---

## What is not protected by cryptography

- **A compromised device** — malware or a keylogger can capture the password, PRF output, or decrypted plaintext before or after Keypsafe touches it. Client-side encryption cannot protect against a compromised client.
- **A malicious JS delivery** — if Keypsafe's web app is served with modified JavaScript, secrets can be exfiltrated at the moment of decryption. The CLI eliminates this risk for the recovery path. See the [threat model](/security/threat-model) for a full discussion.
