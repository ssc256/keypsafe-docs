# Key derivation

This document describes every key derivation operation in Keypsafe: what inputs go in, what comes out, why the parameters were chosen, and what security properties each step provides.

For the full key hierarchy and how derived keys are used together, see [Crypto architecture](./crypto-architecture).

---

## Overview

Keypsafe uses two distinct key derivation mechanisms for different purposes:

| Mechanism | Used for | Implementation |
|---|---|---|
| Argon2id | Deriving a key from a user's password | `hash-wasm` (WASM) |
| HKDF-SHA256 | Deriving purpose-specific keys from high-entropy secrets | Web Crypto API |

These are not interchangeable. Argon2id is designed to be slow and memory-hard — the right tool when the input is a low-entropy human password. HKDF is designed to be fast and deterministic — the right tool when the input already has high entropy (a PRF output, a DEK, or a combined key) and you need to derive multiple independent keys from it without any one of them leaking information about the others.

---

## Argon2id — password key derivation

### What it does

Derives a 32-byte key (`kPwd`) from the user's password. This key is then combined with the recovery key to form the IKM for the pwdpk wrapping key.

### Parameters

| Parameter | Value | Meaning |
|---|---|---|
| Algorithm | Argon2id | Hybrid of Argon2i (side-channel resistant) and Argon2d (GPU resistant) |
| Version | v1.3 (0x13) | Current stable Argon2 spec version |
| Iterations (`time`) | 3 | Number of passes over memory |
| Memory | 64 MiB | Working memory required per attempt |
| Parallelism | 1 | Single-threaded (required by hash-wasm) |
| Output length | 32 bytes | Sized for use as AES-256 key material |
| Salt | 16 bytes random (`argonSalt`) | Per-vault, generated at creation, stored in DB |

### Why these parameters

**Argon2id** is the current OWASP and NIST recommendation for password hashing. The `id` variant resists both side-channel attacks (relevant for shared hosting environments) and GPU/ASIC brute-force attacks.

**64 MiB memory, 3 iterations** is the OWASP recommended minimum for Argon2id as of 2024. Each guess an attacker makes requires 64 MiB of RAM and 3 full passes. On commodity hardware this takes roughly 200–500ms per guess, making large-scale offline brute-force expensive even with many parallel machines.

**Parallelism = 1** is a constraint of `hash-wasm`, the WASM implementation used in the browser. It is not a security weakness — parallel Argon2 only helps the legitimate user (faster derivation on multi-core hardware), not the attacker (who also has to serialize through memory). With single-threaded hash-wasm, both parties are subject to the same constraint.

**Per-vault argon salt** means that deriving the password key for vault A gives an attacker nothing about vault B, even if the user used the same password for both. An attacker cannot amortize a single Argon2 computation across multiple vaults.

### The recovery key requirement

Further, `kPwd` alone does not wrap the DEK. It is concatenated with the recovery key before HKDF:

```
pwdpkIKM = kPwd ‖ recoveryKey
```

This means a correct password guess is insufficient to access secrets without the recovery key. An attacker who has the database dump and knows the user's password cannot decrypt any vaults. The recovery key contributes 256 bits of independent random entropy, so even if Argon2 were completely broken (e.g. returning a fixed output), the recovery key ensures the combined IKM remains cryptographically strong.

### Password normalization

Before the password reaches Argon2id, it is normalized via `normalizePassword()`:

```
normalizedPassword = password.normalize("NFC").trim()
```

NFC normalization ensures that visually identical characters with different Unicode representations (e.g. a composed `é` vs. `e` + combining accent) produce the same key material. Trimming removes accidental leading/trailing whitespace. This normalization is applied consistently at every point in the app where a password is used — signup, login, vault creation, key derivation, and recovery — so a password typed with or without surrounding spaces on any device always derives the same key.

### Inputs and output

```
kPwd = Argon2id(
  password    = normalizedPassword (UTF-8),
  salt        = argonSalt (16 bytes, per-vault, from DB),
  time        = 3,
  memory      = 65536 KiB (64 MiB),
  parallelism = 1,
  hashLength  = 32,
  version     = 0x13
)
```

---

## HKDF-SHA256 — purpose-specific key derivation

### What it does

HKDF (HMAC-based Key Derivation Function, RFC 5869) derives one or more cryptographically independent keys from a single high-entropy input. Keypsafe uses it to derive four distinct keys per vault, each bound to a specific purpose via an `info` string.

### Parameters

| Parameter | Value |
|---|---|
| Hash | SHA-256 |
| IKM | High-entropy secret (PRF output, combined pwd+recovery key, or DEK) |
| Salt | `kdfSalt` — 32 bytes, per-vault, generated at creation |
| Info | Purpose label string (see below) |
| Output | 256-bit AES-GCM key (non-extractable `CryptoKey`) |

### Info strings (suite 1)

Each derivation is bound to a purpose label called the `info` string. Using a different info string with the same IKM and salt produces a completely independent key. Knowing one derived key gives an attacker no information about any other.

| Key | Info string | Purpose |
|---|---|---|
| `wrapKeyPK` | `keypsafe/kek/pk/v1` | Wraps DEK using passkey PRF output |
| `wrapKeyPWDPK` | `keypsafe/kek/pwdpk/v1` | Wraps DEK using password + recovery key |
| `payloadKey` | `keypsafe/dek/payload/v1` | Encrypts vault plaintext |
| `metaKey` | `keypsafe/meta/v1` | Encrypts vault metadata |

Info strings are versioned (`/v1`) and formatted consistently (`keypsafe/{purpose}/{version}`). The suite number stored per-vault determines which set of info strings is used at decryption, allowing future changes without breaking existing vaults.

### Why HKDF instead of using the IKM directly

Using an IKM directly as an AES key has several weaknesses:

- If the same IKM is used for two different purposes, compromise of one ciphertext can leak information about the other
- PRF output and password-derived keys may have non-uniform bit distributions that HKDF corrects
- HKDF provides domain separation — keys derived for different purposes are cryptographically independent even with the same IKM

### Why the kdfSalt matters

The HKDF salt is `kdfSalt` — a 32-byte random value generated per-vault at creation and stored in the database. This provides:

- **Cross-vault isolation** — even if two vaults use the same passkey PRF output (same user, same passkey), their HKDF salts differ, so `wrapKeyPK` differs between vaults. A key extracted from one vault cannot decrypt another.
- **Defense in depth** — if HKDF's extract step has a weakness with a zero or fixed salt, the random kdfSalt eliminates that concern

The kdfSalt is not a secret; it is stored in plaintext in the database. Its purpose is domain separation, and its integrity is protected separately: a copy is stored encrypted inside the META envelope and checked during decryption using a constant-time comparison.

### Derivations in context

**Passkey path:**
```
wrapKeyPK = HKDF-SHA256(
  ikm  = prfOut (32 bytes from WebAuthn PRF extension),
  salt = kdfSalt (32 bytes, per-vault),
  info = "keypsafe/kek/pk/v1"
) → AES-256-GCM key
```

**Password + recovery key path:**
```
kPwd        = Argon2id(password, argonSalt, ...)
pwdpkIKM    = kPwd ‖ recoveryKey  (32 + 32 = 64 bytes)

wrapKeyPWDPK = HKDF-SHA256(
  ikm  = pwdpkIKM,
  salt = kdfSalt,
  info = "keypsafe/kek/pwdpk/v1"
) → AES-256-GCM key
```

**Payload encryption:**
```
payloadKey = HKDF-SHA256(
  ikm  = DEK (32 bytes, random per-vault),
  salt = kdfSalt,
  info = "keypsafe/dek/payload/v1"
) → AES-256-GCM key
```

**Metadata encryption:**
```
metaKey = HKDF-SHA256(
  ikm  = DEK,
  salt = kdfSalt,
  info = "keypsafe/meta/v1"
) → AES-256-GCM key
```

---

## PRF salt derivation

The WebAuthn PRF extension requires a per-application salt to scope the PRF output. Keypsafe's PRF salt is derived deterministically per user:

```
prfSalt = SHA-256("keypsafe/prf/{userId}")
```

This means the PRF output is stable across devices and sessions for the same user and passkey — the same passkey always produces the same PRF output for Keypsafe, which is required for deterministic key derivation. The userId scoping ensures that two different Keypsafe users with the same passkey (unlikely but possible with synced credentials) get different PRF outputs.

---

## Key properties summary

| Key | Entropy source | Derivation | Per-vault? | Stored? |
|---|---|---|---|---|
| DEK | `crypto.getRandomValues` (32 bytes) | None — raw random | Yes | Never in plaintext |
| `kdfSalt` | `crypto.getRandomValues` (32 bytes) | None — raw random | Yes | DB (plaintext) + META (encrypted) |
| `argonSalt` | `crypto.getRandomValues` (16 bytes) | None — raw random | Yes | DB (plaintext) |
| `recoveryKey` | `crypto.getRandomValues` (32 bytes) | None — raw random | No — per user, shared across vaults | META envelope (encrypted) |
| `prfOut` | Hardware authenticator | WebAuthn PRF extension | No — deterministic per user+passkey | Never |
| `kPwd` | Password + argonSalt | Argon2id | Yes (argonSalt is per-vault) | Never |
| `pwdpkIKM` | `kPwd ‖ recoveryKey` | Concatenation | Yes | Never |
| `wrapKeyPK` | prfOut + kdfSalt | HKDF | Yes | Never |
| `wrapKeyPWDPK` | pwdpkIKM + kdfSalt | HKDF | Yes | Never |
| `payloadKey` | DEK + kdfSalt | HKDF | Yes | Never |
| `metaKey` | DEK + kdfSalt | HKDF | Yes | Never |

"Never stored" keys exist only in memory during the encryption or decryption operation and are zeroed immediately after use.
