# System architecture

## Overview

Keypsafe is a client-side encrypted vault system for storing crypto wallet secrets (seeds, private keys). Encryption and decryption happen entirely on the user's device, while the backend stores only ciphertext. The server cannot read user secrets even with full database access.

The system has three user-facing surfaces: a **web app**, a **CLI recovery tool**, and a **wallet SDK** that is designed to support any platform — browser extension, mobile app, desktop app — to add encrypted backup and restore without sending plaintext off-device.

---

## Applications

### Web app

The primary user interface. Built with Vite + React.

**Key routes:**

| Route | Purpose |
|---|---|
| `/login` | Supabase auth |
| `/encrypt` | Create and encrypt a new vault |
| `/decrypt` | Decrypt and view a stored vault |
| `/settings` | Manage vaults, reset factors, delete account |
| `/wallet-bridge` | postMessage relay for wallets (unprotected by design) |

All routes except `/wallet-bridge` are protected by a `RequireAuth` guard. The bridge is intentionally unguarded — wallets are not user accounts; the bridge's job is to accept encrypted payloads and store them after an auth check.

### CLI

A standalone decryption tool with no network dependency. Takes an exported backup JSON and prompts interactively for the password and recovery key (hidden input, never passed as arguments). Intended as a last-resort recovery path if the web app is unavailable.

```bash
# Recommended — writes to a file, nothing appears on screen:
node recover.js backup.json --output secret.txt

# Explicit terminal output — clears screen + scrollback after confirmation:
node recover.js backup.json --stdout
```

Secrets are never accepted via command-line arguments (shell history / `ps aux` exposure). One of `--output` or `--stdout` must be specified; omitting both is an error.

### Wallet SDK demos

Fox Wallet and Ghost Wallet are reference integrations showing how a wallet can embed the Keypsafe SDK to offer encrypted seed backup and restore without routing plaintext through a server.

The integration pattern:

1. Wallet embeds the Keypsafe SDK
2. Wallet encrypts the seed locally — plaintext never leaves the wallet process
3. Wallet sends the encrypted vault to the Keypsafe bridge for storage
4. On restore, the bridge returns the encrypted vault; the wallet decrypts locally

The current SDK targets JavaScript environments (browser and Node.js). The demos use `postMessage` as the bridge transport because they run in a browser context. The underlying crypto and vault format are platform-agnostic; native library ports are on the roadmap.

---

## Packages

### `crypto`

Low-level cryptographic primitives. No business logic, no storage calls.

- **AES-GCM** — authenticated encryption for all envelopes and payloads
- **Argon2id** — password key derivation (via hash-wasm, single-threaded)
- **HKDF-SHA256** — key derivation from shared secrets
- **Encoding** — base64url, hex, Uint8Array conversions
- **Zeroization** — `zeroMany()` wipes sensitive buffers after use

### `flows`

Orchestrates multi-step encrypt/decrypt operations. Calls `crypto` primitives in the correct order, manages key lifetimes, zeroes intermediates.

- `encryptVault()` — takes plaintext + factors → returns encrypted vault structure
- `decryptVault()` — takes encrypted vault + factors → returns plaintext, with passkey-first / password-recovery key fallback
- `buildPwdpkWrapKey()`, `unwrapDekWithPasskey()`, `unwrapDekWithPwdPaper()` — factor-specific key operations

### `platform`

Backend abstraction and WebAuthn integration.

- `StorageAdapter` interface — `loadVault`, `createVault`, `listVaults`
- `supabaseStorage` — concrete implementation; filters by both `vaultId` and `userId` for defense-in-depth on top of RLS
- `createPasskey()`, `getPasskeyPrf()` — WebAuthn PRF extension for passkey-based key derivation

### `sdk`

The `KeypsafeSDK` class. Wires `flows`, `platform`, and `crypto` together for callers.

- `decryptVault(opts)` — decrypt a vault by ID
- `decryptVaultWith(opts, fn)` — decrypt, run a function with the plaintext, auto-zero
- `createVault(opts)` — create a new vault with both recovery factors

Initialized with a storage adapter: `new KeypsafeSDK({ storage })`.

### `utils`

Shared types and helpers. Most importantly, the `BridgeRequest` / `BridgeResponse` message types that define the wallet ↔ bridge protocol.

---

## Data flow

### Encryption (create vault)

```
User input (plaintext + password)
  │
  ├─ WebAuthn: getPasskeyPrf() → prfOut [user taps authenticator]
  ├─ Argon2id(password, argon_salt) → kPwd
  ├─ kPwd || recoveryKey → pwdpkKey
  │
  └─ encryptVault()
       ├─ Generate random DEK
       ├─ HKDF(prfOut, kdf_salt) → wrapKeyPK
       │  └─ AES-GCM wrap DEK → pk_envelope
       ├─ HKDF(pwdpkKey, kdf_salt) → wrapKeyPWDPK
       │  └─ AES-GCM wrap DEK → pwdpk_envelope
       ├─ HKDF(DEK, kdf_salt, "keypsafe/meta/v1") → metaKey
       │  └─ AES-GCM encrypt metadata JSON → meta_envelope
       └─ HKDF(DEK, kdf_salt, "keypsafe/dek/payload/v1") → payloadKey
          └─ AES-GCM encrypt plaintext → payload
  │
  └─ supabaseStorage.createVault() → persist all ciphertexts
```

Plaintext never leaves the device. The recovery key is generated at signup in a dedicated system vault (hidden from vault listings). Wallets obtain it at backup time via a bridge request; users can view it in Settings using their passkey.

### Decryption (unlock vault)

```
User selects vault + provides factor
  │
  ├─ supabaseStorage.loadVault(vaultId, userId) → encrypted vault
  │
  ├─ [Passkey path] getPasskeyPrf() → prfOut
  │   └─ HKDF(prfOut, kdf_salt) → wrapKeyPK
  │      └─ AES-GCM unwrap pk_envelope → DEK
  │
  └─ [Password+recovery key path] Argon2id + HKDF → wrapKeyPWDPK
     └─ AES-GCM unwrap pwdpk_envelope → DEK
  │
  └─ DEK → decrypt meta_envelope (verify kdf_salt) + decrypt payload → plaintext
```

Passkey is primary method with password+recovery key as the fallback. If both fail, decryption throws.

### Wallet SDK flow (backup and restore)

The wallet encrypts locally and sends only ciphertext to the bridge for storage. If the wallet needs the user's passkey PRF to do local crypto, it can request it from the bridge.

```
Wallet                             Keypsafe bridge
  │                                        │
  ├─ PASSKEY_PRF_REQUEST ─────────────────►│ (if wallet needs PRF)
  │  ◄────── PASSKEY_PRF_RESULT ───────────┤ bridge prompts user, returns PRF output
  │                                        │
  ├─ BACKUP_REQUEST ───────────────────────►│ encrypted vault, no plaintext
  │  ◄────── BACKUP_RESULT ────────────────┤ vaultId returned
```

---

## Database schema (Supabase)

All vault data lives in a single `vault` table. Columns of note:

| Column | Type | Purpose |
|---|---|---|
| `id` | UUID | Vault identifier |
| `user_id` | UUID | Owner (FK to `auth.users`) |
| `payload_ciphertext` | bytea | Encrypted secret |
| `pk_envelope_ciphertext` | bytea | Passkey-wrapped DEK |
| `pwdpk_envelope_ciphertext` | bytea | Password+recovery key-wrapped DEK |
| `meta_envelope_ciphertext` | bytea | Encrypted metadata (contains recovery key) |
| `argon_salt` | bytea | Per-vault Argon2id salt |
| `kdf_salt` | bytea | Per-vault HKDF salt |
| `suite` | int | Crypto suite version |

Each envelope has a corresponding `_nonce`, `_aad`, and `_version` column. AAD binds each envelope to a specific `userId` + `vaultId`, preventing ciphertext transplant attacks.

**RLS** (`user_id = auth.uid()`) is the primary access guard. The storage adapter also filters by `userId` in every query as defense-in-depth.

---

## Key design decisions

**Client-side only encryption.** The server stores ciphertext. Keypsafe/Supabase never sees plaintext, DEKs, or wrapping keys.

**Two independent recovery factors.** Passkey (hardware-backed PRF) and password+recovery key are separate wrapping paths for the same DEK. Losing one factor does not mean losing the vault.

**Recovery key is vault-scoped but user-shared.** Keypsafe generates the first vault (hidden) to generate a recovery key. Subsequent vaults recover it from the first vault's metadata via the passkey. This keeps the recovery UX simple (one recovery key to back up) without weakening the per-vault key hierarchy.

**Passkey PRF, not passkey signature.** The WebAuthn PRF extension returns a deterministic output tied to the credential and a salt. This output is used as key material, not as an authentication proof, so the passkey acts as a hardware key derivation function.

**Versioned envelopes.** Every ciphertext has a `_version` column. The crypto suite is versioned at the vault level. Migration paths for algorithm upgrades are built into the schema.
