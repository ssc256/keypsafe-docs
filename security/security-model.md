# Security model

## What Keypsafe protects against

**Database breach.** Supabase stores only ciphertext. A full database dump, including by Keypsafe insiders with direct DB access, reveals nothing about vault contents. Every secret is encrypted before it leaves the user's device.

**Server-side compromise.** Keypsafe's backend has no access to plaintext, DEKs, or wrapping keys at any point. There is no server-side decryption path.

**Cross-user access.** Every ciphertext envelope includes AAD (additional authenticated data) that binds it to a specific `userId` and `vaultId`. An attacker who can write to the database cannot transplant a ciphertext from one user's vault to another — decryption would fail. Supabase RLS enforces `user_id = auth.uid()` as the primary access guard; the storage adapter filters by both `userId` and `vaultId` in every query as an independent defense-in-depth layer.

**Weak passwords.** The password factor is hardened with Argon2id (time=3, memory=64MiB) before being combined with the recovery key. Offline brute-force attacks against the password alone are computationally expensive, and the recovery key adds 256 bits of entropy that the attacker must also possess.

**Single factor loss.** Losing a passkey does not lose the vault — the password+recovery key path is an independent wrapping of the same DEK. Losing the recovery key is also recoverable with the passkey. Both factors must be lost to lose access permanently.

---

## What Keypsafe does not protect against

**Compromised JS delivery.** The web app is JavaScript served from Keypsafe's servers. Keypsafe (or an attacker who compromises Keypsafe's infrastructure) could ship a version of the app that intercepts plaintext after decryption before it reaches the user. This is a known limitation of all browser-based encryption products, including ProtonMail web and Signal web. It requires an active, ongoing attack — not a passive database breach — and would be illegal and auditable.

**Compromised device.** If a user's device has malware, a keylogger, or a compromised browser, no client-side encryption system can protect them.

**Passkey credential theft.** Passkey credentials are hardware-backed on most modern devices (Secure Enclave, TPM). Theft is difficult but not impossible — a compromised OS or authenticator could expose the credential.

**The PRF delegation boundary.** The Keypsafe bridge allows third-party wallets to request a passkey PRF via `PASSKEY_PRF_REQUEST`. The bridge performs the WebAuthn ceremony internally and derives a **vault-scoped IKM** (`vaultPrf = HKDF(userPrf, vaultId, "keypsafe/prf/vault/v1")`) before responding. The raw `userPrf` (which would unlock all of a user's vaults) never crosses the postMessage boundary. Wallets receive only a value scoped to the single requested vault, so a compromised wallet can decrypt at most one vault — the same one it backed up. The postMessage channel itself is origin-checked and constrained to the wallet/bridge pair. See the [threat model](./threat-model) for more detail.

---

## Trust hierarchy

Different surfaces carry different trust requirements:

| Surface | Trust required | Why |
|---|---|---|
| Supabase database | None | Contains only ciphertext |
| Keypsafe CLI | None | Locally installed, auditable, no network dependency |
| Keypsafe web app | Keypsafe JS delivery | Server-served JS runs in browser |
| Wallet bridge | Keypsafe JS delivery | Same as web app |
| Third-party wallet using the SDK | Wallet developer + Keypsafe SDK code | Crypto happens in the wallet's process; wallet is not Keypsafe |

The CLI is the most trustless surface. For users who need a fully auditable recovery path, the CLI decrypts a backup file without any network calls.

---

## Cryptographic design

**Encryption.** All secrets are encrypted with AES-256-GCM. Every envelope uses a fresh random nonce and includes AAD for integrity binding.

**Key hierarchy.** Each vault has a random per-vault DEK (data encryption key). The DEK is never stored in plaintext — it is wrapped separately by each recovery factor and stored as an encrypted envelope. The vault payload is encrypted with a key derived from the DEK via HKDF, not the DEK directly.

**Two wrapping paths.** The DEK is independently wrapped by two factors:
- Passkey path: `HKDF(prfOut, kdf_salt, "keypsafe/kek/pk/v1")` → AES key → wraps DEK
- Password+recovery key path: `Argon2id(password, argon_salt)` + recovery key → `HKDF(..., "keypsafe/kek/pwdpk/v1")` → AES key → wraps DEK

Either path alone is sufficient to decrypt. Neither path reveals anything about the other.

**Key derivation.** HKDF-SHA256 is used to derive purpose-specific keys from shared secrets. Each derived key has a unique info string (`keypsafe/kek/pk/v1`, `keypsafe/kek/pwdpk/v1`, `keypsafe/dek/payload/v1`, `keypsafe/meta/v1`) to prevent key reuse across contexts.

**Metadata integrity.** The metadata envelope (encrypted with the DEK) contains the `kdf_salt`. On decryption, the decrypted `kdf_salt` is compared against the value stored in the database. A mismatch aborts decryption and indicates tampering.

**Zeroization.** Sensitive key material (DEK, intermediate wrapping keys) is overwritten in memory (best-effort zeroization in JS environment) after use.

**Versioning.** Every envelope stores a version number. The crypto suite is versioned at the vault level. Algorithm upgrades do not require migrating existing vaults immediately — old and new suites can coexist.

---

## What we claim

- Your secrets are safe from database breaches
- Your secrets are safe from anyone with direct Supabase access, including Keypsafe
- Losing your passkey does not mean losing your vaults
- Losing your recovery key does not mean losing your vaults
- A compromised password alone is not sufficient to decrypt your vault

## Security model boundaries

Keypsafe is built to protect encrypted vault data under expected operating conditions, but it is not a guarantee against every class of attack.

- Its security depends in part on users receiving and running the intended client code. A compromised application delivery path could weaken these protections.
- It is not designed to defend against a compromised user device.
- Our wallet SDK integration is still evolving and should be understood as a practical security layer, not fully trustless architecture.
