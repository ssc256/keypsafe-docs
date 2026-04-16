# Overview

## What Keypsafe is

Keypsafe is an encrypted backup and recovery system for software wallet seed phrases and private keys. It lets users securely back up their wallet and recover it if they lose access to their device, without trusting Keypsafe with their secrets.

Encryption and decryption happen entirely on the user's device. Keypsafe servers store only ciphertext. Even a full database breach, a compromised Keypsafe employee, or a subpoena reveals nothing — no plaintext, no keys, and no way to decrypt stored vaults without the user's credentials.

---

## The problem

Many people entering crypto have little conception of what a seed phrase is or why it exists. They install a wallet, complete setup, and never internalize that those 12 words *are* their account — not a backup code, not a hint, but the only credential that matters. When they lose a device or reinstall the app, their instinct is to log back in with an email address and password. That doesn't work. Keypsafe bridges this gap: it gives users a familiar, credential-based recovery path while preserving the security properties of self-custody.

For users who do understand seed phrases, the problem is different but equally real. Self-custody depends entirely on keeping that seed safe — if you lose it, you lose everything, permanently, with no recourse. For software wallet users, this creates a painful tradeoff:

**If you back up your seed, you create a new attack surface.** Most people store seeds in notes apps, screenshots, iCloud, Google Drive, email drafts, or written on paper in insecure locations. Any of these can be breached, synced to the cloud, found by a family member, or lost in a house fire.

**If you don't back up your seed, you risk losing it.** A broken phone, a factory reset, or a lost device means permanent loss of funds.

Hardware wallets solve this by generating and storing seeds in dedicated secure hardware and never exposing them to a general-purpose device. But hardware wallets require purchasing specialized equipment, add friction to everyday use, and are overkill for users with modest holdings or who are just getting started in crypto.

**Even experienced users aren't immune.** Power users often maintain many wallets for different purposes, such as trading, DeFi, airdrops, and test wallets. Keeping track of which seed corresponds to which wallet, and ensuring each one is properly backed up, becomes its own operational burden. Seeds accumulate, backups get inconsistent, and a wallet gets lost not from carelessness but from sheer volume.

**The majority of crypto users use software wallets, and they are almost universally underserved by existing backup solutions.**

---

## The solution

Keypsafe takes the strong cryptographic material at the foundation of self-custody and protects it with equally strong factors — but surfaces it through credentials people already know: email, password, passkey.

Keypsafe gives software wallet users a self-custodial method of saving and restoring seeds, convenient enough to actually use, and safer than the alternatives.

**Client-side encryption.** The user's seed is encrypted on their device before it leaves. Keypsafe's servers receive and store only ciphertext. Encryption keys never touch Keypsafe's infrastructure. This is the same security model used by end-to-end encrypted messaging — the service provider is structurally unable to read user data.

**Two independent recovery factors.** Every vault is protected by two separate cryptographic factors, each capable of independent recovery:

- **Passkey** — a hardware-backed credential stored in the user's device (Secure Enclave on Apple, TPM on Windows). Decryption requires a biometric or PIN, and the credential cannot be exported from the device. This is the primary day-to-day access method.
- **Password + recovery key** — a user-chosen password combined with a randomly generated recovery key (displayed at setup and accessible via Settings). This path works even if the passkey device is lost or destroyed, and is quantum-resistant. It is the guaranteed recovery path.

Neither factor reveals anything about the other. The two paths are cryptographically independent.

**One recovery key for all vaults.** Users generate a single recovery key when they create their account. All subsequent vaults use the same recovery key, recovered automatically via the passkey. Users write down one secret once and are protected indefinitely as they add more wallets.

Unlike losing your seed, losing the recovery key is not catastrophic. You can view and reset it with your password and passkey.

**SDK for wallet integration.** Keypsafe provides a JavaScript SDK that any wallet can embed to offer encrypted backup and restore as a first-class feature. The integration is designed so that the wallet's plaintext seed never leaves the wallet. The wallet encrypts locally and sends only ciphertext to Keypsafe for storage. On the round trip, ciphertext is sent to the wallet and decrypted there, never exposed to the server.

Wallet integration also eliminates two of the most common seed theft vectors: keyloggers and clipboard hijackers. There's nothing to intercept because the seed is never typed or pasted.

As more wallets integrate, Keypsafe becomes a shared recovery layer across the ecosystem — a single place to store and restore all seeds, however many wallets a user has.

---

## Who it's for

**Primary:** Software wallet users who self-custody crypto assets and want a safe, recoverable backup without the complexity of hardware wallets or the risk of other storage methods.

**Secondary:** Wallet developers who want to offer encrypted backup as a built-in feature, without building the cryptographic infrastructure themselves.

The long-term vision is for Keypsafe to become what OAuth became for authentication: a shared, trusted recovery layer that any wallet can integrate, so users have one place to store and restore all their seeds regardless of which wallets they use. Before OAuth, every app built its own login system. Before Keypsafe, every wallet has its own backup story — or none at all.

---

## What makes it different

Most existing "backup" solutions for crypto assets fall into one of two categories:

**Custodial solutions** (exchanges, centralized key managers) — the service can access your keys. You are trusting a company to keep your assets safe, which reintroduces the counterparty risk that self-custody is meant to eliminate.

**Manual backup** (writing down the seed, engraving it in metal, storing in password managers) — no cryptographic protection, highly dependent on the user's operational security, and no recovery mechanism if the backup is lost.

Keypsafe is neither. It is non-custodial by design — structurally, not by policy. The server cannot decrypt vaults even if compelled to. And it provides a structured, tested recovery path rather than relying on users to manage their own backups correctly.

---

## Why not just use a password manager?

You can. But a seed phrase isn't a password, and the difference matters.

A password protects access to an account. If it's compromised, you change it. A seed phrase *is* the account — it controls the underlying funds directly, permanently, and without any recourse. There's no support ticket, no dispute process, no way to recover what's gone. The threat model is categorically different, and a tool designed for one is not the right tool for the other.

**The single point of failure problem.** Password managers are consolidators — their value proposition is putting everything in one place behind one master credential. That's the right design for passwords. For a seed phrase, it means your most irreplaceable secret lives inside the same system as your streaming subscriptions and email logins. A single compromised master password, a phishing attack, or a breach exposes everything at once. Keypsafe is a separate system with a separate authentication surface. Your seed isn't bundled with credentials that rotate.

**Feature surface is attack surface.** Password managers are built for convenience: browser autofill, team vaults, sharing, CLI integrations, third-party app access. Every one of those features exists for a use case your seed phrase has no business touching. A seed should never autofill. It should never be in a shared vault. It should never be accessible via an API token. Keypsafe's narrow scope isn't a limitation — it's a deliberate reduction in attack surface.

**Purpose-built cryptography.** Generic password managers store seeds as opaque strings with key derivation optimized for password-manager use cases. Keypsafe uses Argon2id tuned specifically for resistance to offline brute-force attacks — the threat that applies after a ciphertext is stolen. The two-factor recovery model (passkey + password/recovery key) is designed around the specific failure modes of seed custody: device loss, forgotten credentials, and long-term recoverability without trusting a third party.

Use a password manager for everything. Use Keypsafe specifically for your seed phrase.

---

## Security properties

| Property | Keypsafe |
|---|---|
| Does Keypsafe store your seed? | No — only ciphertext |
| Can Keypsafe decrypt your vault? | No — encryption keys never leave your device |
| What happens if Keypsafe is hacked? | Attacker gets ciphertext only — nothing decryptable |
| What if you lose your phone? | Reset your passkey with password + recovery key from any device |
| What if you forget your password? | Log in with magic link to reset your password with your passkey |
| What if you lose your recovery key? | Reset with passkey |
| What if you lose both your passkey and recovery key? | Vault is unrecoverable — this is by design |

The vault being unrecoverable if you lose both factors is intentional. A system where Keypsafe could recover your vault in this scenario is a system where Keypsafe has access to your vault. Keypsafe does not.
