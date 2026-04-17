---
layout: home

hero:
  name: Keypsafe
  text: Encrypted backup for crypto wallets
  tagline: Client-side encrypted. Zero-knowledge by design. Your seed phrase never leaves your device.
  actions:
    - theme: brand
      text: Overview
      link: /overview
    - theme: alt
      text: Architecture
      link: /architecture/system-architecture
    - theme: alt
      text: Security
      link: /security/security-model

features:
  - title: Zero-knowledge
    details: Encryption and decryption happen entirely on your device. Keypsafe servers only see ciphertext — even a full database breach doesn't reveal your secrets.
  - title: Two recovery factors
    details: Every vault is protected by a passkey and a password + recovery key. Either factor alone can decrypt. Losing one is never fatal.
  - title: Open cryptography
    details: AES-256-GCM, Argon2id, HKDF-SHA256. Published security model and threat model. No proprietary crypto, no trust us claims. Open source after audit. 
---
