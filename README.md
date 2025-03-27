# ed25519-dalek-hpke

[![crates.io](https://img.shields.io/crates/v/ed25519-dalek-hpke.svg)](https://crates.io/crates/ed25519-dalek-hpke)
[![docs.rs](https://docs.rs/ed25519-dalek-hpke/badge.svg)](https://docs.rs/ed25519-dalek-hpke)
[![Build Status](https://github.com/rustonbsd/ed25519-dalek-hpke/actions/workflows/rust.yml/badge.svg)](https://github.com/rustonbsd/ed25519-dalek-hpke/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

**Convenient HPKE encryption and decryption using `ed25519-dalek` keys.**

This crate provides a simple API to encrypt data for an `ed25519-dalek` public key and decrypt it using the corresponding secret key. It handles the necessary key conversions (Ed25519 <-> X25519) internally, allowing you to work directly with your existing Ed25519 key types.

## Features

* **Simple API:** Provides straightforward `encrypt` and `decrypt` functions.
* **`ed25519-dalek` Compatibility:** Accepts `ed25519_dalek::VerifyingKey` for encryption and `ed25519_dalek::SigningKey` for decryption.
* **Automatic Key Conversion:** Converts Ed25519 keys to their X25519 counterparts as required by HPKE.
* **Underlying Primitives:** Uses `x25519-dalek` for key conversion and the `hpke` crate for the HPKE implementation (using X25519, HKDF-SHA256, and ChaCha20Poly1305).

## Security Warning

* **EXPERIMENTAL:** This library is experimental and has **not** undergone a formal security audit. Use it at your own risk.
* **Ed25519 vs. X25519:** Ed25519 is primarily a signature scheme. While the underlying curve allows for key exchange via conversion to X25519 (Montgomery form), using the same key pair for both signing and encryption can have security implications depending on your protocol. Consider using separate key pairs for signing and encryption if your security model allows it.
* **Review the Code:** Users are encouraged to review the source code and the dependencies (`hpke`, `x25519-dalek`, `ed25519-dalek`).

## How it Works

1. **Encryption (`encrypt`):**
   * Takes an `ed25519_dalek::VerifyingKey`.
   * Converts the Ed25519 public key (Edwards curve point) to its corresponding X25519 public key (Montgomery u-coordinate) using `x25519-dalek`.
   * Uses the resulting X25519 public key with HPKE in base mode, which performs:
     - Ephemeral key generation
     - Key encapsulation (KEM) using X25519
     - Key derivation (KDF) using HKDF-SHA256
     - AEAD encryption using ChaCha20Poly1305

2. **Decryption (`decrypt`):**
   * Takes an `ed25519_dalek::SigningKey`.
   * Derives the X25519 static secret scalar from the Ed25519 secret key material using `x25519-dalek`.
   * Uses the resulting X25519 secret key with HPKE in base mode, which performs:
     - Key decapsulation using the encapsulated key
     - Key derivation (KDF) using HKDF-SHA256
     - AEAD decryption using ChaCha20Poly1305

## Security Considerations

* **Key Management:** Securely managing your `ed25519_dalek::SigningKey` is paramount. If the signing key is compromised, both signatures and encrypted messages can be compromised.
* **HPKE Implementation:** The implementation follows RFC 9180 (HPKE) using the `hpke` crate with the following ciphersuites:
  - KEM: X25519_HKDF_SHA256
  - KDF: HKDF_SHA256
  - AEAD: ChaCha20Poly1305
* **Key Separation Principle:** As mentioned in the warning, cryptographic best practice often recommends using distinct keys for distinct cryptographic operations (signing vs. encryption). This library makes it *possible* to use Ed25519 keys for HPKE, but evaluate if it's *appropriate* for your security requirements.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
