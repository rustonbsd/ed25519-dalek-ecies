use std::error::Error as StdError;
use std::fmt;

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::Deserializable;
use hpke::Kem;
use hpke::OpModeS;
use hpke::Serializable;
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use x25519_dalek::PublicKey as X25519PublicKey;
use x25519_dalek::StaticSecret as X25519SecretKey;

#[derive(Debug)]
pub enum Error {
    InvalidKey,
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidKey => write!(f, "Invalid key format"),
            Error::EncryptionFailed => write!(f, "Encryption failed"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            _ => None,
        }
    }
}

pub trait Ed25519EciesEncryption<VerifyingKey> {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Ed25519EciesDecryption<SigningKey> {
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

impl Ed25519EciesEncryption<ed25519_dalek::VerifyingKey> for ed25519_dalek::VerifyingKey {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut csprng = StdRng::from_rng(&mut rand::rng());

        let recipient_x25519_public: X25519PublicKey = public_key_from_ed25519_to_x25519(self)?;
        let recipient_pk_bytes = recipient_x25519_public.to_bytes();
        let hpke_recipient_pk =
            <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&recipient_pk_bytes)
                .map_err(|_| Error::InvalidKey)?;
        let (encap_key, mut sender_context) =
            hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256, StdRng>(
                &OpModeS::Base,
                &hpke_recipient_pk,
                b"arbitrary_info_bytes",
                &mut csprng,
            )
            .map_err(|_| Error::EncryptionFailed)?;

        let enc_result = sender_context
            .seal(data, b"arbitrary_seal_bytes")
            .map_err(|_| Error::EncryptionFailed)?;

        let mut buf = Vec::with_capacity(enc_result.len() + 8);
        let encap_key_bytes = encap_key.to_bytes().to_vec();
        let key_len = encap_key_bytes.len() as u64;
        buf.extend_from_slice(&key_len.to_le_bytes());
        buf.extend(encap_key_bytes);
        buf.extend(enc_result);

        Ok(buf)
    }
}

impl Ed25519EciesDecryption<ed25519_dalek::SigningKey> for ed25519_dalek::SigningKey {
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let ecies_secret_key = secret_key_from_ed25519_to_x25519(self)?;
        let hpke_recipient_sk =
            <X25519HkdfSha256 as Kem>::PrivateKey::from_bytes(ecies_secret_key.as_bytes())
                .map_err(|_| Error::InvalidKey)?;

        if data.len() < 8 {
            return Err(Error::DecryptionFailed);
        }
        let (key_len, data) = data.split_at(8);
        let key_len = u64::from_le_bytes(key_len.try_into().unwrap()) as usize;
        if key_len > 128 || data.len() < key_len {
            return Err(Error::DecryptionFailed);
        }
        let (encapped_key, data) = data.split_at(key_len);
        if data.len() == 0 {
            return Err(Error::DecryptionFailed);
        }
        let enc_key = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(encapped_key)
            .map_err(|_| Error::InvalidKey)?;
        let mut receiver_context = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &hpke::OpModeR::Base,
            &hpke_recipient_sk,
            &enc_key,
            b"arbitrary_info_bytes",
        )
        .map_err(|_| Error::InvalidKey)?;

        receiver_context
            .open(data, b"arbitrary_seal_bytes")
            .map_err(|_| Error::DecryptionFailed)
    }
}

pub fn public_key_from_ed25519_to_x25519(
    ed_verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<X25519PublicKey, Error> {
    ed_verifying_key
        .to_montgomery()
        .to_bytes()
        .try_into()
        .map_err(|_| Error::InvalidKey)
}

pub fn secret_key_from_ed25519_to_x25519(
    ed_signing_key: &ed25519_dalek::SigningKey,
) -> Result<X25519SecretKey, Error> {
    ed_signing_key
        .to_scalar_bytes()
        .try_into()
        .map_err(|_| Error::InvalidKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn test_key_conversion_and_derivation() {
        // Generate Ed25519 keypair
        let mut old_rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut old_rng);
        let verifying_key = signing_key.verifying_key();

        // Convert Ed25519 public key to X25519
        let x25519_pub_from_ed = public_key_from_ed25519_to_x25519(&verifying_key)
            .expect("Failed to convert Ed25519 public key to X25519");

        // Convert Ed25519 secret key to X25519
        let x25519_secret = secret_key_from_ed25519_to_x25519(&signing_key)
            .expect("Failed to convert Ed25519 secret key to X25519");

        // Derive X25519 public key from secret key
        let x25519_pub_from_secret = X25519PublicKey::from(&x25519_secret);

        // Both derived public keys should match
        assert_eq!(
            x25519_pub_from_ed.as_bytes(),
            x25519_pub_from_secret.as_bytes(),
            "Public keys derived through different paths should match"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Generate Ed25519 keypair
        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // Test data
        let plaintext = b"Hello, ECIES!";

        // Encrypt using Ed25519 public key
        let ciphertext = verifying_key.encrypt(plaintext);
        println!("chiphertext: {:?}", ciphertext);

        // Decrypt using Ed25519 private key
        let decrypted = signing_key
            .decrypt(&ciphertext.unwrap())
            .expect("Decryption failed");

        // Check if decrypted matches original
        assert_eq!(
            plaintext,
            decrypted.as_slice(),
            "Decrypted data should match original plaintext"
        );
    }

    #[test]
    fn test_encryption_different_keys() {
        // Generate two different keypairs
        let mut rng = rand_core::OsRng;
        let signing_key1 = SigningKey::generate(&mut rng);
        let signing_key2 = SigningKey::generate(&mut rng);
        let verifying_key1 = signing_key1.verifying_key();

        let plaintext = b"Secret message";

        // Encrypt with first public key
        let ciphertext = verifying_key1
            .encrypt(plaintext)
            .expect("Encryption failed");

        // Try to decrypt with second private key (should fail)
        let result = signing_key2.decrypt(&ciphertext);
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_invalid_ciphertext() {
        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut rng);

        // Try to decrypt invalid data
        let invalid_data = vec![1, 2, 3, 4, 5];
        let result = signing_key.decrypt(&invalid_data);
        println!("Decrypt: {result:?}");
        assert!(result.is_err(), "Decryption should fail with invalid data");
    }
}
