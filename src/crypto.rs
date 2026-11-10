use crate::types::{Errors, KeyType, NonceType};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn generate_keys() -> (EphemeralSecret, PublicKey) {
    let ephermalsecret = EphemeralSecret::random();
    let public = PublicKey::from(&ephermalsecret);
    (ephermalsecret, public)
}

pub fn derive_session_key(my_key: EphemeralSecret, peer_pub: KeyType) -> (KeyType, KeyType) {
    let sharedsecret = my_key.diffie_hellman(&PublicKey::from(peer_pub));
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &sharedsecret.to_bytes());
    let mut s2c = [0u8; 32];
    let mut c2s = [0u8; 32];
    hk.expand("s2cv1".as_bytes(), &mut s2c).unwrap(); // bound to be ok because
    hk.expand("c2sv1".as_bytes(), &mut c2s).unwrap(); // bound to be ok because
    // shared_key length is exactly 32 bytes
    (s2c, c2s)
}
pub fn decrypt_message(message: &[u8], key: KeyType, counter: u64) -> Result<Vec<u8>, Errors> {
    let chachakey = chacha20poly1305::Key::from(key);
    let chacha = ChaCha20Poly1305::new(&chachakey);
    let nonce = Nonce::from(counter_to_nonce(counter));
    chacha
        .decrypt(&nonce.into(), message)
        .map_err(|e| Errors::CryptographicError(e))
}
pub fn encrypt_message(message: &[u8], key: KeyType, counter: u64) -> Result<Vec<u8>, Errors> {
    let chachakey = chacha20poly1305::Key::from(key);
    let chacha = ChaCha20Poly1305::new(&chachakey);
    let nonce = Nonce::from(counter_to_nonce(counter));
    chacha
        .encrypt(&nonce.into(), message)
        .map_err(|e| Errors::CryptographicError(e))
}

fn counter_to_nonce(counter: u64) -> Nonce {
    let mut noncebytes: Vec<u8> = vec![];
    noncebytes.extend_from_slice(&counter.to_le_bytes());
    noncebytes.extend_from_slice(&[0, 0, 0, 0]);
    let noncebytes: NonceType = noncebytes.try_into().unwrap();
    Nonce::from(noncebytes)
}
