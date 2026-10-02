//! Shadowsocks AEAD ciphers (SIP004): password -> master key -> per-salt
//! session key, and the TCP chunk / UDP packet framing built on them.
//!
//! ```text
//! master  = EVP_BytesToKey(MD5, password, key_len)
//! subkey  = HKDF-SHA1(ikm = master, salt, info = "ss-subkey", key_len)
//! nonce   = 12-byte little-endian counter, +1 after every seal/open
//! TCP     = salt | seal(len u16 BE) | seal(payload) | seal(len) | seal(payload) ...
//! UDP     = salt | seal(ATYP ADDR PORT | data)          (nonce 0)
//! ```

use std::fmt;

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;

pub const TAG_LEN: usize = 16;
/// Largest payload in one TCP chunk; the two high bits of the length are reserved.
pub const MAX_PAYLOAD: usize = 0x3fff;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Chacha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
}

impl Method {
    /// Accepts the shadowsocks names and go-shadowsocks2's `AEAD_*` aliases.
    pub fn parse(s: &str) -> Option<Method> {
        Some(match s.to_ascii_lowercase().as_str() {
            "chacha20-ietf-poly1305" | "chacha20-poly1305" | "aead_chacha20_poly1305" => Method::Chacha20Poly1305,
            "aes-128-gcm" | "aead_aes_128_gcm" => Method::Aes128Gcm,
            "aes-256-gcm" | "aead_aes_256_gcm" => Method::Aes256Gcm,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Method::Chacha20Poly1305 => "chacha20-ietf-poly1305",
            Method::Aes128Gcm => "aes-128-gcm",
            Method::Aes256Gcm => "aes-256-gcm",
        }
    }

    fn algorithm(self) -> &'static aead::Algorithm {
        match self {
            Method::Chacha20Poly1305 => &aead::CHACHA20_POLY1305,
            Method::Aes128Gcm => &aead::AES_128_GCM,
            Method::Aes256Gcm => &aead::AES_256_GCM,
        }
    }

    /// Key length, which is also the salt length.
    pub fn key_len(self) -> usize {
        self.algorithm().key_len()
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Master key derived from the password.
#[derive(Clone)]
pub struct Key {
    method: Method,
    master: Vec<u8>,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({}, ..)", self.method)
    }
}

impl Key {
    pub fn new(method: Method, password: &str) -> Key {
        Key {
            method,
            master: evp_bytes_to_key(password.as_bytes(), method.key_len()),
        }
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn salt_len(&self) -> usize {
        self.method.key_len()
    }

    /// A fresh random salt for a new session.
    pub fn new_salt(&self) -> Vec<u8> {
        rand::random::<[u8; 32]>()[..self.salt_len()].to_vec()
    }

    /// Session cipher for `salt`.
    pub fn cipher(&self, salt: &[u8]) -> Cipher {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt).extract(&self.master);
        let okm = prk
            .expand(&[SUBKEY_INFO], self.method.algorithm())
            .expect("ss: subkey length is valid for HKDF-SHA1");
        Cipher {
            key: LessSafeKey::new(UnboundKey::from(okm)),
            counter: 0,
        }
    }
}

/// One direction of a session: the subkey plus its nonce counter.
pub struct Cipher {
    key: LessSafeKey,
    counter: u64,
}

impl Cipher {
    fn nonce(&mut self) -> Nonce {
        let mut n = [0u8; aead::NONCE_LEN];
        n[..8].copy_from_slice(&self.counter.to_le_bytes());
        self.counter += 1;
        Nonce::assume_unique_for_key(n)
    }

    /// Encrypts `buf[start..]` in place and appends the tag.
    pub fn seal(&mut self, buf: &mut Vec<u8>, start: usize) {
        let nonce = self.nonce();
        let tag = self
            .key
            .seal_in_place_separate_tag(nonce, Aad::empty(), &mut buf[start..])
            .expect("ss: seal input within AEAD limits");
        buf.extend_from_slice(tag.as_ref());
    }

    /// Decrypts `buf` (ciphertext followed by its tag) in place and returns the
    /// plaintext, or `None` if authentication fails.
    pub fn open<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a mut [u8]> {
        let nonce = self.nonce();
        self.key.open_in_place(nonce, Aad::empty(), buf).ok()
    }

    /// Appends one TCP chunk carrying `payload` (at most `MAX_PAYLOAD` bytes).
    pub fn seal_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) {
        debug_assert!(payload.len() <= MAX_PAYLOAD);
        let start = out.len();
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        self.seal(out, start);
        let start = out.len();
        out.extend_from_slice(payload);
        self.seal(out, start);
    }
}

/// OpenSSL's EVP_BytesToKey with MD5, one iteration and no salt.
fn evp_bytes_to_key(password: &[u8], len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(len + 16);
    let mut block = Vec::with_capacity(16 + password.len());
    while key.len() < len {
        block.extend_from_slice(password);
        let d = md5(&block);
        key.extend_from_slice(&d);
        block.clear();
        block.extend_from_slice(&d);
    }
    key.truncate(len);
    key
}

/// MD5 (RFC 1321). Only used for EVP_BytesToKey compatibility.
fn md5(input: &[u8]) -> [u8; 16] {
    const S: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
        0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
        0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87,
        0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
        0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];
    let mut msg = input.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((input.len() as u64).wrapping_mul(8)).to_le_bytes());

    let mut h: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    for block in msg.as_chunks::<64>().0 {
        let words = block.as_chunks::<4>().0;
        let m: [u32; 16] = std::array::from_fn(|i| u32::from_le_bytes(words[i]));
        let [mut a, mut b, mut c, mut d] = h;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let f = f.wrapping_add(a).wrapping_add(K[i]).wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[(i / 16) * 4 + i % 4]));
        }
        for (x, v) in h.iter_mut().zip([a, b, c, d]) {
            *x = x.wrapping_add(v);
        }
    }
    let mut out = [0u8; 16];
    for (o, x) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *o = x.to_le_bytes();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn md5_rfc1321() {
        for (input, want) in [
            ("", "d41d8cd98f00b204e9800998ecf8427e"),
            ("abc", "900150983cd24fb0d6963f7d28e17f72"),
            ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
            (
                "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                "57edf4a22be3c955ac49da2e2107b67a",
            ),
        ] {
            assert_eq!(hex(&md5(input.as_bytes())), want, "md5({input:?})");
        }
    }

    // Vectors below come from an independent Python implementation
    // (hashlib + `cryptography`'s HKDF / ChaCha20Poly1305 / AESGCM).

    #[test]
    fn master_key_matches_evp_bytes_to_key() {
        assert_eq!(
            hex(&evp_bytes_to_key(b"foobar", 32)),
            "3858f62230ac3c915f300c664312c63f568378529614d22ddb49237d2f60bfdf"
        );
        assert_eq!(
            hex(&evp_bytes_to_key(b"foobar", 16)),
            "3858f62230ac3c915f300c664312c63f"
        );
    }

    #[test]
    fn chunk_matches_reference() {
        for (method, salt_len, want) in [
            (
                Method::Chacha20Poly1305,
                32,
                "5d928c1cfb3122f507f35f22a7e52bf8f7bfc7e7dd301fb288ad174e3e1e3ac4c53ea7748f656e",
            ),
            (
                Method::Aes128Gcm,
                16,
                "f84b9cc69ae6388cf048d4698de9491ca6e15761c1b623fa94803f4a9586911f824240b6bde8c9",
            ),
        ] {
            let key = Key::new(method, "foobar");
            let salt: Vec<u8> = (0..salt_len).collect();
            let mut out = Vec::new();
            key.cipher(&salt).seal_chunk(b"hello", &mut out);
            assert_eq!(hex(&out), want, "{method}");

            let mut dec = key.cipher(&salt);
            let len = dec.open(&mut out[..2 + TAG_LEN]).unwrap();
            assert_eq!(len, [0, 5]);
            assert_eq!(dec.open(&mut out[2 + TAG_LEN..]).unwrap(), b"hello");
        }
    }

    #[test]
    fn wrong_password_or_tamper_fails() {
        let salt = Key::new(Method::Aes256Gcm, "a").new_salt();
        assert_eq!(salt.len(), 32);
        let mut out = Vec::new();
        Key::new(Method::Aes256Gcm, "a")
            .cipher(&salt)
            .seal_chunk(b"data", &mut out);

        let mut wrong = out.clone();
        assert!(
            Key::new(Method::Aes256Gcm, "b")
                .cipher(&salt)
                .open(&mut wrong[..18])
                .is_none()
        );

        let mut tampered = out.clone();
        tampered[0] ^= 1;
        assert!(
            Key::new(Method::Aes256Gcm, "a")
                .cipher(&salt)
                .open(&mut tampered[..18])
                .is_none()
        );
    }

    #[test]
    fn method_names() {
        for m in [Method::Chacha20Poly1305, Method::Aes128Gcm, Method::Aes256Gcm] {
            assert_eq!(Method::parse(m.name()), Some(m));
        }
        assert_eq!(Method::parse("AEAD_CHACHA20_POLY1305"), Some(Method::Chacha20Poly1305));
        assert_eq!(Method::parse("aes-256-cfb"), None);
        assert_eq!(Method::Aes128Gcm.key_len(), 16);
        assert_eq!(Method::Chacha20Poly1305.key_len(), 32);
    }
}
