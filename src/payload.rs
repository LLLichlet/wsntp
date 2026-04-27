//! Binary payload format for WSNTP.
//!
//! Handles serialization, deserialization, signing, and verification of the
//! signed-message container that gets embedded into image FFT coefficients.
//!
//! ```text
//! |-----------|-----------|-----------|-----------|-----------|-----------|-----------|
//! |  "WSNT"   |   0x01    |   0x00    |  pubkey   | signature |  msg_len  |  message  |
//! |    4B     |    1B     |    1B     |   32B     |   64B     |   2B BE   |    N B    |
//! |-----------|-----------|-----------|-----------|-----------|-----------|-----------|
//! ```

use crate::crypto::{sign, verify, VerifyResult};
use crate::error::WsntpError;

const MAGIC: &[u8; 4] = b"WSNT";
const VERSION: u8 = 0x01;

const OFF_PUBKEY: usize = 6;   // after magic(4) + version(1) + reserved(1)
const OFF_SIGNATURE: usize = 38;  // after pubkey(32)
const OFF_MSG_LEN: usize = 102;   // after signature(64)
const HEADER_SIZE: usize = 104;   // total overhead before message

pub(crate) struct Payload {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
    pub message: Vec<u8>,
}

impl Payload {
    /// Create a new payload with a zeroed-out signature.
    ///
    /// Returns an error if `message` exceeds 65535 bytes (u16::MAX).
    /// Call [`sign`](Self::sign) afterwardsto populate the signature field.
    pub fn new(public_key: [u8; 32], message: Vec<u8>) -> Result<Self, WsntpError> {
        if message.len() > u16::MAX as usize {
            return Err(WsntpError::cli(format!(
                "message too long: {} bytes (max {})",
                message.len(),
                u16::MAX,
            )));
        }
        Ok(Self {
            public_key,
            signature: [0u8; 64],
            message,
        })
    }

    /// Build the signing input: `pubkey || msg_len || message`.
    ///
    /// The signing input deliberately excludes the version byte so that
    /// payloads signed under one version can be re-encoded under a newer
    /// version without invalidating the signature.  Magic and reserved
    /// bytes are excluded because they are framing markers, not data.
    fn signing_input(&self) -> Vec<u8> {
        let len_bytes = (self.message.len() as u16).to_be_bytes();
        let mut buf = Vec::with_capacity(32 + 2 + self.message.len());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&len_bytes);
        buf.extend_from_slice(&self.message);
        buf
    }

    /// Sign the payload in-place with an Ed25519 secret seed.
    pub fn sign(&mut self, secret_seed: &[u8; 32]) {
        let input = self.signing_input();
        self.signature = sign(&input, secret_seed);
    }

    /// Verify the embedded Ed25519 signature.
    pub fn verify_signature(&self) -> VerifyResult {
        let input = self.signing_input();
        verify(&input, &self.signature, &self.public_key)
    }

    /// Serialize to bytes:
    /// `magic | version | reserved | pubkey | signature | msg_len | message`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.message.len());
        buf.extend_from_slice(MAGIC);
        buf.push(VERSION);
        buf.push(0x00);
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.signature);
        buf.extend_from_slice(&(self.message.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.message);
        buf
    }

    /// Deserialize from bytes.  Caller is responsible for locating the magic
    /// bytes before calling this function — `data[0..4]` must be `MAGIC`.
    pub fn decode(data: &[u8]) -> Result<Self, WsntpError> {
        if data.len() < HEADER_SIZE {
            return Err(WsntpError::cli("payload too short"));
        }
        if &data[0..4] != MAGIC {
            return Err(WsntpError::cli("invalid magic bytes"));
        }
        if data[4] != VERSION {
            return Err(WsntpError::cli(format!("unknown payload version: {}", data[4])));
        }
        if data[5] != 0x00 {
            return Err(WsntpError::cli("reserved byte must be 0x00"));
        }

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(&data[OFF_PUBKEY..OFF_PUBKEY + 32]);

        let mut signature = [0u8; 64];
        signature.copy_from_slice(&data[OFF_SIGNATURE..OFF_SIGNATURE + 64]);

        let msg_len = u16::from_be_bytes([data[OFF_MSG_LEN], data[OFF_MSG_LEN + 1]]) as usize;
        if data.len() < HEADER_SIZE + msg_len {
            return Err(WsntpError::cli(
                "payload truncated: message shorter than declared length",
            ));
        }

        let message = data[HEADER_SIZE..HEADER_SIZE + msg_len].to_vec();
        Ok(Self {
            public_key,
            signature,
            message,
        })
    }

    /// Scan `data` for the magic prefix and return its byte offset, if any.
    pub fn find_magic(data: &[u8]) -> Option<usize> {
        data.windows(4).position(|w| w == *MAGIC)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;

    fn dummy_payload() -> Payload {
        let kp = crypto::generate_keypair();
        Payload {
            public_key: kp.public,
            signature: [0u8; 64],
            message: b"hello world".to_vec(),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let p = dummy_payload();
        let encoded = p.encode();
        let decoded = Payload::decode(&encoded).unwrap();
        assert_eq!(decoded.public_key, p.public_key);
        assert_eq!(decoded.signature, p.signature);
        assert_eq!(decoded.message, p.message);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = crypto::generate_keypair();
        let mut p = Payload::new(kp.public, b"signed message".to_vec()).unwrap();
        p.sign(&kp.secret);
        assert!(matches!(p.verify_signature(), VerifyResult::Valid));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let kp = crypto::generate_keypair();
        let mut p = Payload::new(kp.public, b"original".to_vec()).unwrap();
        p.sign(&kp.secret);

        p.message = b"tampered!".to_vec();
        assert!(matches!(
            p.verify_signature(),
            VerifyResult::InvalidSignature
        ));
    }

    #[test]
    fn tampered_public_key_fails_verification() {
        let kp = crypto::generate_keypair();
        let mut p = Payload::new(kp.public, b"msg".to_vec()).unwrap();
        p.sign(&kp.secret);

        let other = crypto::generate_keypair();
        p.public_key = other.public;
        assert!(matches!(
            p.verify_signature(),
            VerifyResult::InvalidSignature
        ));
    }

    #[test]
    fn oversized_message_rejected() {
        let kp = crypto::generate_keypair();
        let msg = vec![b'x'; u16::MAX as usize + 1];
        assert!(Payload::new(kp.public, msg).is_err());
    }

    #[test]
    fn decode_rejects_short_data() {
        assert!(Payload::decode(b"WSN").is_err());
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0..4].copy_from_slice(b"BAD!");
        assert!(Payload::decode(&data).is_err());
    }

    #[test]
    fn decode_rejects_unsupported_version() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0..4].copy_from_slice(MAGIC);
        data[4] = 0xFF;
        assert!(Payload::decode(&data).is_err());
    }

    #[test]
    fn decode_rejects_nonzero_reserved() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0..4].copy_from_slice(MAGIC);
        data[4] = VERSION;
        data[5] = 0x01; // bad reserved byte
        assert!(Payload::decode(&data).is_err());
    }

    #[test]
    fn decode_rejects_truncated_message() {
        let mut data = vec![0u8; HEADER_SIZE];
        data[0..4].copy_from_slice(MAGIC);
        data[4] = VERSION;
        data[OFF_MSG_LEN] = 0x00;
        data[OFF_MSG_LEN + 1] = 0x10; // claims 16-byte message, but no data follows
        assert!(Payload::decode(&data).is_err());
    }

    #[test]
    fn empty_message() {
        let kp = crypto::generate_keypair();
        let mut p = Payload::new(kp.public, vec![]).unwrap();
        p.sign(&kp.secret);
        let encoded = p.encode();
        let decoded = Payload::decode(&encoded).unwrap();
        assert!(decoded.message.is_empty());
        assert!(matches!(decoded.verify_signature(), VerifyResult::Valid));
    }

    #[test]
    fn max_length_message() {
        let kp = crypto::generate_keypair();
        let msg = vec![b'x'; u16::MAX as usize];
        let mut p = Payload::new(kp.public, msg.clone()).unwrap();
        p.sign(&kp.secret);
        let encoded = p.encode();
        let decoded = Payload::decode(&encoded).unwrap();
        assert_eq!(decoded.message.len(), u16::MAX as usize);
        assert!(matches!(decoded.verify_signature(), VerifyResult::Valid));
    }

    #[test]
    fn find_magic_at_start() {
        let p = dummy_payload();
        let encoded = p.encode();
        assert_eq!(Payload::find_magic(&encoded), Some(0));
    }

    #[test]
    fn find_magic_with_garbage_prefix() {
        let p = dummy_payload();
        let encoded = p.encode();
        let mut noisy = vec![0x00u8; 5];
        noisy.extend_from_slice(&encoded);
        assert_eq!(Payload::find_magic(&noisy), Some(5));
    }

    #[test]
    fn find_magic_not_present() {
        assert_eq!(Payload::find_magic(b"no magic here"), None);
    }

    #[test]
    fn find_magic_data_shorter_than_4_bytes() {
        assert_eq!(Payload::find_magic(b"WS"), None);
    }
}
