//! Extract and verify a signed message from an image.
//!
//! ```text
//! Image + Public Key
//!   → divide image into 8×8 blocks
//!   → PRNG(pubkey) determines same block/coefficient order as embed
//!   → block FFT → QIM extract bits → pack to bytes
//!   → scan for "WSNT" magic → decode Payload
//!   → Ed25519 verify(embedded_pubkey, payload, embedded_sig)
//!   → compare embedded_pubkey == user_provided_pubkey
//!   → return message (or error)
//! ```

use crate::block::{self, block_rng, shuffle_coeffs, shuffle_indices};
use crate::error::WsntpError;
use crate::fft::{fft_2d, FftDir};
use crate::payload::Payload;
use crate::qim;
use image::RgbImage;
use ndarray::Array2;
use num_complex::Complex;
use rand::rngs::StdRng;
use rustfft::FftPlanner;

/// Extract and verify a signed message from an image.
///
/// `public_key` is the 32-byte Ed25519 public key used to locate the payload
/// and verify the signature.  Returns the embedded message bytes on success.
pub(crate) fn extract(
    image: &RgbImage,
    public_key: &[u8; 32],
) -> Result<Vec<u8>, WsntpError> {
    // --- block grid ---
    let (width, height) = (image.width() as usize, image.height() as usize);
    let cols = width / block::BLOCK;
    let rows = height / block::BLOCK;
    if cols == 0 || rows == 0 {
        return Err(WsntpError::cli(format!(
            "image too small: need at least {}×{} pixels",
            block::BLOCK,
            block::BLOCK
        )));
    }

    // --- same block order as embed ---
    let mut block_indices: Vec<usize> = (0..rows * cols).collect();
    let mut master_rng = block_rng(public_key, 0);
    shuffle_indices(&mut block_indices, &mut master_rng);

    // --- extract bits from all blocks, accumulate as bytes ---
    let mut byte_buf = Vec::new();
    let mut pending_bits: Vec<bool> = Vec::new();

    for &block_idx in &block_indices {
        let by = block_idx / cols;
        let bx = block_idx % cols;
        extract_block(image, bx, by, public_key, &mut pending_bits);

        // Flush complete bytes
        while pending_bits.len() >= 8 {
            let byte = bits_to_byte(&pending_bits[..8]);
            byte_buf.push(byte);
            pending_bits.drain(..8);
        }

        // Try to decode once we've seen enough bytes for a header
        if byte_buf.len() >= 110 {
            // 104 header + a few bytes of message
            if let Ok(msg) = try_decode(&byte_buf, public_key) {
                return Ok(msg);
            }
        }
    }

    // Final attempt with all accumulated bytes
    if let Ok(msg) = try_decode(&byte_buf, public_key) {
        return Ok(msg);
    }

    Err(WsntpError::cli(
        "no valid payload found — wrong key or image not signed",
    ))
}

/// Extract bits from one 8×8 image block into `out`.
fn extract_block(
    image: &RgbImage,
    bx: usize,
    by: usize,
    public_key: &[u8; 32],
    out: &mut Vec<bool>,
) {
    let mut r = Array2::zeros((block::BLOCK, block::BLOCK));
    let mut g = Array2::zeros((block::BLOCK, block::BLOCK));
    let mut b = Array2::zeros((block::BLOCK, block::BLOCK));
    for dy in 0..block::BLOCK {
        for dx in 0..block::BLOCK {
            let px = image.get_pixel(
                (bx * block::BLOCK + dx) as u32,
                (by * block::BLOCK + dy) as u32,
            );
            r[(dy, dx)] = Complex::new(px[0] as f64, 0.0);
            g[(dy, dx)] = Complex::new(px[1] as f64, 0.0);
            b[(dy, dx)] = Complex::new(px[2] as f64, 0.0);
        }
    }

    let block_idx = (by * (image.width() as usize / block::BLOCK) + bx) as u32;
    let mut rng = block_rng(public_key, block_idx);

    let mut planner = FftPlanner::new();
    fft_2d(&mut r, &mut planner, FftDir::Forward);
    fft_2d(&mut g, &mut planner, FftDir::Forward);
    fft_2d(&mut b, &mut planner, FftDir::Forward);

    let budget = block::bits_per_block(block::BLOCK);
    extract_from_channel(&r, budget, &mut rng, out);
    extract_from_channel(&g, budget, &mut rng, out);
    extract_from_channel(&b, budget, &mut rng, out);
}

/// Extract `budget` bits from one channel's FFT coefficients.
fn extract_from_channel(
    channel: &Array2<Complex<f64>>,
    budget: usize,
    rng: &mut StdRng,
    out: &mut Vec<bool>,
) {
    let n = channel.nrows();
    let mut coeffs = block::candidate_coefficients(n);
    shuffle_coeffs(&mut coeffs, rng);

    let mut taken = 0;
    for &(u, v, is_sc) in &coeffs {
        if taken >= budget {
            break;
        }
        if is_sc {
            out.push(qim::extract_bit(channel[(u, v)].re, qim::DELTA));
            taken += 1;
        } else {
            let (b0, b1) = qim::extract_complex(&channel[(u, v)], qim::DELTA);
            out.push(b0);
            out.push(b1);
            taken += 2;
        }
    }
}

/// Try to find and decode a payload in `data`, verifying against `public_key`.
fn try_decode(data: &[u8], expected_pubkey: &[u8; 32]) -> Result<Vec<u8>, WsntpError> {
    let offset = match Payload::find_magic(data) {
        Some(o) => o,
        None => return Err(WsntpError::cli("magic not found")),
    };

    let payload = Payload::decode(&data[offset..])?;

    // Layer 1: signature verification
    if !matches!(payload.verify_signature(), crate::crypto::VerifyResult::Valid) {
        return Err(WsntpError::cli("signature verification failed — image may be tampered"));
    }

    // Layer 2: pubkey comparison
    if payload.public_key != *expected_pubkey {
        return Err(WsntpError::cli(
            "public key mismatch — image was signed by a different key",
        ));
    }

    Ok(payload.message)
}

fn bits_to_byte(bits: &[bool]) -> u8 {
    debug_assert!(bits.len() >= 8);
    let mut b = 0u8;
    for (i, &bit) in bits[..8].iter().enumerate() {
        if bit {
            b |= 1 << (7 - i);
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::embed;
    use image::Rgb;

    const TEST_IMG_SIZE: u32 = 32;

    /// Mid-gray image avoids clamping artefacts (all-black images cause
    /// round-trip errors when IFFT pushes pixel values below zero).
    fn mid_gray_image(w: u32, h: u32) -> RgbImage {
        let mut img = RgbImage::new(w, h);
        for y in 0..h {
            for x in 0..w {
                img.put_pixel(x, y, Rgb([128, 128, 128]));
            }
        }
        img
    }

    #[test]
    fn embed_then_extract_roundtrip() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();

        let embedded = embed::embed(&img, &kp.secret, b"hello world").unwrap();
        let extracted = extract(&embedded, &kp.public).unwrap();

        assert_eq!(extracted, b"hello world");
    }

    #[test]
    fn embed_then_extract_empty_message() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();

        let embedded = embed::embed(&img, &kp.secret, b"").unwrap();
        let extracted = extract(&embedded, &kp.public).unwrap();

        assert!(extracted.is_empty());
    }

    #[test]
    fn wrong_key_fails() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let alice = crypto::generate_keypair();
        let bob = crypto::generate_keypair();

        let embedded = embed::embed(&img, &alice.secret, b"secret").unwrap();
        assert!(extract(&embedded, &bob.public).is_err());
    }

    #[test]
    fn unsigned_image_fails() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();
        assert!(extract(&img, &kp.public).is_err());
    }

    #[test]
    fn long_message_roundtrip() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();
        let msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

        let embedded = embed::embed(&img, &kp.secret, msg).unwrap();
        let extracted = extract(&embedded, &kp.public).unwrap();

        assert_eq!(extracted, msg.as_slice());
    }

    #[test]
    fn different_message_per_key() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let alice = crypto::generate_keypair();
        let bob = crypto::generate_keypair();

        let a = embed::embed(&img, &alice.secret, b"alice says hi").unwrap();
        let b = embed::embed(&img, &bob.secret, b"bob says hi").unwrap();

        assert_eq!(extract(&a, &alice.public).unwrap(), b"alice says hi");
        assert_eq!(extract(&b, &bob.public).unwrap(), b"bob says hi");
        assert!(extract(&a, &bob.public).is_err());
        assert!(extract(&b, &alice.public).is_err());
    }
}
