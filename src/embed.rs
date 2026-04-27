/*
    WSNTP (What's Signed On The Picture?) is a picture signing tool running in the cmd lines.
    Copyright (C) 2026  LLLichlet

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

//! Embed a signed message into an image.
//!
//! ```text
//! Image + Secret Seed + Message
//!   → derive public key
//!   → Payload { pubkey, signature, message }
//!   → encode to bytes → bits
//!   → divide image into 8×8 blocks
//!   → PRNG(pubkey, block_idx) selects which coefficients to modify
//!   → block FFT → QIM embed → Hermitian fix → IFFT
//!   → output image
//! ```

use crate::block::{self, block_rng, shuffle_coeffs, shuffle_indices};
use crate::crypto;
use crate::error::WsntpError;
use crate::fft::{fft_2d, FftDir};
use crate::payload::Payload;
use crate::qim;
use image::RgbImage;
use ndarray::Array2;
use num_complex::Complex;
use rand::rngs::StdRng;
use rustfft::FftPlanner;

/// Embed a signed message into an image.
///
/// `secret_seed` is the 32-byte Ed25519 seed.  The matching public key is
/// derived from it and embedded alongside the signature and message.
///
/// Returns a new image.  Edge pixels that do not form a full 8×8 block are
/// carried over unchanged.
pub(crate) fn embed(
    image: &RgbImage,
    secret_seed: &[u8; 32],
    message: &[u8],
) -> Result<RgbImage, WsntpError> {
    let public_key = crypto::derive_public(secret_seed);

    // --- payload ---
    let mut payload = Payload::new(public_key, message.to_vec())?;
    payload.sign(secret_seed);
    let payload_bytes = payload.encode();
    let bits: Vec<bool> = bytes_to_bits(&payload_bytes);

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
    let capacity = 3 * block::bits_per_block(block::BLOCK) * rows * cols;
    if bits.len() > capacity {
        return Err(WsntpError::cli(format!(
            "message too long for image: {} bits needed, {} available",
            bits.len(),
            capacity
        )));
    }

    // --- select blocks (deterministic shuffle seeded from pubkey) ---
    let mut block_indices: Vec<usize> = (0..rows * cols).collect();
    let mut master_rng = block_rng(&public_key, 0);
    shuffle_indices(&mut block_indices, &mut master_rng);

    let blocks_needed = bits.len().div_ceil(3 * block::bits_per_block(block::BLOCK));

    // --- copy image so we can mutate it ---
    let mut output = image.clone();

    let mut bit_cursor = 0usize;
    for &block_idx in block_indices.iter().take(blocks_needed) {
        let by = block_idx / cols;
        let bx = block_idx % cols;
        let taken = embed_block(&mut output, bx, by, &bits, bit_cursor, &public_key)?;
        bit_cursor += taken;
    }

    Ok(output)
}

// ---------------------------------------------------------------------------
// per-block embedding
// ---------------------------------------------------------------------------

/// Embed as many payload bits as possible into one 8×8 image block.
fn embed_block(
    image: &mut RgbImage,
    bx: usize,
    by: usize,
    bits: &[bool],
    bit_offset: usize,
    public_key: &[u8; 32],
) -> Result<usize, WsntpError> {
    // Extract three channels into complex arrays
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
    let consumed_r = embed_in_channel(&mut r, bits, bit_offset, budget, &mut rng);
    let consumed_g = embed_in_channel(&mut g, bits, bit_offset + consumed_r, budget, &mut rng);
    let consumed_b = embed_in_channel(
        &mut b,
        bits,
        bit_offset + consumed_r + consumed_g,
        budget,
        &mut rng,
    );

    fft_2d(&mut r, &mut planner, FftDir::Inverse);
    fft_2d(&mut g, &mut planner, FftDir::Inverse);
    fft_2d(&mut b, &mut planner, FftDir::Inverse);

    for dy in 0..block::BLOCK {
        for dx in 0..block::BLOCK {
            let x = (bx * block::BLOCK + dx) as u32;
            let y = (by * block::BLOCK + dy) as u32;
            let r8 = r[(dy, dx)].re.round().clamp(0.0, 255.0) as u8;
            let g8 = g[(dy, dx)].re.round().clamp(0.0, 255.0) as u8;
            let b8 = b[(dy, dx)].re.round().clamp(0.0, 255.0) as u8;
            image.put_pixel(x, y, image::Rgb([r8, g8, b8]));
        }
    }

    Ok(consumed_r + consumed_g + consumed_b)
}

/// Embed bits into a single channel's FFT coefficients.
fn embed_in_channel(
    channel: &mut Array2<Complex<f64>>,
    bits: &[bool],
    bit_offset: usize,
    budget: usize,
    rng: &mut StdRng,
) -> usize {
    let n = channel.nrows();
    debug_assert_eq!(n, channel.ncols());

    let mut coeffs = block::candidate_coefficients(n);
    shuffle_coeffs(&mut coeffs, rng);

    let mut taken = 0;
    for &(u, v, is_sc) in &coeffs {
        if taken >= budget {
            break;
        }

        if is_sc {
            if bit_offset + taken < bits.len() {
                let old = channel[(u, v)];
                let new_re = qim::embed_bit(old.re, bits[bit_offset + taken], qim::DELTA);
                channel[(u, v)] = Complex::new(new_re, 0.0);
            }
            taken += 1;
        } else {
            let conj_u = (n - u) % n;
            let conj_v = (n - v) % n;

            let b0 = bits.get(bit_offset + taken).copied().unwrap_or(false);
            let b1 = bits.get(bit_offset + taken + 1).copied().unwrap_or(false);

            let old = channel[(u, v)];
            let new_val = qim::embed_complex(&old, (b0, b1), qim::DELTA);
            channel[(u, v)] = new_val;
            channel[(conj_u, conj_v)] = Complex::new(new_val.re, -new_val.im);

            taken += 2;
        }
    }
    taken
}

// ---------------------------------------------------------------------------
// utility
// ---------------------------------------------------------------------------

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for &b in bytes {
        for shift in (0..8).rev() {
            bits.push((b >> shift) & 1 != 0);
        }
    }
    bits
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use image::Rgb;

    const TEST_IMG_SIZE: u32 = 32;

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
    fn embed_then_clamp_in_range() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();
        let result = embed(&img, &kp.secret, b"test").unwrap();
        assert_eq!(result.width(), TEST_IMG_SIZE);
        assert_eq!(result.height(), TEST_IMG_SIZE);
    }

    #[test]
    fn embed_rejects_tiny_image() {
        let img = RgbImage::new(4, 4);
        let kp = crypto::generate_keypair();
        assert!(embed(&img, &kp.secret, b"hi").is_err());
    }

    #[test]
    fn embed_rejects_huge_message() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();
        let big = vec![b'x'; 300];
        assert!(embed(&img, &kp.secret, &big).is_err());
    }

    #[test]
    fn embed_deterministic() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();
        let a = embed(&img, &kp.secret, b"hello").unwrap();
        let b = embed(&img, &kp.secret, b"hello").unwrap();
        assert_eq!(a.as_raw(), b.as_raw());
    }

    #[test]
    fn embed_different_keys_different_output() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let alice = crypto::generate_keypair();
        let bob = crypto::generate_keypair();
        let a = embed(&img, &alice.secret, b"hello").unwrap();
        let b = embed(&img, &bob.secret, b"hello").unwrap();
        assert_ne!(a.as_raw(), b.as_raw());
    }

    #[test]
    fn embed_empty_message() {
        let img = mid_gray_image(TEST_IMG_SIZE, TEST_IMG_SIZE);
        let kp = crypto::generate_keypair();
        let result = embed(&img, &kp.secret, b"").unwrap();
        assert_eq!(result.width(), TEST_IMG_SIZE);
        assert_eq!(result.height(), TEST_IMG_SIZE);
    }
}
