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

//! Shared block-level helpers for embed and extract.

use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

pub(crate) const BLOCK: usize = 8;

/// List candidate coefficient positions in an `n`×`n` FFT block.
///
/// Returns `(u, v, is_self_conjugate)` tuples:
/// - Self-conjugate positions (DC excluded) → 1 bit (real part only).
/// - Canonical representative of a conjugate pair → 2 bits (real + imag).
///
/// DC `(0,0)` is always excluded (too visible).
pub(crate) fn candidate_coefficients(n: usize) -> Vec<(usize, usize, bool)> {
    let mut visited = vec![false; n * n];
    let mut out = Vec::with_capacity(n * n / 2);

    for u in 0..n {
        for v in 0..n {
            let idx = u * n + v;
            if visited[idx] {
                continue;
            }

            let conj_u = (n - u) % n;
            let conj_v = (n - v) % n;

            if u == conj_u && v == conj_v {
                if !(u == 0 && v == 0) {
                    out.push((u, v, true));
                }
                visited[idx] = true;
            } else {
                out.push((u, v, false));
                visited[idx] = true;
                visited[conj_u * n + conj_v] = true;
            }
        }
    }
    out
}

/// How many bits can one channel of an `n`×`n` block hold?
pub(crate) fn bits_per_block(n: usize) -> usize {
    candidate_coefficients(n)
        .iter()
        .map(|&(_, _, sc)| if sc { 1 } else { 2 })
        .sum()
}

/// Create a deterministic block-level RNG from the public key and block index.
pub(crate) fn block_rng(public_key: &[u8; 32], block_idx: u32) -> StdRng {
    let mut seed = *public_key;
    let idx_bytes = block_idx.to_le_bytes();
    for i in 0..4 {
        seed[i] ^= idx_bytes[i];
    }
    StdRng::from_seed(seed)
}

/// Fisher-Yates shuffle for block indices.
pub(crate) fn shuffle_indices(indices: &mut [usize], rng: &mut StdRng) {
    for i in (1..indices.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        indices.swap(i, j);
    }
}

/// Fisher-Yates shuffle for coefficient tuples.
pub(crate) fn shuffle_coeffs(coeffs: &mut [(usize, usize, bool)], rng: &mut StdRng) {
    for i in (1..coeffs.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        coeffs.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_coefficients_sizes() {
        let c = candidate_coefficients(8);
        let bits: usize = c.iter().map(|&(_, _, sc)| if sc { 1 } else { 2 }).sum();
        assert_eq!(bits, 63);
        assert_eq!(bits_per_block(8), 63);
    }

    #[test]
    fn shuffle_is_permutation() {
        let mut indices: Vec<usize> = (0..100).collect();
        let original = indices.clone();
        let key = [0xAAu8; 32];
        let mut rng = block_rng(&key, 0);
        shuffle_indices(&mut indices, &mut rng);
        indices.sort_unstable();
        assert_eq!(indices, original);
    }

    #[test]
    fn block_rng_is_deterministic() {
        let key = [0xCCu8; 32];
        let mut a = block_rng(&key, 7);
        let mut b = block_rng(&key, 7);
        assert_eq!(a.next_u32(), b.next_u32());
        assert_eq!(a.next_u32(), b.next_u32());
    }

    #[test]
    fn different_block_indices_produce_different_rng() {
        let key = [0xBBu8; 32];
        let mut a = block_rng(&key, 0);
        let mut b = block_rng(&key, 1);
        // Extremely unlikely to collide
        assert_ne!(a.next_u32(), b.next_u32());
    }
}
