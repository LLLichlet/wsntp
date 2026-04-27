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

//! Quantization Index Modulation (QIM) for embedding individual bits into
//! floating-point values in the frequency domain.

use num_complex::Complex;

/// QIM quantization step size.
///
/// Chosen to balance robustness vs. imperceptibility for 8-bit images after
/// 8×8 block-wise 2D FFT.  Each unit of Δ on an FFT coefficient translates
/// to roughly Δ/64 ≈ 0.75 gray levels per pixel at the output, which is
/// enough to survive integer rounding yet invisible to the eye.
///
/// A larger Δ tolerates more post-processing (JPEG, resize), a smaller Δ
/// leaves less visible trace.  Tune per deployment.
pub(crate) const DELTA: f64 = 48.0;

/// Embed a single bit into a real value via quantization index modulation.
///
/// Quantizes `value` to the nearest multiple of `delta` whose parity matches
/// `bit`.  When the nearest multiple has wrong parity, the adjacent multiple
/// that lies closer to the original value is chosen.
pub(crate) fn embed_bit(value: f64, bit: bool, delta: f64) -> f64 {
    debug_assert!(delta > 0.0, "QIM delta must be positive");

    let q = (value / delta).round();
    let parity = checked_parity(q);

    if bit as i64 == parity {
        return q * delta;
    }

    // The rounded multiple has wrong parity — pick the adjacent multiple
    // that lies closer to the original value, minimising distortion.
    let adjusted = if value / delta >= q { q + 1.0 } else { q - 1.0 };
    adjusted * delta
}

/// Extract a single bit from a real value via quantization index modulation.
///
/// Returns the parity (bit value) of the nearest integer multiple of `delta`.
pub(crate) fn extract_bit(value: f64, delta: f64) -> bool {
    debug_assert!(delta > 0.0, "QIM delta must be positive");

    let q = (value / delta).round();
    checked_parity(q) != 0
}

/// Embed two bits (real, imag) into a complex coefficient.
pub(crate) fn embed_complex(c: &Complex<f64>, bits: (bool, bool), delta: f64) -> Complex<f64> {
    Complex::new(
        embed_bit(c.re, bits.0, delta),
        embed_bit(c.im, bits.1, delta),
    )
}

/// Extract two bits (real, imag) from a complex coefficient.
pub(crate) fn extract_complex(c: &Complex<f64>, delta: f64) -> (bool, bool) {
    (extract_bit(c.re, delta), extract_bit(c.im, delta))
}

/// Cast the rounded quotient to i64 for parity check.
///
/// `f64` can exactly represent all integers up to 2^53, and image FFT
/// coefficients stay well below i64::MAX (~9e18).  The assertion catches
/// pathological inputs before the cast would become UB.
fn checked_parity(q: f64) -> i64 {
    debug_assert!(
        q >= (i64::MIN as f64) && q <= (i64::MAX as f64),
        "QIM quotient out of safe cast range"
    );
    q as i64 & 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_bit_correct_parity_already() {
        let got = embed_bit(0.0, false, DELTA);
        assert_eq!(got, 0.0);

        let got = embed_bit(DELTA, true, DELTA);
        assert_eq!(got, DELTA);
    }

    #[test]
    fn embed_bit_flips_to_nearest() {
        let got = embed_bit(0.0, true, DELTA);
        assert!(
            (got - DELTA).abs() < 1e-10 || (got + DELTA).abs() < 1e-10,
            "expected ±DELTA, got {got}"
        );

        // 0.6Δ is closer to 0Δ than 1Δ, so lands on 0
        let got = embed_bit(0.6 * DELTA, false, DELTA);
        assert!(
            (got - 0.0).abs() < 1e-10,
            "0.6Δ should round to 0, got {got}"
        );
    }

    #[test]
    fn embed_then_extract_roundtrip() {
        for &v in &[-200.0, -50.0, 0.0, 50.0, 200.0, 487.3, -123.45] {
            for &b in &[false, true] {
                let embedded = embed_bit(v, b, DELTA);
                let extracted = extract_bit(embedded, DELTA);
                assert_eq!(
                    extracted, b,
                    "value={v}, bit={b}, embedded={embedded}, extracted={extracted}"
                );
            }
        }
    }

    #[test]
    fn roundtrip_with_custom_delta() {
        for &d in &[1.0, 16.0, 100.0] {
            for &v in &[-50.0, 0.0, 50.0, 273.15] {
                for &b in &[false, true] {
                    assert_eq!(
                        extract_bit(embed_bit(v, b, d), d),
                        b,
                        "delta={d}, value={v}, bit={b}"
                    );
                }
            }
        }
    }

    #[test]
    fn complex_roundtrip() {
        let c = Complex::new(123.4, -567.8);
        let bits = (true, false);
        let embedded = embed_complex(&c, bits, DELTA);
        let extracted = extract_complex(&embedded, DELTA);
        assert_eq!(extracted, bits);
    }

    #[test]
    fn extract_from_zero() {
        assert!(!extract_bit(0.0, DELTA));
        assert!(extract_bit(DELTA, DELTA));
        // -1 is odd in two's complement → bit 1 (true)
        assert!(extract_bit(-DELTA, DELTA));
    }

    #[test]
    fn embedding_distortion_is_bounded() {
        for &v in &[0.0, 50.0, -50.0, 300.0, -300.0] {
            for &b in &[false, true] {
                let embedded = embed_bit(v, b, DELTA);
                assert!(
                    (embedded - v).abs() <= DELTA + 1e-10,
                    "distortion too large: v={v}, bit={b}, embedded={embedded}"
                );
            }
        }
    }

    #[test]
    fn exact_integer_multiple_wrong_parity() {
        // v = 2*Δ, even parity → bit false stays, bit true flips to nearest odd (1*Δ or 3*Δ)
        let got = embed_bit(2.0 * DELTA, true, DELTA);
        assert!(
            (got - DELTA).abs() < 1e-10 || (got - 3.0 * DELTA).abs() < 1e-10,
            "expected Δ or 3Δ, got {got}"
        );
    }
}
