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

//! 2D FFT and block-wise frequency-domain operations for RGB images.

use crate::error::WsntpError;
use image::{Rgb, RgbImage};
use ndarray::Array2;
use num_complex::Complex;
use rayon::prelude::*;
use rustfft::FftPlanner;

struct RgbComplex {
    r: Array2<Complex<f64>>,
    g: Array2<Complex<f64>>,
    b: Array2<Complex<f64>>,
}

/// 2D FFT direction.
#[allow(dead_code)] // Inverse will be used by the embed module
pub(crate) enum FftDir {
    Forward,
    Inverse,
}

/// Apply a 1D FFT to every row of `data`.
pub(crate) fn fft_rows(
    data: &mut Array2<Complex<f64>>,
    planner: &mut FftPlanner<f64>,
    dir: FftDir,
) {
    let n = data.ncols();
    let fft = match dir {
        FftDir::Forward => planner.plan_fft_forward(n),
        FftDir::Inverse => planner.plan_fft_inverse(n),
    };
    for mut row in data.rows_mut() {
        let as_vec = row
            .as_slice_mut()
            .expect("ndarray row is not contiguous; expected C-order (row-major) layout");
        fft.process(as_vec);
    }
}

/// Apply a 1D FFT to every column of `data`.
pub(crate) fn fft_cols(
    data: &mut Array2<Complex<f64>>,
    planner: &mut FftPlanner<f64>,
    dir: FftDir,
) {
    let m = data.nrows();
    let n = data.ncols();
    let fft = match dir {
        FftDir::Forward => planner.plan_fft_forward(m),
        FftDir::Inverse => planner.plan_fft_inverse(m),
    };
    let mut col_buffer = vec![Complex::default(); m];
    for j in 0..n {
        for i in 0..m {
            col_buffer[i] = data[(i, j)];
        }
        fft.process(&mut col_buffer);
        for i in 0..m {
            data[(i, j)] = col_buffer[i];
        }
    }
}

/// Apply a 2D FFT (or inverse) in-place.
///
/// Forward: row FFT → column FFT.
/// Inverse: column FFT → row FFT → divide by N (total element count).
pub(crate) fn fft_2d(data: &mut Array2<Complex<f64>>, planner: &mut FftPlanner<f64>, dir: FftDir) {
    match dir {
        FftDir::Forward => {
            fft_rows(data, planner, FftDir::Forward);
            fft_cols(data, planner, FftDir::Forward);
        }
        FftDir::Inverse => {
            let n = (data.nrows() * data.ncols()) as f64;
            fft_cols(data, planner, FftDir::Inverse);
            fft_rows(data, planner, FftDir::Inverse);
            for v in data.iter_mut() {
                *v /= n;
            }
        }
    }
}

fn image_to_rgb_complex(image: &RgbImage) -> RgbComplex {
    let (width, height) = image.dimensions();
    let cols = width as usize;
    let rows = height as usize;
    let mut r = Array2::zeros((rows, cols));
    let mut g = Array2::zeros((rows, cols));
    let mut b = Array2::zeros((rows, cols));
    for (x, y, px) in image.enumerate_pixels() {
        let (y, x) = (y as usize, x as usize);
        r[(y, x)] = Complex::new(px[0] as f64, 0.0);
        g[(y, x)] = Complex::new(px[1] as f64, 0.0);
        b[(y, x)] = Complex::new(px[2] as f64, 0.0);
    }
    RgbComplex { r, g, b }
}

fn process_channel(data: Array2<Complex<f64>>) -> Array2<Complex<f64>> {
    let mut planner = FftPlanner::new();
    let mut data = data;
    fft_2d(&mut data, &mut planner, FftDir::Forward);
    data
}

fn compute_shifted_mags(
    channel: &Array2<Complex<f64>>,
    rows: usize,
    cols: usize,
    half_r: usize,
    half_c: usize,
) -> (Vec<f64>, f64, f64) {
    let mut min_log = f64::INFINITY;
    let mut max_log = f64::NEG_INFINITY;
    let mags: Vec<f64> = (0..rows)
        .flat_map(|y| (0..cols).map(move |x| (y, x)))
        .map(|(y, x)| {
            let src_y = (y + half_r) % rows;
            let src_x = (x + half_c) % cols;
            let v = (channel[(src_y, src_x)].norm() + 1.0).ln();
            min_log = min_log.min(v);
            max_log = max_log.max(v);
            v
        })
        .collect();
    (mags, min_log, max_log)
}

fn rgb_complex_to_image(data: &RgbComplex) -> RgbImage {
    let (rows, cols) = (data.r.nrows(), data.r.ncols());
    let width = cols as u32;
    let height = rows as u32;
    let half_r = rows / 2;
    let half_c = cols / 2;

    let results: Vec<_> = [&data.r, &data.g, &data.b]
        .into_par_iter()
        .map(|ch| compute_shifted_mags(ch, rows, cols, half_r, half_c))
        .collect();
    let [(r_mags, r_min, r_max), (g_mags, g_min, g_max), (b_mags, b_min, b_max)] =
        <[_; 3]>::try_from(results).unwrap();

    let scale = |v: f64, min: f64, max: f64| -> u8 {
        let range = max - min;
        if range == 0.0 {
            128
        } else {
            ((v - min) / range * 255.0).clamp(0.0, 255.0) as u8
        }
    };

    let mut img = RgbImage::new(width, height);
    for y in 0..rows {
        for x in 0..cols {
            let idx = y * cols + x;
            img.put_pixel(
                x as u32,
                y as u32,
                Rgb([
                    scale(r_mags[idx], r_min, r_max),
                    scale(g_mags[idx], g_min, g_max),
                    scale(b_mags[idx], b_min, b_max),
                ]),
            );
        }
    }
    img
}

/// Computes the 2D FFT magnitude spectrum of an RGB image.
///
/// Applies a forward 2D FFT to each color channel independently (in parallel),
/// then converts the complex frequency-domain data to a visual magnitude image.
/// Low frequencies are shifted to the image center, and magnitudes are
/// log-scaled to compress the wide dynamic range.
///
/// Returns an error if the image has zero width or height.
pub fn fft_picture(image: &RgbImage) -> Result<RgbImage, WsntpError> {
    if image.width() == 0 || image.height() == 0 {
        return Err(WsntpError::cli("image has zero dimension"));
    }

    let rgb = image_to_rgb_complex(image);
    let RgbComplex { r, g, b } = rgb;

    let results: Vec<_> = [r, g, b].into_par_iter().map(process_channel).collect();
    let [r_result, g_result, b_result]: [Array2<Complex<f64>>; 3] = results
        .try_into()
        .expect("par_iter over 3-elem array always returns 3 results");

    Ok(rgb_complex_to_image(&RgbComplex {
        r: r_result,
        g: g_result,
        b: b_result,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_image_dc_at_center() {
        let mut img = RgbImage::new(2, 2);
        for y in 0..2 {
            for x in 0..2 {
                img.put_pixel(x, y, Rgb([128, 128, 128]));
            }
        }
        let result = fft_picture(&img).unwrap();
        let dc = result.get_pixel(1, 1);
        assert!(dc[0] > 200, "DC R should be bright, got {}", dc[0]);
        let off = result.get_pixel(0, 0);
        assert!(off[0] < 10, "non-DC R should be dark, got {}", off[0]);
    }

    #[test]
    fn single_pixel_image() {
        let mut img = RgbImage::new(1, 1);
        img.put_pixel(0, 0, Rgb([200, 100, 50]));
        let result = fft_picture(&img).unwrap();
        let px = result.get_pixel(0, 0);
        assert_eq!(px[0], 128);
        assert_eq!(px[1], 128);
        assert_eq!(px[2], 128);
    }

    #[test]
    fn zero_dimension_rejected() {
        assert!(fft_picture(&RgbImage::new(0, 10)).is_err());
        assert!(fft_picture(&RgbImage::new(10, 0)).is_err());
    }

    #[test]
    fn preserves_dimensions() {
        let img = RgbImage::new(16, 8);
        let result = fft_picture(&img).unwrap();
        assert_eq!(result.width(), 16);
        assert_eq!(result.height(), 8);
    }

    #[test]
    fn fft_roundtrip_preserves_data() {
        let rows = 8;
        let cols = 8;
        let mut data = Array2::from_shape_fn((rows, cols), |(y, x)| {
            Complex::new((y * cols + x) as f64, 0.0)
        });
        let original = data.clone();

        let mut planner = FftPlanner::new();
        fft_2d(&mut data, &mut planner, FftDir::Forward);
        fft_2d(&mut data, &mut planner, FftDir::Inverse);

        for y in 0..rows {
            for x in 0..cols {
                let diff = (data[(y, x)] - original[(y, x)]).norm();
                assert!(diff < 1e-10, "roundtrip error at ({y},{x}): {diff}");
            }
        }
    }

    #[test]
    fn fftshift_ordering() {
        let w = 16u32;
        let h = 16u32;
        let mut img = RgbImage::new(w, h);
        for y in 0..h {
            for x in 0..w {
                let v = (x + y) as u8;
                img.put_pixel(x, y, Rgb([v, v, v]));
            }
        }
        let result = fft_picture(&img).unwrap();
        let center = result.get_pixel(w / 2, h / 2);
        let corner = result.get_pixel(0, 0);
        assert!(
            center[0] > corner[0],
            "DC at center should be brighter than corner"
        );
    }
}
