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

//! Central error type for WSNTP.

use std::fmt;

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum WsntpError {
    /// User-facing CLI error (bad arguments, validation failures).
    Cli(String),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// Image decoding/encoding error.
    Image(image::ImageError),
    /// Cryptographic error (algorithm failure, not tamper detection).
    Crypto(String),
    /// Key not found in local key store.
    KeyNotFound(String),
}

impl WsntpError {
    /// Construct a CLI error from any string-like value.
    pub(crate) fn cli(msg: impl Into<String>) -> Self {
        Self::Cli(msg.into())
    }
}

impl fmt::Display for WsntpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cli(msg) => write!(f, "{msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Image(err) => write!(f, "image error: {err}"),
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Self::KeyNotFound(msg) => write!(f, "key not found: {msg}"),
        }
    }
}

impl std::error::Error for WsntpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cli(_) | Self::Crypto(_) | Self::KeyNotFound(_) => None,
            Self::Io(err) => Some(err),
            Self::Image(err) => Some(err),
        }
    }
}

impl From<String> for WsntpError {
    fn from(s: String) -> Self {
        Self::Cli(s)
    }
}

impl From<std::io::Error> for WsntpError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<image::ImageError> for WsntpError {
    fn from(err: image::ImageError) -> Self {
        Self::Image(err)
    }
}
