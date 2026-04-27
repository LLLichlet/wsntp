#![forbid(unsafe_code)]

mod block;
mod crypto;
mod embed;
mod error;
mod extract;
mod fft;
mod keys;
mod payload;
mod qim;

use crate::crypto::generate_keypair;
use crate::embed::embed;
use crate::error::WsntpError;
use crate::extract::extract;
use crate::fft::fft_picture;
use crate::keys::KeyStore;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use clap::{Parser, Subcommand};
use image::ImageReader;
use std::process;

#[derive(Parser)]
#[command(name = "wsntp", about = "What's Signed On The Picture?")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new Ed25519 key pair and store it
    GenKey {
        /// Alias for the new key
        alias: String,
    },
    /// Embed a signed message into an image
    Embed {
        /// Input image file
        #[arg(short = 'i', long)]
        input: String,
        /// Output image file
        #[arg(short = 'o', long)]
        output: String,
        /// Key alias in the local store
        #[arg(short = 'k', long)]
        key: Option<String>,
        /// Raw base64-encoded secret key (alternative to --key)
        #[arg(long = "secret")]
        secret_key: Option<String>,
        /// Message to embed
        #[arg(short = 'm', long)]
        message: String,
    },
    /// Extract and verify a signed message from an image
    Extract {
        /// Input image file
        #[arg(short = 'i', long)]
        input: String,
        /// Key alias in the local store
        #[arg(short = 'k', long)]
        key: Option<String>,
        /// Raw base64-encoded public key (alternative to --key)
        #[arg(long = "public")]
        public_key: Option<String>,
    },
    /// List stored key aliases
    ListKeys,
    /// Set the default key alias
    SetDefault {
        /// Alias to set as default
        alias: String,
    },
    /// Show the 2D FFT magnitude spectrum of an image
    Fft {
        /// Input image file
        #[arg(short = 'i', long)]
        input: String,
        /// Output image file
        #[arg(short = 'o', long)]
        output: String,
    },
}

fn run() -> Result<(), WsntpError> {
    let cli = Cli::parse();

    match cli.command {
        Command::GenKey { alias } => cmd_gen_key(&alias),
        Command::Embed {
            input,
            output,
            key,
            secret_key,
            message,
        } => cmd_embed(&input, &output, key.as_deref(), secret_key.as_deref(), &message),
        Command::Extract {
            input,
            key,
            public_key,
        } => cmd_extract(&input, key.as_deref(), public_key.as_deref()),
        Command::ListKeys => cmd_list_keys(),
        Command::SetDefault { alias } => cmd_set_default(&alias),
        Command::Fft { input, output } => {
            let img = ImageReader::open(&input)?.decode()?.into_rgb8();
            let ffted = fft_picture(&img)?;
            ffted.save(&output)?;
            Ok(())
        }
    }
}

fn cmd_gen_key(alias: &str) -> Result<(), WsntpError> {
    let store = KeyStore::new()?;
    let kp = generate_keypair();
    store.save(alias, &kp)?;
    let b64_pub = BASE64.encode(kp.public);
    println!("Key pair '{alias}' created.  Public key: {b64_pub}");
    Ok(())
}

fn cmd_embed(
    input: &str,
    output: &str,
    alias: Option<&str>,
    raw_secret: Option<&str>,
    message: &str,
) -> Result<(), WsntpError> {
    let secret_seed = load_secret(alias, raw_secret)?;

    let img = ImageReader::open(input)?.decode()?.into_rgb8();
    let result = embed(&img, &secret_seed, message.as_bytes())?;
    result.save(output)?;

    println!("Message embedded into '{output}'.");
    Ok(())
}

fn cmd_extract(
    input: &str,
    alias: Option<&str>,
    raw_public: Option<&str>,
) -> Result<(), WsntpError> {
    let public_key = load_public(alias, raw_public)?;

    let img = ImageReader::open(input)?.decode()?.into_rgb8();
    let msg = extract(&img, &public_key)?;

    // Try to display as UTF-8, falling back to hex
    match std::str::from_utf8(&msg) {
        Ok(s) => println!("{s}"),
        Err(_) => {
            let hex: String = msg.iter().map(|b| format!("{b:02x}")).collect();
            println!("(non-UTF-8, hex) {hex}");
        }
    }
    Ok(())
}

fn cmd_list_keys() -> Result<(), WsntpError> {
    let store = KeyStore::new()?;
    let aliases = store.list()?;
    if aliases.is_empty() {
        println!("No keys stored.");
    } else {
        let default = store.default_alias()?.unwrap_or_default();
        for a in &aliases {
            if *a == default {
                println!("* {a}");
            } else {
                println!("  {a}");
            }
        }
    }
    Ok(())
}

fn cmd_set_default(alias: &str) -> Result<(), WsntpError> {
    KeyStore::new()?.set_default_alias(alias)?;
    println!("Default key set to '{alias}'.");
    Ok(())
}

/// Resolve a 32-byte secret seed from either an alias or a raw base64 string.
fn load_secret(alias: Option<&str>, raw: Option<&str>) -> Result<[u8; 32], WsntpError> {
    if let Some(b64) = raw {
        return decode_key(b64, "secret key");
    }
    let store = KeyStore::new()?;
    let alias = resolve_alias(&store, alias)?;
    store.load_secret(alias)
}

/// Resolve a 32-byte public key from either an alias or a raw base64 string.
fn load_public(alias: Option<&str>, raw: Option<&str>) -> Result<[u8; 32], WsntpError> {
    if let Some(b64) = raw {
        return decode_key(b64, "public key");
    }
    let store = KeyStore::new()?;
    let alias = resolve_alias(&store, alias)?;
    store.load_public(alias)
}

/// If an alias is given, use it.  Otherwise, fall back to the default alias.
fn resolve_alias<'a>(store: &'a KeyStore, alias: Option<&'a str>) -> Result<&'a str, WsntpError> {
    match alias {
        Some(a) => Ok(a),
        None => {
            let default = store.default_alias()?.ok_or_else(|| {
                WsntpError::cli("no key specified and no default key set")
            })?;
            // Return a leaked string — only used ephemerally in CLI context
            // before process exit, so the leak is harmless.
            Ok(Box::leak(default.into_boxed_str()))
        }
    }
}

fn decode_key(b64: &str, label: &str) -> Result<[u8; 32], WsntpError> {
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|_| WsntpError::cli(format!("invalid base64 {label}")))?;
    bytes
        .try_into()
        .map_err(|_| WsntpError::cli(format!("{label} must be 32 bytes")))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        process::exit(1);
    }
}
