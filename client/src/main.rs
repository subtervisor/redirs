use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use core::str;
use k256::{
    ecdsa::{signature::Signer, Signature},
    elliptic_curve::{rand_core::OsRng, ScalarPrimitive},
    PublicKey, Secp256k1,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    process::exit,
};
use tracing::{debug, error, info};
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

/// Redirs client app (URL shortener)
#[derive(Debug, Parser)]
#[clap(name = "redirs", version)]
pub struct RedirsAppArgs {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Register a new administrative user
    Register {
        /// Save credentials when registration is successful
        #[clap(long, short = 's', default_value_t = false)]
        save: bool,
        /// Name to use for credential registration
        #[clap()]
        name: String,
    },
    /// Shorten a URL
    Shorten {
        /// URL to shorten
        #[clap()]
        url: url::Url,
    },
    /// List existing shortened URLs
    List {
        /// Number of URLs to retrieve
        #[clap(long, short, default_value_t = 10)]
        count: u32,
        /// Offset from beginning of URLs to retrieve
        #[clap(long, short, default_value_t = 0)]
        offset: u32,
    },
}

#[derive(Debug, Args)]
struct GlobalOpts {
    /// Host URL for redirs server
    #[clap(long, short = 'H')]
    host: Option<url::Url>,

    /// User ID for admin user
    #[clap(long, short = 'u')]
    uid: Option<i64>,

    /// K-256 key for admin user
    #[clap(long, short = 'k')]
    key: Option<ScalarPrimitive<Secp256k1>>,

    /// Config file path override (for saving and loading)
    #[clap(long, short = 'c')]
    config_path: Option<std::path::PathBuf>,
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct RedirsConfig {
    uid: Option<i64>,
    host: Option<url::Url>,
    key: Option<ScalarPrimitive<Secp256k1>>,
}

#[derive(Serialize)]
struct URLRequest {
    uid: i64,
    url: url::Url,
    signature: Signature,
}

// Admin registration request.
#[derive(Serialize)]
struct RegistrationRequest {
    uid: Option<i64>,
    name: String,
    public_key: k256::PublicKey,
    signature: Option<Signature>,
}

// List entries
#[derive(Serialize)]
struct LookupRequest {
    uid: i64,
    limit: u32,
    offset: u32,
    signature: Signature,
}

#[derive(Deserialize, Debug)]
struct ShortenerResult {
    status: String,
    result: String,
}

#[derive(Deserialize, Debug)]
struct ShortenerEntry {
    id: String,
    url: url::Url,
    creator: String,
    created: String,
}

#[derive(Deserialize, Debug)]
struct ShortenerEntries {
    entries: Vec<ShortenerEntry>,
}

fn main() -> Result<()> {
    // Logging init
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // Parse CLI arguments
    let args = RedirsAppArgs::parse();

    // Load config file path. In order of priority:
    // 1. Explicitly declared path from CLI arguments
    // 2. .redirs.json in your home directory
    // 3. redirs.json in the current directory
    let config_file = args.global_opts.config_path.unwrap_or(
        dirs::home_dir()
            .and_then(|d| Some(d.join(".redirs.json")))
            .unwrap_or(PathBuf::from("redirs.json")),
    );

    // Try to read config, if it exists.
    debug!("Using config file path: {}", config_file.display());
    let mut config: RedirsConfig = if let Ok(input_config_file) = File::open(&config_file) {
        let reader = BufReader::new(input_config_file);
        serde_json::from_reader(reader).context("Failed to parse config file")?
    } else {
        RedirsConfig::default()
    };
    debug!(
        "Loaded config: {}",
        serde_json::to_string(&config).context("Failed to encode config JSON")?
    );

    // Override config with CLI args, if set
    if args.global_opts.host.is_some() {
        config.host = args.global_opts.host;
    }
    if args.global_opts.key.is_some() {
        config.key = args.global_opts.key;
    }
    if args.global_opts.uid.is_some() {
        config.uid = args.global_opts.uid;
    }

    // Validate auth settings
    if config.uid.is_none() || config.key.is_none() {
        config.uid = None;
        config.key = None;
    }
    debug!(
        "Runtime config: {}",
        serde_json::to_string(&config).context("Failed to encode config JSON")?
    );

    // Ensure required settings are set
    if config.host.is_none() {
        error!("No host specified.");
        exit(1);
    }
    let host = config.host.as_ref().unwrap();
    if !host.as_str().ends_with("/") {
        error!("Host must end in /");
        exit(1);
    }

    let client = reqwest::blocking::Client::new();
    match args.command {
        Command::Shorten { url } => {
            debug!("Shortening URL: {}", url);
            if config.key.is_none() || config.uid.is_none() {
                error!("Incomplete configuration specified.");
                exit(1);
            }
            let api_url = host
                .join("api/shorten")
                .context("Failed to generate API URL")?;

            debug!("API URL: {}", api_url);

            let secret_key = k256::SecretKey::new(config.key.unwrap());
            let signing_key: k256::ecdsa::SigningKey = secret_key.into();
            let signature: Signature = signing_key.sign(&url.as_str().as_bytes());
            let request = URLRequest {
                uid: config.uid.unwrap(),
                url,
                signature,
            };

            let http_result = client
                .post(api_url)
                .json(&request)
                .send()
                .context("Failed to send registration request")?;
            let result_bytes = http_result
                .bytes()
                .context("Failed to get response bytes")?;
            let result_str =
                str::from_utf8(&result_bytes).context("Failed to parse response as UTF-8")?;
            debug!("Raw response: {}", result_str);
            let result: ShortenerResult =
                serde_json::from_str(result_str).context("Failed to parse server response")?;

            if result.status == "success" {
                let short_url = host
                    .join(&result.result)
                    .context("Failed to join short URL")?;
                println!("{}", short_url);
            } else {
                anyhow::bail!("Failed to register: {}", result.result)
            }
        },
        Command::Register { save, name } => {
            info!("Registering user {} with save mode: {}", name, save);
            let new_privkey = k256::ecdsa::SigningKey::random(&mut OsRng);
            let new_pubkey: PublicKey = new_privkey.verifying_key().into();
            info!("Public key: {:?}", new_pubkey);
            let signature = config.key.and_then(|k| {
                let secret_key = k256::SecretKey::new(k);
                let signing_key: k256::ecdsa::SigningKey = secret_key.into();
                let mut payload = name.as_bytes().to_vec();
                payload.append(&mut new_pubkey.to_sec1_bytes().to_vec());
                Some(signing_key.sign(&payload))
            });
            debug!("Signature: {:?}", signature);
            let api_url = host
                .join("api/admin")
                .context("Failed to generate API URL")?;
            debug!("API URL: {}", api_url);
            let request = RegistrationRequest {
                uid: config.uid,
                name,
                public_key: new_pubkey,
                signature,
            };
            let http_result = client
                .post(api_url)
                .json(&request)
                .send()
                .context("Failed to send registration request")?;
            let result_bytes = http_result
                .bytes()
                .context("Failed to get response bytes")?;
            let result_str =
                str::from_utf8(&result_bytes).context("Failed to parse response as UTF-8")?;
            debug!("Raw response: {}", result_str);
            let result: ShortenerResult =
                serde_json::from_str(result_str).context("Failed to parse server response")?;
            if result.status == "success" {
                let uid: i64 = result.result.parse().context("Failed to parse admin UID")?;
                let privkey: k256::SecretKey = new_privkey.into();
                config.uid = uid.into();
                config.key = privkey.as_scalar_primitive().clone().into();
                if save {
                    debug!("Resulting config: {:?}", config);
                    let config_file_out = File::create(config_file)
                        .context("Failed to open config file for writing")?;
                    let mut writer = BufWriter::new(config_file_out);
                    serde_json::to_writer(&mut writer, &config)
                        .context("Failed to serialize and write config")?;
                    println!("Registered!");
                } else {
                    println!(
                        "{}",
                        serde_json::to_string(&config).context("Failed to encode config JSON")?
                    );
                }
            } else {
                anyhow::bail!("Failed to register: {}", result.result)
            }
        },
        Command::List { count, offset } => {
            debug!("Fetching URLs: Count {}, Offset {}", count, offset);
            if config.key.is_none() || config.uid.is_none() {
                error!("Incomplete configuration specified.");
                exit(1);
            }
            let api_url = host
                .join("api/list")
                .context("Failed to generate API URL")?;

            debug!("API URL: {}", api_url);

            let secret_key = k256::SecretKey::new(config.key.unwrap());
            let signing_key: k256::ecdsa::SigningKey = secret_key.into();
            let mut payload_bytes = count.to_be_bytes().to_vec();
            payload_bytes.append(&mut offset.to_be_bytes().to_vec());
            let signature: Signature = signing_key.sign(&payload_bytes);

            let request = LookupRequest {
                uid: config.uid.unwrap(),
                limit: count,
                offset,
                signature,
            };

            let http_result = client
                .post(api_url)
                .json(&request)
                .send()
                .context("Failed to send list request")?;
            let result_bytes = http_result
                .bytes()
                .context("Failed to get response bytes")?;
            let result_str =
                str::from_utf8(&result_bytes).context("Failed to parse response as UTF-8")?;
            debug!("Raw response: {}", result_str);
            if let Ok(mut entries) = serde_json::from_str::<ShortenerEntries>(result_str) {
                for entry in entries.entries.drain(..) {
                    println!(
                        "{}{} => {} (created by {} on {})",
                        config.host.as_ref().unwrap().to_string(),
                        entry.id,
                        entry.url.to_string(),
                        entry.creator,
                        entry.created
                    );
                }
            } else if let Ok(result) = serde_json::from_str::<ShortenerResult>(result_str) {
                if result.status == "success" {
                    error!(
                        "Got success status but we were expecting a list. Result: {}",
                        result.result
                    );
                } else {
                    anyhow::bail!("Failed to get list: {}", result.result)
                }
            } else {
                anyhow::bail!("Got bad response: {}", result_str);
            }
        },
    }
    Ok(())
}
