#[macro_use]
extern crate rocket;

// Imports
use anyhow::{Context, Result};
use clap::Parser;
use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, VerifyingKey};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::{http::Status, response::Redirect, Request, State};
use rocket_governor::{Method, Quota, RocketGovernable, RocketGovernor};
use sqlx::{migrate::Migrator, sqlite::SqlitePool, Sqlite};
use std::path::PathBuf;
use tracing::{debug, error};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

// Set up migrator instance
static MIGRATOR: Migrator = sqlx::migrate!(); // defaults to "./migrations"

// CLI arguments
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
  /// Path to the sqlite database. Defaults to redirs.sqlite.
  #[arg(short, long)]
  database: Option<PathBuf>,

  /// Port to listen on.
  #[arg(short, long, default_value_t = 8000)]
  port: u16,
}

// URL shortening request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct URLRequest<'r> {
  uid: i64,
  url: &'r str,
  signature: Signature,
}

// Admin registration request.
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
struct RegistrationRequest<'r> {
  uid: Option<i64>,
  name: &'r str,
  public_key: k256::PublicKey,
  signature: Option<Signature>,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
struct ShortenerResult {
  status: String,
  result: String,
}

pub struct RateLimitGuard;

impl<'r> RocketGovernable<'r> for RateLimitGuard {
  fn quota(_method: Method, _route_name: &str) -> Quota {
    Quota::per_second(Self::nonzero(1u32))
  }
}

async fn validate(
  db: &State<SqlitePool>,
  uid: i64,
  payload: &[u8],
  signature: &Signature,
) -> Result<(), Status> {
  // Get pubkey to check
  let pubkey_bytes: (Vec<u8>,) = sqlx::query_as("SELECT pubkey FROM admins WHERE id = $1")
    .bind(uid)
    .fetch_one(&**db)
    .await
    .map_err(|e| match e {
      sqlx::Error::RowNotFound => Status::Unauthorized,
      _ => {
        error!("Public key lookup failed: {}", e);
        Status::InternalServerError
      },
    })?;

  let pubkey = k256::ecdsa::VerifyingKey::from_sec1_bytes(&pubkey_bytes.0).map_err(|e| {
    error!("Internal error parsing pubkey from database: {}", e);
    Status::InternalServerError
  })?;

  pubkey
    .verify(payload, signature)
    .map_err(|_| Status::Unauthorized)
}

#[post("/api/shorten", format = "json", data = "<request>")]
async fn new(
  request: Json<URLRequest<'_>>,
  db: &State<SqlitePool>,
  _limitguard: RocketGovernor<'_, RateLimitGuard>,
) -> Result<Json<ShortenerResult>, Status> {
  validate(db, request.uid, request.url.as_bytes(), &request.signature).await?;
  let id = nano_id::base64::<4>();
  let p_url = url::Url::parse(request.url).map_err(|_| Status::UnprocessableEntity)?;
  sqlx::query("INSERT INTO urls(id, url, creator) VALUES ($1, $2, $3)")
    .bind(&id)
    .bind(p_url.as_str())
    .bind(&request.uid)
    .execute(&**db)
    .await
    .map_err(|e| {
      error!("Failed to register URL: {}", e);
      Status::InternalServerError
    })?;
  Ok(Json(ShortenerResult {
    status: "success".to_string(),
    result: id,
  }))
}

#[post("/api/admin", format = "json", data = "<request>")]
async fn add(
  request: Json<RegistrationRequest<'_>>,
  db: &State<SqlitePool>,
  _limitguard: RocketGovernor<'_, RateLimitGuard>,
) -> Result<Json<ShortenerResult>, Status> {
  let count: i64 = sqlx::query_scalar("SELECT COUNT(id) FROM admins")
    .fetch_one(&**db)
    .await
    .map_err(|e| {
      error!("Failed to get count: {}", e);
      Status::InternalServerError
    })?;

  if count != 0 {
    if request.uid.is_none() || request.signature.is_none() {
      return Err(Status::Unauthorized);
    }
    let mut payload_bytes = request.name.as_bytes().to_vec();
    payload_bytes.append(&mut request.public_key.to_sec1_bytes().to_vec());
    validate(
      db,
      request.uid.unwrap(),
      &payload_bytes,
      &request.signature.unwrap(),
    )
    .await?;
  }

  let vk: VerifyingKey = request.public_key.into();
  let bytes = vk.to_sec1_bytes();

  let result = sqlx::query("INSERT INTO admins(name, pubkey) VALUES ($1, $2)")
    .bind(request.name)
    .bind(bytes.as_ref())
    .execute(&**db)
    .await
    .map_err(|_| Status::InternalServerError)?;
  let row_id = result.last_insert_rowid();
  info!("Created admin with name {} ({})", request.name, row_id);
  Ok(Json(ShortenerResult {
    status: "success".to_string(),
    result: format!("{}", row_id),
  }))
}

#[get("/<code>")]
async fn code(code: &str, db: &State<SqlitePool>) -> Redirect {
  debug!("Loading code: {}", code);
  if code.len() > 4 {
    debug!("Code is too long!");
    return Redirect::to(uri!("https://google.com/"));
  }
  match sqlx::query_as::<Sqlite, (String,)>("SELECT url FROM urls WHERE id = $1")
    .bind(code)
    .fetch_one(&**db)
    .await
  {
    Ok(url) => {
      debug!("Matched redirect: {}", url.0);
      Redirect::to(url.0)
    },
    Err(e) => {
      debug!("Failed to find redirect for {}: {}", code, e);
      Redirect::to(uri!("https://google.com/"))
    },
  }
}

#[catch(default)]
fn default_catcher(status: Status, _request: &Request) -> Json<ShortenerResult> {
  Json(ShortenerResult {
    status: "error".to_string(),
    result: status.to_string(),
  })
}

async fn db_init(path: PathBuf) -> Result<SqlitePool> {
  let db_url = format!(
    "sqlite://{}?mode=rwc",
    path.to_str().context("DB path contains invalid Unicode")?
  );
  let db = SqlitePool::connect(&db_url)
    .await
    .context("Failed to open SQLite database")?;

  MIGRATOR
    .run(&db)
    .await
    .context("Failed to run database migrations")?;

  Ok(db)
}

#[launch]
async fn rocket() -> _ {
  tracing_subscriber::registry()
    .with(fmt::layer())
    .with(EnvFilter::from_default_env())
    .init();
  let args = Args::parse();
  let figment = rocket::Config::figment().merge(("port", args.port));
  let db_path = args
    .database
    .unwrap_or(PathBuf::try_from("redirs.sqlite").unwrap());
  let db = db_init(db_path).await.expect("Failed to open database");

  rocket::custom(figment)
    .manage(db)
    .register("/", catchers![default_catcher])
    .mount("/", routes![code, add, new])
}
