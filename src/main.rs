use std::process::ExitCode;

use moongate::client::{self, ClientId, ClientType, NewClient, RedirectUri};
use moongate::signing::SigningKey;
use moongate::{AppState, Config, MIGRATOR, app};
use sqlx::PgPool;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None => serve().await,
        Some("register-client") => register_client(&args[1..]).await,
        Some(_) => Err(USAGE.into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(%error, "moongate failed");
            ExitCode::FAILURE
        }
    }
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    let pool = PgPool::connect(&config.database_url).await?;
    MIGRATOR.run(&pool).await?;

    let pem = std::fs::read(&config.signing_key_file)
        .map_err(|_| "MOONGATE_SIGNING_KEY_FILE could not be read")?;
    let signing_key = SigningKey::from_pem(&pem)
        .map_err(|_| "MOONGATE_SIGNING_KEY_FILE is not a usable RSA key")?;
    drop(pem);
    signing_key.activate(&pool).await?;
    tracing::info!(kid = signing_key.kid(), "signing key active");
    moongate::maintenance::spawn(pool.clone());

    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!(bind = %config.bind, "moongate listening");
    let state = AppState::new(
        pool,
        config.issuer,
        config.upstream,
        std::sync::Arc::new(signing_key),
    )
    .with_client_ip_header(config.client_ip_header);
    // Connect info supplies the peer address used for per-IP rate limiting.
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Ctrl-C locally, SIGTERM from container runtimes and systemd.
async fn shutdown_signal() {
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate => {}
    }
    tracing::info!("shutting down");
}

const USAGE: &str = "usage: moongate [register-client --id <client_id> --name <display name> \
--type <confidential|public> --redirect-uri <uri>... [--post-logout-redirect-uri <uri>...]]";

/// Registers a client and prints its secret once. Config needs only DATABASE_URL.
async fn register_client(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let (mut id, mut name, mut client_type) = (None, None, None);
    let (mut redirect_uris, mut post_logout_redirect_uris) = (Vec::new(), Vec::new());
    let mut args = args.iter();
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(USAGE)?;
        match flag.as_str() {
            "--id" => id = Some(ClientId::parse(value).ok_or("invalid --id")?),
            "--name" => name = Some(value.clone()),
            "--type" => {
                client_type = Some(match value.as_str() {
                    "confidential" => ClientType::Confidential,
                    "public" => ClientType::Public,
                    _ => return Err("--type must be confidential or public".into()),
                })
            }
            "--redirect-uri" => redirect_uris.push(
                RedirectUri::parse(value).map_err(|e| format!("--redirect-uri {value} {e}"))?,
            ),
            "--post-logout-redirect-uri" => post_logout_redirect_uris.push(
                RedirectUri::parse(value)
                    .map_err(|e| format!("--post-logout-redirect-uri {value} {e}"))?,
            ),
            _ => return Err(USAGE.into()),
        }
    }
    let new = NewClient {
        id: id.ok_or(USAGE)?,
        display_name: name.ok_or(USAGE)?,
        client_type: client_type.ok_or(USAGE)?,
        redirect_uris,
        post_logout_redirect_uris,
    };
    if new.redirect_uris.is_empty() {
        return Err("at least one --redirect-uri is required".into());
    }

    let database_url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL must be set")?;
    let pool = PgPool::connect(&database_url).await?;
    MIGRATOR.run(&pool).await?;
    match client::register(&pool, &new).await? {
        Some(secret) => println!(
            "client_id: {}\nclient_secret: {}\n(shown once; store it now)",
            new.id.as_str(),
            secret.expose()
        ),
        None => println!("client_id: {} (public; no secret)", new.id.as_str()),
    }
    Ok(())
}
