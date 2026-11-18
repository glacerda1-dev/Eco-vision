use std::{net::SocketAddr, str::FromStr};

use axum::Router;
use eco_vision::{
    application::eco_vision_service::EcoVisionService,
    infrastructure::{app_configuration::Config, database_repository::DatabaseRepository},
    presentation::http_api::{self, AppState},
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Inicializa o subscriber de logging. Respeita RUST_LOG; padrão: info.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,eco_vision=debug,tower_http=debug")),
        )
        .init();
    // Resolve .env beside Cargo.toml, independent of the shell's current directory.
    let project_env = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".env");
    if project_env.is_file() {
        dotenvy::from_path(project_env)?;
    }

    // Lê as credenciais do administrador agora, antes de construir a Config,
    // para que nunca entrem na estrutura de configuração de runtime.
    let admin_email = std::env::var("ECO_VISION_ADMIN_EMAIL")
        .ok()
        .filter(|s| !s.trim().is_empty());
    let admin_password = std::env::var("ECO_VISION_ADMIN_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty());

    let config = Config::from_env();
    let repository = DatabaseRepository::connect(&config.database_url).await?;
    repository.migrate_and_seed().await?;
    repository.cleanup_expired_sessions().await?;
    let service = EcoVisionService::new(repository, config)?;

    // Provisiona o admin e descarta as credenciais imediatamente.
    service
        .bootstrap_administrator(admin_email.as_deref(), admin_password.as_deref())
        .await?;
    drop(admin_email);
    drop(admin_password);

    let app = Router::new()
        .merge(http_api::router())
        .with_state(AppState::new(service))
        .layer(TraceLayer::new_for_http());

    let addr = SocketAddr::from_str(
        &std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".to_owned()),
    )?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Eco Vision ativa em http://{addr} (documentação: /docs)");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
