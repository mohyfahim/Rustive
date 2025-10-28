mod entity;
mod errors;
mod migration;
mod utils;

use axum::Extension;
use axum::Router;
use axum::extract::Path;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::routing::get;
use axum::routing::post;
use log::{debug, error, info};
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::Set;
use sea_orm::ColumnTrait;
use sea_orm::DbConn;
use sea_orm::EntityTrait;
use sea_orm::QueryFilter;
use sea_orm::SqlErr;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde::Deserialize;
use serde::Serialize;

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use crate::errors::RustiveError;
use crate::utils::execute_shell_script;
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Config {
    listen_addr: String,
    captive_url: String,
    lan_iface: String,
    wan_iface: String,
    // simple whitelists
    allowed_ips: Vec<String>,
    allowed_hosts: Vec<String>,
    // path to persist authorized macs
    db_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8090".into(),
            captive_url: "http://auth.local:8080/portal".into(),
            lan_iface: "eth0".into(),
            wan_iface: "eth1".into(),
            allowed_ips: vec!["8.8.8.8".into()],
            allowed_hosts: vec!["updates.example.com".into()],
            db_path: "sqlite://db.db?mode=rwc".into(),
        }
    }
}

#[derive(Clone, Debug)]
struct AppState {
    config: Config,
    // store normalized lowercase mac addresses
    authorized_macs: Arc<RwLock<HashSet<String>>>,
    // simple ip-based allow list
    allowed_ips: Arc<RwLock<HashSet<String>>>,
    allowed_hosts: Arc<RwLock<HashSet<String>>>,
    db: DatabaseConnection,
}

// async fn capture_all_traffics()  ->

// async fn setup_schema(db: &DbConn) -> Result<(), RustiveError> {
//     db.get_schema_builder()
// }

async fn shutdown_signal(state: AppState) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal;

        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {
            info!("Received CTRL+C");
            info!("{:?}",state);
            info!("{:p}", &state.config);
            info!("{:p}", &state.db);
            info!("{:p}", state.authorized_macs);
        },
        _ = terminate => {},
    }
}

#[tokio::main]
async fn main() -> Result<(), RustiveError> {
    env_logger::init();
    info!("Rustive Program is Starting");

    let config = Config::default();

    let conn = Database::connect(&config.db_path.clone())
        .await
        .expect("Database Connection Failed");
    if let Err(e) = migration::Migrator::up(&conn, None).await {
        return Err(RustiveError::DatabaseError(e));
    }

    let result = execute_shell_script("./capture.sh", vec![], Duration::from_secs(10)).await?;
    debug!("{:?}", result);

    let auth_set = Arc::new(RwLock::new(HashSet::<String>::new()));
    let allowed_ips = Arc::new(RwLock::new(HashSet::new()));
    for ip in &config.allowed_ips {
        allowed_ips.write().await.insert(ip.clone());
    }
    let allowed_hosts = Arc::new(RwLock::new(HashSet::new()));
    for h in &config.allowed_hosts {
        allowed_hosts.write().await.insert(h.clone());
    }

    let state = AppState {
        config: config.clone(),
        authorized_macs: auth_set.clone(),
        allowed_ips: allowed_ips.clone(),
        allowed_hosts: allowed_hosts.clone(),
        db: conn,
    };
    let app = Router::new()
        .route("/", get(show_portal))
        .route("/{*full_path}", get(show_portal))
        .route("/authorize", post(api_authorize))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .unwrap();
    info!("Server is Running on {}", &config.listen_addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(state))
        .await?;

    Ok(())
}

#[derive(Deserialize)]
struct AuthReq {
    mac: String,
}

async fn api_authorize(
    state: State<AppState>,
    axum::Json(payload): axum::Json<AuthReq>,
) -> impl IntoResponse {
    info!("{:?}", state);
    info!("{:p}", &state.config);
    info!("{:p}", &state.db);
    info!("{:p}", state.authorized_macs);

    let mac = payload.mac.to_lowercase();
    // basic normalization
    let mac = mac.replace("-", ":");

    {
        let mut s = state.authorized_macs.write().await;
        if s.insert(mac.clone()) {
            let client = entity::client::Entity::find()
                .filter(entity::client::Column::MacAddr.eq(mac.clone()))
                .one(&state.db)
                .await;
            if let Err(e) = client {
                error!("DB Error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(serde_json::json!({"status":"false","mac":mac})),
                );
            }
            let possible_client = client.unwrap();
            if possible_client.is_none() {
                error!("DB Error: client is None");
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(serde_json::json!({"message":"Client doesn't exist"})),
                );
            } else {
                let mut client_active: entity::client::ActiveModel =
                    possible_client.unwrap().into();
                client_active.auth = Set(true);
                if let Err(e) = client_active.update(&state.db).await {
                    error!("DB Error: {}", e);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(serde_json::json!({"status":"false","mac":mac})),
                    );
                }
            }
        }
    }

    // // run iptables rule to allow traffic from this mac on FORWARD chain
    // // WARNING: This uses `iptables` and requires root.
    // let iface = &state.config.lan_iface;
    // let mac_clone = mac.clone();
    // tokio::spawn(async move {
    //     if let Err(e) = add_iptables_allow(&mac_clone, iface).await {
    //         error!("Failed to run iptables for {}: {}", mac_clone, e);
    //     } else {
    //         info!("Added iptables rule to allow MAC {}", mac_clone);
    //     }
    // });

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({"result": {"mac": mac}})),
    )
}

async fn show_portal(
    _state: State<AppState>,
    full_path: Option<Path<String>>,
) -> impl IntoResponse {
    debug!("full path is {full_path:?}");
    (StatusCode::FOUND, [("Location", "https://podbox.plus")])
}
