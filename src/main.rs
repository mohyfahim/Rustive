mod errors;
mod migration;
mod utils;

use axum::Extension;
use axum::Router;
use axum::response::IntoResponse;
use axum::routing::get;
use log::debug;
use log::info;
use sea_orm::DbConn;
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
            listen_addr: "0.0.0.0:8080".into(),
            captive_url: "http://auth.local:8080/portal".into(),
            lan_iface: "eth0".into(),
            wan_iface: "eth1".into(),
            allowed_ips: vec!["8.8.8.8".into()],
            allowed_hosts: vec!["updates.example.com".into()],
            db_path: "authorized_macs.json".into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: Config,
    // store normalized lowercase mac addresses
    authorized_macs: Arc<RwLock<HashSet<String>>>,
    // simple ip-based allow list
    allowed_ips: Arc<RwLock<HashSet<String>>>,
    allowed_hosts: Arc<RwLock<HashSet<String>>>,
}

// async fn capture_all_traffics()  ->

// async fn setup_schema(db: &DbConn) -> Result<(), RustiveError> {
//     db.get_schema_builder()
// }

#[tokio::main]
async fn main() -> Result<(), RustiveError> {
    env_logger::init();
    info!("Rustive Program is Starting");

    let conn = Database::connect("sqlite://db.db?mode=rwc")
        .await
        .expect("Database Connection Failed");
    if let Err(e) = migration::Migrator::up(&conn, None).await {
        return Err(RustiveError::DatabaseError(e));
    }
    if let Err(e) = conn.close().await {
        return Err(RustiveError::DatabaseError(e));
    }
    // let result = execute_shell_script("./capture.sh", vec![], Duration::from_secs(10)).await?;
    // debug!("{:?}", result);

    // let config = Config::default();
    // let auth_set = Arc::new(RwLock::new(HashSet::new()));
    // let allowed_ips = Arc::new(RwLock::new(HashSet::new()));
    // for ip in &config.allowed_ips {
    //     allowed_ips.write().await.insert(ip.clone());
    // }
    // let allowed_hosts = Arc::new(RwLock::new(HashSet::new()));
    // for h in &config.allowed_hosts {
    //     allowed_hosts.write().await.insert(h.clone());
    // }

    // let state = AppState {
    //     config: config.clone(),
    //     authorized_macs: auth_set.clone(),
    //     allowed_ips: allowed_ips.clone(),
    //     allowed_hosts: allowed_hosts.clone(),
    // };
    // let shared_state = Extension(state.clone());
    // let app = Router::new().route("/authorize", get(api_authorize));
    Ok(())
}

#[derive(Deserialize)]
struct AuthReq {
    mac: String,
}

// async fn api_authorize(
//     Extension(state): Extension<AppState>,
//     axum::Json(payload): axum::Json<AuthReq>,
// ) -> impl IntoResponse {
//     let mac = payload.mac.to_lowercase();
//     // basic normalization
//     let mac = mac.replace("-", ":");

//     // persist
//     {
//         let mut s = state.authorized_macs.write().await;
//         if s.insert(mac.clone()) {
//             // if let Err(e) = persist_db(&state.config.db_path, &s) {
//             //     error!("Failed to persist db: {}", e);
//             // }
//         }
//     }

//     // run iptables rule to allow traffic from this mac on FORWARD chain
//     // WARNING: This uses `iptables` and requires root.
//     let iface = &state.config.lan_iface;
//     let mac_clone = mac.clone();
//     tokio::spawn(async move {
//         if let Err(e) = add_iptables_allow(&mac_clone, iface).await {
//             error!("Failed to run iptables for {}: {}", mac_clone, e);
//         } else {
//             info!("Added iptables rule to allow MAC {}", mac_clone);
//         }
//     });

//     axum::Json(serde_json::json!({"status":"ok","mac":mac}))
// }
