mod entity;
mod errors;
mod migration;
mod utils;

use axum::Extension;
use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::extract::Path;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::Response;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::IntoResponse;
use axum::response::Redirect;
use axum::routing::get;
use axum::routing::post;
use log::warn;
use log::{debug, error, info};
use rand::Rng;
use rand::distr::Alphanumeric;
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::Set;
use sea_orm::ColIdx;
use sea_orm::ColumnTrait;
use sea_orm::DbConn;
use sea_orm::EntityTrait;
use sea_orm::QueryFilter;
use sea_orm::QueryOrder;
use sea_orm::SqlErr;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde::Deserialize;
use serde::Serialize;
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::fmt::format;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tower_http::cors::Any;
use tower_http::cors::CorsLayer;

use crate::entity::client;
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
            db_path: "sqlite:///var/lib/rustive/db.db?mode=rwc".into(),
        }
    }
}

/// Simple LRU-ish cache for mapping IP -> token, capacity-limited.
/// Uses insertion order with eviction of oldest when capacity exceeded.
#[derive(Debug)]
struct ClientCache {
    map: HashMap<String, String>, // ip -> token
    order: VecDeque<String>,      // queue of IPs, oldest at front
    capacity: usize,
}

impl ClientCache {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn len(&self) -> usize {
        self.map.len()
    }

    fn get(&self, ip: &str) -> Option<String> {
        self.map.get(ip).cloned()
    }

    fn insert(&mut self, ip: String, token: String) {
        // if already exists, move to back (most recently inserted)
        if self.map.contains_key(&ip) {
            // update token then move ip to back
            self.map.insert(ip.clone(), token);
            // remove old position from order and push_back
            self.order.retain(|k| k != &ip);
            self.order.push_back(ip);
            return;
        }

        // Evict oldest if capacity reached
        if self.map.len() >= self.capacity {
            if let Some(old_ip) = self.order.pop_front() {
                self.map.remove(&old_ip);
            }
        }

        self.order.push_back(ip.clone());
        self.map.insert(ip, token);
    }

    fn remove(&mut self, ip: &str) {
        if self.map.remove(ip).is_some() {
            self.order.retain(|k| k != ip);
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
    pending_authorizations: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
    pending_ping_timers: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<()>>>>,
    client_cache: Arc<RwLock<ClientCache>>,
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

// spawn a refreshable 5s ping timer for `mac` if not exists
// if exists, caller should instead send a ping (see api_ping below).
async fn create_ping_timer_if_missing(state: State<AppState>, mac: String) {
    // create only if not already present
    {
        let pending_ping = state.pending_ping_timers.lock().await;
        if pending_ping.contains_key(&mac) {
            debug!("ping timer already exists for {}", mac);
            return;
        }
    }

    // cancel 15s timer if present (ping supersedes it)
    {
        let mut pending15 = state.pending_authorizations.lock().await;
        if let Some(handle) = pending15.remove(&mac) {
            debug!("Cancelling 15s timer because ping started for {}", mac);
            handle.abort();
        }
    }

    // create channel & spawn task
    let (tx, mut rx) = mpsc::unbounded_channel::<()>();
    {
        let mut pending_ping = state.pending_ping_timers.lock().await;
        pending_ping.insert(mac.clone(), tx);
    }

    let state_for_task = state.clone();
    let mac_for_task = mac.clone();

    tokio::spawn(async move {
        loop {
            let sleep_fut = sleep(Duration::from_secs(5));
            tokio::select! {
                _ = sleep_fut => {
                    // timeout: no ping for 5s -> auto-authorize
                    info!("Ping timer expired (5s) — auto-authorizing {}", mac_for_task);

                    let client_res = client::Entity::find()
                        .filter(client::Column::MacAddr.eq(mac_for_task.clone()))
                        .one(&state_for_task.db)
                        .await;

                    match client_res {
                        Ok(Some(existing)) => {
                            let mut am: client::ActiveModel = existing.into();
                            am.auth = Set(true);
                            if let Err(e) = am.update(&state_for_task.db).await {
                                error!("DB error when ping-auto-authorizing (update) {}: {}", mac_for_task, e);
                            }

                            #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
                            {
                                debug!("start giving access");
                                let result = execute_shell_script(
                                    "sudo",
                                    vec![
                                        "/usr/bin/white_list.sh".to_string(),
                                        "add".to_string(),
                                        "".to_string(),
                                        mac_for_task.clone(),
                                    ],
                                    Duration::from_secs(10),
                                )
                                .await;
                                debug!("{:?}", result);
                            }
                        }
                        Ok(None) => {
                            // // attempt to get IP is optional; insert with None or empty
                            // let new_client = client::ActiveModel {
                            //     mac_addr: Set(Some(mac_for_task.clone())),
                            //     ip_addr: Set(None),
                            //     auth: Set(true),
                            //     ..Default::default()
                            // };
                            // if let Err(e) = new_client.save(&state_for_task.db).await {
                            //     error!("DB error when ping-auto-authorizing (insert) {}: {}", mac_for_task, e);
                            // }

                            warn!("Client is not found");
                        }
                        Err(e) => {
                            error!("DB lookup error during ping-auto-authorize {}: {}", mac_for_task, e);
                        }
                    }

                    // {
                    //     let mut s = state_for_task.authorized_macs.write().await;
                    //     s.insert(mac_for_task.clone());
                    // }

                    // cleanup the pending ping entry
                    let mut pending_ping = state_for_task.pending_ping_timers.lock().await;
                    pending_ping.remove(&mac_for_task);
                    info!("Ping auto-authorization finished for {}", mac_for_task);
                    break;
                }
                recv = rx.recv() => {
                    match recv {
                        Some(_) => {
                            // refresh: client called ping -> restart loop (reset timer)
                            debug!("Received ping refresh for {}", mac_for_task);
                            continue;
                        }
                        None => {
                            // sender dropped -> cancellation (likely because /authorize arrived)
                            debug!("Ping sender dropped — cancel ping timer for {}", mac_for_task);
                            // ensure entry removed (may already be removed)
                            let mut pending_ping = state_for_task.pending_ping_timers.lock().await;
                            pending_ping.remove(&mac_for_task);
                            break;
                        }
                    }
                }
            }
        }
    });
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

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        let result = execute_shell_script(
            "sudo",
            vec!["/usr/bin/capture.sh".to_string()],
            Duration::from_secs(10),
        )
        .await?;
        debug!("{:?}", result);
    }

    let auth_set = Arc::new(RwLock::new(HashSet::<String>::new()));
    let allowed_ips = Arc::new(RwLock::new(HashSet::new()));
    for ip in &config.allowed_ips {
        allowed_ips.write().await.insert(ip.clone());
    }
    let allowed_hosts = Arc::new(RwLock::new(HashSet::new()));
    for h in &config.allowed_hosts {
        allowed_hosts.write().await.insert(h.clone());
    }

    let pending_map: Arc<Mutex<HashMap<String, JoinHandle<()>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let pending_ping_map: Arc<Mutex<HashMap<String, mpsc::UnboundedSender<()>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let client_cache = Arc::new(RwLock::new(ClientCache::new(100)));

    // Load clients from DB into cache (up to capacity)
    {
        // Attempt to load most recent clients first (assumes client::Column::Id exists)
        match client::Entity::find()
            .order_by_desc(client::Column::Id)
            .all(&conn)
            .await
        {
            Ok(clients) => {
                let mut cache = client_cache.write().await;
                for c in clients {
                    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
                    {
                        if c.auth == true {
                            debug!(
                                "giving access to {}",
                                c.ip_addr.clone().unwrap_or("".to_string())
                            );
                            let mac_for_task = c.mac_addr.unwrap_or("".to_string());
                            let ip_for_task = c.ip_addr.clone().unwrap_or("".to_string());
                            let result = execute_shell_script(
                                "sudo",
                                vec![
                                    "/usr/bin/white_list.sh".to_string(),
                                    "add".to_string(),
                                    ip_for_task,
                                    mac_for_task,
                                ],
                                Duration::from_secs(10),
                            )
                            .await;
                        } else {
                            debug!("not giving access to {:?}", c);
                        }
                    }

                    if cache.len() >= cache.capacity {
                        break;
                    }
                    if let (Some(ip), token) = (c.ip_addr.clone(), c.token.clone()) {
                        cache.insert(ip, token);
                    }
                }
                debug!("Loaded {} clients into runtime cache", cache.len());
            }
            Err(e) => {
                error!("Failed to preload client cache from DB: {}", e);
            }
        }
    }

    let state = AppState {
        config: config.clone(),
        authorized_macs: auth_set.clone(),
        allowed_ips: allowed_ips.clone(),
        allowed_hosts: allowed_hosts.clone(),
        db: conn,
        pending_authorizations: pending_map.clone(),
        pending_ping_timers: pending_ping_map.clone(),
        client_cache: client_cache.clone(),
    };

    let app = Router::new()
        .route("/", get(show_portal))
        .route("/captive", get(api_captive))
        .route("/{*full_path}", get(show_portal))
        .route("/authorize", post(api_authorize))
        .route("/dhcp", post(api_dhcp))
        .route("/ping", post(api_ping))
        .with_state(state.clone())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .unwrap();
    info!("Server is Running on {}", &config.listen_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(state))
    .await?;

    Ok(())
}

async fn api_authorize(state: State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let mut mac = String::new();
    let mut mac_for_task = String::new();
    let mut ip_for_task = String::new();
    let default_header_value = HeaderValue::from_static("127.0.0.1");
    let possible_remote_addr = headers.get("x-real-ip").unwrap_or(&default_header_value);
    let remote_addr = possible_remote_addr.to_str().unwrap_or("127.0.0.1");
    debug!("Client request with this ip: {}", remote_addr);
    {
        // let mut s = state.allowed_ips.write().await;
        let client = entity::client::Entity::find()
            .filter(entity::client::Column::IpAddr.eq(remote_addr))
            .one(&state.db)
            .await;
        if let Err(e) = client {
            error!("DB Error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(
                    serde_json::json!({"status":false, "redirect": null, "message": e.to_string()}),
                ),
            );
        }
        let possible_client = client.unwrap();
        if possible_client.is_none() {
            error!("DB Error: client is None");
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(
                    serde_json::json!({"status": false, "redirect": null, "message":"Client doesn't exist"}),
                ),
            );
        } else {
            let client = possible_client.clone().unwrap();
            let auth = client.auth;

            if auth {
                return (
                    StatusCode::OK,
                    axum::Json(
                        serde_json::json!({"status": true, "redirect": "https://podbox.plus/captive-portal/check-internet-access", "message": null}),
                    ),
                );
            }
            mac = client.mac_addr.unwrap();
            mac_for_task = mac.clone();
            ip_for_task = possible_client.clone().unwrap().ip_addr.unwrap();
            let mut client_active: entity::client::ActiveModel = possible_client.unwrap().into();
            client_active.auth = Set(true);
            if let Err(e) = client_active.update(&state.db).await {
                error!("DB Error: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(
                        serde_json::json!({"status": false, "redirect": null, "message": e.to_string()}),
                    ),
                );
            }
        }
    }

    // basic normalization
    // let mac = mac.replace("-", ":");

    // cancel any pending timer for this mac
    {
        let mut pending = state.pending_authorizations.lock().await;
        if let Some(handle) = pending.remove(&mac) {
            debug!("Canceling pending authorization timer for {}", mac);
            handle.abort();
        }
    }

    // cancel any pending ping timer (drop sender -> receiver sees None and quits)
    {
        let mut pending_ping = state.pending_ping_timers.lock().await;
        if pending_ping.remove(&mac).is_some() {
            debug!("Removed pending ping timer for {} due to authorize", mac);
        }
    }

    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
    {
        debug!("start giving access");
        let result = execute_shell_script(
            "sudo",
            vec![
                "/usr/bin/white_list.sh".to_string(),
                "add".to_string(),
                ip_for_task,
                mac_for_task,
            ],
            Duration::from_secs(10),
        )
        .await;
        debug!("{:?}", result);
    }

    (
        StatusCode::OK,
        axum::Json(
            serde_json::json!({"status": true, "redirect": "https://podbox.plus/captive-portal/check-internet-access", "message": null}),
        ),
    )
}

// spawn a 15s timer that will auto-authorize `mac` unless cancelled
async fn start_authorization_timer(state: State<AppState>, mac: String, ip: String) {
    // Cancel any existing pending timer for this mac and replace with a fresh one
    {
        let mut pending = state.pending_authorizations.lock().await;
        if let Some(old_handle) = pending.remove(&mac) {
            debug!("Aborting previous pending timer for {}", mac);
            old_handle.abort();
        }

        // Clone what we need into the spawned task
        let state_for_task = state.clone();
        let mac_for_task = mac.clone();
        let ip_for_task = ip.clone();

        let handle: JoinHandle<()> = tokio::spawn(async move {
            // Wait 15 seconds
            sleep(Duration::from_secs(15)).await;

            // // If authorization already happened while sleeping, bail out
            // {
            //     let s = state_for_task.authorized_macs.read().await;
            //     if s.contains(&mac_for_task) {
            //         debug!(
            //             "{} was authorized during timer, exiting timer.",
            //             mac_for_task
            //         );
            //         // remove pending entry (cleanup)
            //         let mut pending = state_for_task.pending_authorizations.lock().await;
            //         pending.remove(&mac_for_task);
            //         return;
            //     }
            // }

            // Not authorized -> perform auto-authorization: update DB + set in memory set
            info!("Auto-authorizing MAC {} after timer expiry", mac_for_task);
            let client = entity::client::Entity::find()
                .filter(entity::client::Column::MacAddr.eq(mac_for_task.clone()))
                .one(&state_for_task.db)
                .await;

            match client {
                Ok(Some(existing)) => {
                    let mut am: entity::client::ActiveModel = existing.into();
                    am.auth = Set(true);
                    if let Err(e) = am.update(&state_for_task.db).await {
                        error!(
                            "DB error when auto-authorizing (update) {}: {}",
                            mac_for_task, e
                        );
                    }
                    #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
                    {
                        let result = execute_shell_script(
                            "sudo",
                            vec![
                                "/usr/bin/white_list.sh".to_string(),
                                "add".to_string(),
                                ip_for_task,
                                mac_for_task.clone(),
                            ],
                            Duration::from_secs(10),
                        )
                        .await;
                        debug!("{:?}", result);
                    }
                }
                Ok(None) => {
                    // create a new client record with auth = true
                    // let new_client = entity::client::ActiveModel {
                    //     mac_addr: Set(Some(mac_for_task.clone())),
                    //     ip_addr: Set(Some(ip_for_task.clone())),
                    //     auth: Set(true),
                    //     ..Default::default()
                    // };
                    // if let Err(e) = new_client.save(&state_for_task.db).await {
                    //     error!(
                    //         "DB error when auto-authorizing (insert) {}: {}",
                    //         mac_for_task, e
                    //     );
                    // }
                    error!("client does not exists in DB");
                }
                Err(e) => {
                    error!(
                        "DB error when looking up client for auto-authorize {}: {}",
                        mac_for_task, e
                    );
                }
            }

            // // Mark in-memory authorized_macs
            // {
            //     let mut s = state_for_task.authorized_macs.write().await;
            //     s.insert(mac_for_task.clone());
            // }

            // cleanup pending map entry
            let mut pending = state_for_task.pending_authorizations.lock().await;
            pending.remove(&mac_for_task);
            info!("Auto-authorization complete for {}", mac_for_task);
        });

        // Insert the handle into the pending map
        pending.insert(mac, handle);
    }
}

fn generate_random_token(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

#[derive(Deserialize)]
struct DHCPReq {
    action: String,
    ip: String,
    mac: String,
}

async fn api_dhcp(
    state: State<AppState>,
    axum::Json(payload): axum::Json<DHCPReq>,
) -> impl IntoResponse {
    let action = payload.action;
    let mac = payload.mac.to_lowercase();
    let mac = mac.replace("-", ":");

    let ip = payload.ip;

    let mac_for_task = mac.clone();
    let ip_for_task = ip.clone();

    debug!("dhcp is called for {}: {},{} ", action, ip, mac);

    if action == "del" {
        // fetch client to retrieve IP for cache removal
        match entity::client::Entity::find()
            .filter(entity::client::Column::MacAddr.eq(&mac))
            .one(&state.db)
            .await
        {
            Ok(Some(found)) => {
                if let Some(ip_old) = found.ip_addr {
                    let mut cache = state.client_cache.write().await;
                    cache.remove(&ip_old);
                }
            }
            Ok(None) => {
                debug!("No DB client found for DHCP del (mac: {})", mac);
            }
            Err(e) => {
                error!("DB Error when fetching before delete: {}", e);
            }
        }

        // remove dhcp record
        if let Err(e) = entity::client::Entity::delete_many()
            .filter(entity::client::Column::MacAddr.eq(&mac))
            .exec(&state.db)
            .await
        {
            error!("DB Error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        } else {
            debug!("dhcp record is deleted successfully");
            // If there is any pending timer, abort and remove it
            let mut pending = state.pending_authorizations.lock().await;
            if let Some(handle) = pending.remove(&mac) {
                debug!("Aborting pending timer due to DHCP delete for {}", mac);
                handle.abort();
            }
            // If there is any ping timer, remove its sender (task will notice and exit)
            let mut pending_ping = state.pending_ping_timers.lock().await;
            if pending_ping.remove(&mac).is_some() {
                debug!("Removed pending ping timer due to DHCP delete for {}", mac);
            }
            #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
            {
                debug!("start deleting access");
                let result = execute_shell_script(
                    "sudo",
                    vec![
                        "/usr/bin/white_list.sh".to_string(),
                        "del".to_string(),
                        ip_for_task,
                        mac_for_task,
                    ],
                    Duration::from_secs(10),
                )
                .await;
                debug!("{:?}", result);
            }
        }
    } else {
        // add dhcp record
        let client = entity::client::Entity::find()
            .filter(entity::client::Column::MacAddr.eq(mac.clone()))
            .one(&state.db)
            .await;
        if let Err(e) = client {
            error!("DB Error: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }

        let possible_client = client.unwrap();
        if possible_client.is_none() {
            debug!("The client is new");

            let ip_check = entity::client::Entity::find()
                .filter(entity::client::Column::IpAddr.eq(ip.clone()))
                .one(&state.db)
                .await;
            if let Err(e) = ip_check {
                error!("DB Error: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }

            if let Some(possible_ip) = ip_check.unwrap() {
                debug!("found duplicate ip {}", possible_ip.ip_addr.unwrap());
                let delete_ip = entity::client::Entity::delete_by_id(possible_ip.id)
                    .exec(&state.db)
                    .await;
                if let Err(e) = delete_ip {
                    error!("DB Error: {}", e);
                    return StatusCode::INTERNAL_SERVER_ERROR;
                }
            }

            let token = generate_random_token(32);
            debug!("token is {token}");
            let client_active = entity::client::ActiveModel {
                mac_addr: Set(Some(mac.clone())),
                ip_addr: Set(Some(ip.clone())),
                auth: Set(false),
                token: Set(token.clone()),
                ..Default::default()
            };
            if let Err(e) = client_active.save(&state.db).await {
                error!("DB Error: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            // Insert into runtime cache
            {
                let mut cache = state.client_cache.write().await;
                cache.insert(ip.clone(), token);
            }
            // start_authorization_timer(state.clone(), mac.clone(), ip.clone()).await;
        } else {
            let mut client_active: entity::client::ActiveModel = possible_client.unwrap().into();

            let client_auth: bool = client_active.auth.clone().take().unwrap();
            debug!("The client is not new: {}", client_auth);
            #[cfg(all(target_arch = "aarch64", target_os = "linux"))]
            {
                if client_auth == true {
                    debug!("here to run script");
                    let result = execute_shell_script(
                        "sudo",
                        vec![
                            "/usr/bin/white_list.sh".to_string(),
                            "add".to_string(),
                            ip_for_task,
                            mac_for_task,
                        ],
                        Duration::from_secs(10),
                    )
                    .await;
                    debug!("{:?}", result);
                } else {
                    debug!("here2 to run script");
                }
            }
            debug!("here3 to run script");
            let prev_ip_opt = client_active.ip_addr.clone().take().unwrap_or(None);

            client_active.ip_addr = Set(Some(ip.clone()));
            if let Err(e) = client_active.update(&state.db).await {
                error!("DB Error: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
            // update runtime cache: remove old ip mapping (if different), insert new mapping
            // need token for this client: fetch token from DB quickly
            match entity::client::Entity::find()
                .filter(entity::client::Column::MacAddr.eq(mac.clone()))
                .one(&state.db)
                .await
            {
                Ok(Some(updated)) => {
                    if let Some(prev_ip) = prev_ip_opt {
                        if prev_ip != updated.ip_addr.clone().unwrap_or_default() {
                            let mut cache = state.client_cache.write().await;
                            cache.remove(&prev_ip);
                        }
                    }
                    if let (Some(ip_new), token) = (updated.ip_addr.clone(), updated.token.clone())
                    {
                        let mut cache = state.client_cache.write().await;
                        cache.insert(ip_new, token);
                    }
                }
                Ok(None) => {
                    debug!("Client not found after update when attempting to refresh cache");
                }
                Err(e) => {
                    error!("DB Error when refreshing cache after update: {}", e);
                }
            }
        }
    }
    StatusCode::OK
}

#[derive(Deserialize)]
struct PingReq {
    mac: String,
}

/// POST /ping
/// body: {"mac":"aa:bb:cc:..."}
/// - If a ping timer already exists -> send a refresh message.
/// - Otherwise cancel 15s timer (if any) and create a new ping timer that waits 5s and auto-authorizes on expiry.
async fn api_ping(
    state: State<AppState>,
    axum::Json(payload): axum::Json<PingReq>,
) -> impl IntoResponse {
    let mac = payload.mac.to_lowercase();
    let mac = mac.replace("-", ":");

    // If ping timer exists, refresh by sending to its sender
    {
        let mut pending_ping = state.pending_ping_timers.lock().await;
        if let Some(sender) = pending_ping.get(&mac) {
            if sender.send(()).is_err() {
                // receiver gone — remove and fall through to recreate
                debug!(
                    "Ping sender existed but failed to send; removing and recreating for {}",
                    mac
                );
                pending_ping.remove(&mac);
            } else {
                debug!("Refreshed ping timer for {}", mac);
                return StatusCode::OK;
            }
        }
    }

    // No existing ping timer -> cancel any 15s timer and create a ping timer
    {
        let mut pending15 = state.pending_authorizations.lock().await;
        if let Some(handle) = pending15.remove(&mac) {
            debug!("Canceling 15s timer because ping was received for {}", mac);
            handle.abort();
        }
    }

    // create ping timer (it will live until it expires or sender is dropped)
    create_ping_timer_if_missing(state.clone(), mac.clone()).await;

    StatusCode::OK
}

async fn api_captive(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    state: State<AppState>,
) -> impl IntoResponse {
    let mut token = String::new();
    let mut auth: bool = false;
    let remote_add_str = remote_addr.ip().to_string();
    let possible_default_header_value = HeaderValue::from_str(remote_add_str.as_str());

    let default_header_value = match possible_default_header_value {
        Ok(v) => v,
        Err(e) => {
            error!("Failed to create default header value: {}", e);
            HeaderValue::from_static("127.0.0.1")
        }
    };

    let possible_ip_str = headers.get("x-real-ip").unwrap_or(&default_header_value);
    let ip_str = possible_ip_str.to_str().unwrap_or("127.0.0.1");

    let possible_client = entity::client::Entity::find()
        .filter(entity::client::Column::IpAddr.eq(ip_str.to_string()))
        .one(&state.db)
        .await;

    match possible_client {
        Ok(Some(client)) => {
            token = client.token;
            auth = client.auth;
        }
        _ => {}
    }

    debug!("captive api: {ip_str}, {token}, {auth}");
    if auth {
        (
            StatusCode::OK,
            [
                (
                    "Location",
                    format!(
                        "https://podbox.plus/captive-portal/user-guide?token={}",
                        token
                    ),
                ),
                ("Content-Type", "application/captive+json".to_string()),
                ("Cache-Control", "private".to_string()),
            ],
            format!(
                "{{\"captive\": false, \"user-portal-url\": \
                \"https://podbox.plus/captive-portal/user-guide?token={}\", \"venue-info-url\":\"https://podbox.plus/\",\
                 \"seconds-remaining\": 3600, \"can-extend-session\": true}}",
                token
            ),
        )
    } else {
        (
            StatusCode::OK,
            [
                (
                    "Location",
                    format!(
                        "https://podbox.plus/captive-portal/user-guide?token={}",
                        token
                    ),
                ),
                ("Content-Type", "application/captive+json".to_string()),
                ("Cache-Control", "private".to_string()),
            ],
            format!(
                "{{\"captive\": true, \"user-portal-url\": \"https://podbox.plus/captive-portal/user-guide?token={}\", \"venue-info-url\":\"https://podbox.plus/\"}}",
                token
            ),
        )
    }
}

async fn show_portal(
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    state: State<AppState>,
    full_path: Option<Path<String>>,
) -> impl IntoResponse {
    let mut token = String::new();
    let ip_str = remote_addr.ip().to_string();

    // Try runtime cache first
    {
        let cache = state.client_cache.read().await;
        if let Some(t) = cache.get(&ip_str) {
            token = t;
        }
    }
    if token.is_empty() {
        let possible_client = entity::client::Entity::find()
            .filter(entity::client::Column::IpAddr.eq(remote_addr.ip().clone().to_string()))
            .one(&state.db)
            .await;
        match possible_client {
            Ok(Some(client)) => {
                token = client.token;
            }
            _ => {}
        }
    }
    debug!("full path is {full_path:?}, {ip_str}, {token}");
    (
        StatusCode::OK,
        [
            (
                "Location",
                format!(
                    "https://podbox.plus/captive-portal/user-guide?token={}",
                    token
                ),
            ),
            ("Content-Type", "application/captive+json".to_string()),
            ("Cache-Control", "private".to_string()),
        ],
        format!(
            "{{\"captive\": true, \"user-portal-url\": \"https://podbox.plus/captive-portal/user-guide?token={}\", \"venue-info-url\":\"https://podbox.plus/\"}}",
            token
        ),
    )
}
