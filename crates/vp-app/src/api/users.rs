use serde_json::json;
use std::sync::Arc;

use super::{ApiState, reply};

#[derive(serde::Deserialize)]
struct AddUserReq {
    name: Option<String>,
    secret: String,
    quota_bytes: Option<u64>,
    rate_limit_up: Option<f64>,
    rate_limit_down: Option<f64>,
    brutal_mbps: Option<u32>,
}

pub(crate) async fn handle_users_list(stream: &mut tokio::net::TcpStream, st: &ApiState) {
    let users = st.user_manager.all_users();
    let mut snapshots = Vec::with_capacity(users.len());
    for u in users {
        snapshots.push(u.snapshot());
    }
    snapshots.sort_by(|a, b| a.username.cmp(&b.username));
    reply(stream, 200, "OK", &json!({ "users": snapshots })).await;
}

pub(crate) async fn handle_user_get(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    target: &str,
) {
    if let Some(user) = st.user_manager.get_user_by_target(target) {
        reply(stream, 200, "OK", &json!(user.snapshot())).await;
    } else {
        reply(
            stream,
            404,
            "Not Found",
            &json!({"message": format!("user '{target}' not found")}),
        )
        .await;
    }
}

pub(crate) async fn handle_user_add(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    body_bytes: &[u8],
) {
    match serde_json::from_slice::<AddUserReq>(body_bytes) {
        Ok(r) => {
            let username = r.name.unwrap_or_else(|| r.secret.clone());
            let limiter = if r.rate_limit_up.is_some() || r.rate_limit_down.is_some() {
                Some(Arc::new(vp_core::BandwidthLimiter::from_bytes_per_sec(
                    r.rate_limit_up,
                    r.rate_limit_down,
                )))
            } else {
                None
            };
            let brutal = r
                .brutal_mbps
                .map(|m| Arc::new(vp_core::BrutalPacer::from_mbps(m)));
            let user = Arc::new(
                vp_core::UserAccount::new(username, r.secret, r.quota_bytes, limiter)
                    .with_brutal(brutal),
            );
            st.user_manager.add_user(user.clone());
            reply(stream, 200, "OK", &json!(user.snapshot())).await;
        }
        Err(e) => {
            reply(
                stream,
                400,
                "Bad Request",
                &json!({"message": format!("invalid user json: {e}")}),
            )
            .await;
        }
    }
}

pub(crate) async fn handle_user_delete(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    target: &str,
) {
    if let Some(user) = st.user_manager.remove_user(target) {
        let killed = st.conns.kill_by_user(&user.username);
        reply(
            stream,
            200,
            "OK",
            &json!({
                "message": format!("user '{}' removed", user.username),
                "killed_connections": killed,
            }),
        )
        .await;
    } else {
        reply(
            stream,
            404,
            "Not Found",
            &json!({"message": format!("user '{target}' not found")}),
        )
        .await;
    }
}

pub(crate) async fn handle_user_reset(
    stream: &mut tokio::net::TcpStream,
    st: &ApiState,
    target: &str,
) {
    if let Some(user) = st.user_manager.reset_traffic(target) {
        reply(stream, 200, "OK", &json!(user.snapshot())).await;
    } else {
        reply(
            stream,
            404,
            "Not Found",
            &json!({"message": format!("user '{target}' not found")}),
        )
        .await;
    }
}
