use std::sync::atomic::Ordering;

use super::{ApiState, reply_text};

pub(crate) async fn handle_metrics(stream: &mut tokio::net::TcpStream, st: &ApiState) {
    let mut out = String::with_capacity(2048);
    let version = env!("CARGO_PKG_VERSION");
    out.push_str("# HELP vpcore_build_info Build information\n");
    out.push_str("# TYPE vpcore_build_info gauge\n");
    out.push_str(&format!("vpcore_build_info{{version=\"{version}\"}} 1\n\n"));

    let up = st.stats.upload.load(Ordering::Relaxed);
    let down = st.stats.download.load(Ordering::Relaxed);
    out.push_str("# HELP vpcore_traffic_upload_bytes_total Total uploaded bytes\n");
    out.push_str("# TYPE vpcore_traffic_upload_bytes_total counter\n");
    out.push_str(&format!("vpcore_traffic_upload_bytes_total {up}\n\n"));

    out.push_str("# HELP vpcore_traffic_download_bytes_total Total downloaded bytes\n");
    out.push_str("# TYPE vpcore_traffic_download_bytes_total counter\n");
    out.push_str(&format!("vpcore_traffic_download_bytes_total {down}\n\n"));

    let active_conns = st.conns.len();
    out.push_str("# HELP vpcore_connections_active Number of currently active connections\n");
    out.push_str("# TYPE vpcore_connections_active gauge\n");
    out.push_str(&format!("vpcore_connections_active {active_conns}\n\n"));

    let (budget_active, budget_rejected) = st.stats.conn_budget.snapshot();
    out.push_str("# HELP vpcore_connections_budget_active Number of budgeted connections\n");
    out.push_str("# TYPE vpcore_connections_budget_active gauge\n");
    out.push_str(&format!(
        "vpcore_connections_budget_active {budget_active}\n\n"
    ));

    out.push_str("# HELP vpcore_connections_budget_rejected_total Rejected connections due to budget limits\n");
    out.push_str("# TYPE vpcore_connections_budget_rejected_total counter\n");
    out.push_str(&format!(
        "vpcore_connections_budget_rejected_total {budget_rejected}\n\n"
    ));

    let pool = vp_common::bufpool::stats();
    out.push_str(
        "# HELP vpcore_bufpool_active_buffers Number of buffers currently active in buffer pool\n",
    );
    out.push_str("# TYPE vpcore_bufpool_active_buffers gauge\n");
    out.push_str(&format!(
        "vpcore_bufpool_active_buffers {}\n\n",
        pool.active
    ));

    out.push_str("# HELP vpcore_bufpool_idle_buffers Number of idle buffers in buffer pool\n");
    out.push_str("# TYPE vpcore_bufpool_idle_buffers gauge\n");
    out.push_str(&format!("vpcore_bufpool_idle_buffers {}\n\n", pool.idle));

    out.push_str("# HELP vpcore_bufpool_hits_total Buffer pool hit count\n");
    out.push_str("# TYPE vpcore_bufpool_hits_total counter\n");
    out.push_str(&format!("vpcore_bufpool_hits_total {}\n\n", pool.pool_hits));

    out.push_str("# HELP vpcore_bufpool_misses_total Buffer pool miss count\n");
    out.push_str("# TYPE vpcore_bufpool_misses_total counter\n");
    out.push_str(&format!(
        "vpcore_bufpool_misses_total {}\n\n",
        pool.pool_misses
    ));

    let users = st.user_manager.all_users();
    if !users.is_empty() {
        out.push_str("# HELP vpcore_user_upload_bytes_total Uploaded bytes by user\n");
        out.push_str("# TYPE vpcore_user_upload_bytes_total counter\n");
        for u in &users {
            let snap = u.snapshot();
            out.push_str(&format!(
                "vpcore_user_upload_bytes_total{{user=\"{}\"}} {}\n",
                snap.username, snap.upload
            ));
        }
        out.push('\n');

        out.push_str("# HELP vpcore_user_download_bytes_total Downloaded bytes by user\n");
        out.push_str("# TYPE vpcore_user_download_bytes_total counter\n");
        for u in &users {
            let snap = u.snapshot();
            out.push_str(&format!(
                "vpcore_user_download_bytes_total{{user=\"{}\"}} {}\n",
                snap.username, snap.download
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP vpcore_user_active_connections Number of active connections by user\n",
        );
        out.push_str("# TYPE vpcore_user_active_connections gauge\n");
        for u in &users {
            let snap = u.snapshot();
            out.push_str(&format!(
                "vpcore_user_active_connections{{user=\"{}\"}} {}\n",
                snap.username, snap.active_conns
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP vpcore_user_quota_bytes Total quota in bytes for user (0 = unlimited)\n",
        );
        out.push_str("# TYPE vpcore_user_quota_bytes gauge\n");
        for u in &users {
            let snap = u.snapshot();
            let q = snap.quota_bytes.unwrap_or(0);
            out.push_str(&format!(
                "vpcore_user_quota_bytes{{user=\"{}\"}} {q}\n",
                snap.username
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP vpcore_user_quota_exceeded Whether user quota is exceeded (1=true, 0=false)\n",
        );
        out.push_str("# TYPE vpcore_user_quota_exceeded gauge\n");
        for u in &users {
            let snap = u.snapshot();
            let exceeded = if snap.quota_exceeded { 1 } else { 0 };
            out.push_str(&format!(
                "vpcore_user_quota_exceeded{{user=\"{}\"}} {exceeded}\n",
                snap.username
            ));
        }
        out.push('\n');
    }

    reply_text(
        stream,
        200,
        "OK",
        &out,
        "text/plain; version=0.0.4; charset=utf-8",
    )
    .await;
}
