use std::sync::Arc;

use axum::extract::State;
use axum::http::header;
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use tokio::sync::Mutex;

use crate::sandbox_manager::SandboxManager;

pub type SharedManager = Arc<Mutex<SandboxManager>>;

pub fn spawn_dashboard(manager: SharedManager, port: u16) {
    tokio::spawn(async move {
        let app = Router::new()
            .route("/", get(serve_dashboard))
            .route("/api/metrics", get(serve_metrics))
            .with_state(manager);

        let addr = format!("0.0.0.0:{}", port);
        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        println!("✓ Dashboard running at http://localhost:{}", port);
        axum::serve(listener, app).await.unwrap();
    });
}

async fn serve_metrics(State(manager): State<SharedManager>) -> impl IntoResponse {
    let mgr = manager.lock().await;
    let metrics = mgr.all_metrics();
    (
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_string_pretty(&metrics).unwrap_or_default(),
    )
}

async fn serve_dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html>
<head>
    <title>CPEX WASM Plugin Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }
        h1 { font-size: 1.5rem; margin-bottom: 1.5rem; color: #38bdf8; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
        .card { background: #1e293b; border-radius: 0.75rem; padding: 1.5rem; border: 1px solid #334155; }
        .card h2 { font-size: 1rem; color: #94a3b8; margin-bottom: 1rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .metric { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #334155; }
        .metric:last-child { border-bottom: none; }
        .metric-label { color: #94a3b8; }
        .metric-value { font-weight: 600; font-variant-numeric: tabular-nums; }
        .metric-value.good { color: #4ade80; }
        .metric-value.warn { color: #fbbf24; }
        .metric-value.bad { color: #f87171; }
        .status { font-size: 0.75rem; color: #64748b; margin-top: 1rem; text-align: right; }
        .no-plugins { color: #64748b; font-style: italic; }
    </style>
</head>
<body>
    <h1>CPEX WASM Plugin Dashboard</h1>
    <div id="content"><p class="no-plugins">Loading...</p></div>
    <p class="status" id="status"></p>

    <script>
        async function refresh() {
            try {
                const res = await fetch('/api/metrics');
                const data = await res.json();
                const plugins = Object.entries(data);

                if (plugins.length === 0) {
                    document.getElementById('content').innerHTML = '<p class="no-plugins">No plugins loaded</p>';
                    return;
                }

                let html = '<div class="grid">';
                for (const [name, m] of plugins) {
                    html += `
                        <div class="card">
                            <h2>${name}</h2>
                            <div class="metric">
                                <span class="metric-label">Total Invocations</span>
                                <span class="metric-value">${m.total_invocations}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Total Fuel Consumed</span>
                                <span class="metric-value">${formatNumber(m.total_fuel_consumed)}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Last Invocation Fuel</span>
                                <span class="metric-value">${formatNumber(m.last_fuel_consumed)}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Traps (errors)</span>
                                <span class="metric-value ${m.total_traps > 0 ? 'bad' : 'good'}">${m.total_traps}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Network Allowed</span>
                                <span class="metric-value good">${m.network_allowed}</span>
                            </div>
                            <div class="metric">
                                <span class="metric-label">Network Denials</span>
                                <span class="metric-value ${m.network_denials > 0 ? 'warn' : 'good'}">${m.network_denials}</span>
                            </div>
                        </div>
                    `;
                }
                html += '</div>';
                document.getElementById('content').innerHTML = html;
                document.getElementById('status').textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
            } catch (e) {
                document.getElementById('status').textContent = `Error: ${e.message}`;
            }
        }

        function formatNumber(n) {
            if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
            if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
            if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
            return n.toString();
        }

        refresh();
        setInterval(refresh, 2000);
    </script>
</body>
</html>
"#;
