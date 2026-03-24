//! IBM z/OS MCP Server — secure bridge to IBM Cloud Key Protect and z/OS Connect.
//!
//! # Security Architecture
//!
//! This server enforces defense-in-depth for all operations:
//! - **Input validation**: All identifiers bounded via psm-mcp-core input validators
//! - **Payload limits**: Max 64 KB payloads, 1 MB JSON-RPC messages
//! - **Credential hygiene**: API keys masked in logs
//! - **Environment isolation**: Required vars checked at startup, optional vars warned
//! - **No shell execution**: All operations via structured HTTP APIs
//! - **URL construction safety**: No user-controlled path segments beyond validated identifiers

mod client;
mod tools;

use client::IbmZClient;
use psm_mcp_transport::server::McpServer;
use std::sync::Arc;
use tools::key_protect::{
    CreateKeyTool, DeleteKeyTool, GetKeyPoliciesTool, GetKeyTool, ListKeysTool, RotateKeyTool,
    UnwrapKeyTool, WrapKeyTool,
};
use tools::zos_connect::{
    CallServiceTool, GetServiceTool, HealthTool, ListApisTool, ListServicesTool,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    IbmZClient::check_env_vars();
    let client = Arc::new(IbmZClient::new());

    let mut server = McpServer::new("ibmz-mcp-server", env!("CARGO_PKG_VERSION"));

    // Key Protect tools
    server.register_tool(ListKeysTool {
        client: Arc::clone(&client),
    });
    server.register_tool(CreateKeyTool {
        client: Arc::clone(&client),
    });
    server.register_tool(GetKeyTool {
        client: Arc::clone(&client),
    });
    server.register_tool(DeleteKeyTool {
        client: Arc::clone(&client),
    });
    server.register_tool(RotateKeyTool {
        client: Arc::clone(&client),
    });
    server.register_tool(WrapKeyTool {
        client: Arc::clone(&client),
    });
    server.register_tool(UnwrapKeyTool {
        client: Arc::clone(&client),
    });
    server.register_tool(GetKeyPoliciesTool {
        client: Arc::clone(&client),
    });

    // z/OS Connect tools
    server.register_tool(HealthTool {
        client: Arc::clone(&client),
    });
    server.register_tool(ListServicesTool {
        client: Arc::clone(&client),
    });
    server.register_tool(ListApisTool {
        client: Arc::clone(&client),
    });
    server.register_tool(GetServiceTool {
        client: Arc::clone(&client),
    });
    server.register_tool(CallServiceTool {
        client: Arc::clone(&client),
    });

    tracing::info!("ibmz-mcp-server starting with {} tools", 13);

    if let Err(e) = server.run_stdio().await {
        tracing::error!(error = %e, "server exited with error");
        std::process::exit(1);
    }
}
