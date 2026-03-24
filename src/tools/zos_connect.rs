//! z/OS Connect tool handlers — health, services, APIs.

use crate::client::IbmZClient;
use psm_mcp_core::error::PsmMcpError;
use psm_mcp_core::input::{require_string, validate_name};
use psm_mcp_core::tool::{ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use std::sync::Arc;

/// Maximum identifier length for z/OS service names.
const MAX_ID_LEN: usize = 256;

// ── Health ─────────────────────────────────────────────────────────

pub struct HealthTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for HealthTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "zos_connect_health".into(),
            description: "Check z/OS Connect health".into(),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    async fn handle(&self, _arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let result = self
            .client
            .zos_request("GET", "/zosConnect/healthz", None)
            .await?;
        ToolResult::json(&result)
    }
}

// ── List Services ──────────────────────────────────────────────────

pub struct ListServicesTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for ListServicesTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "zos_connect_list_services".into(),
            description: "List z/OS Connect services".into(),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    async fn handle(&self, _arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let result = self
            .client
            .zos_request("GET", "/zosConnect/services", None)
            .await?;
        ToolResult::json(&result)
    }
}

// ── List APIs ──────────────────────────────────────────────────────

pub struct ListApisTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for ListApisTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "zos_connect_list_apis".into(),
            description: "List z/OS Connect APIs".into(),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    async fn handle(&self, _arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let result = self
            .client
            .zos_request("GET", "/zosConnect/apis", None)
            .await?;
        ToolResult::json(&result)
    }
}

// ── Get Service ────────────────────────────────────────────────────

pub struct GetServiceTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for GetServiceTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "zos_connect_get_service".into(),
            description: "Get z/OS Connect service details".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"service_name": {"type": "string"}},
                "required": ["service_name"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let service_name = require_string(&arguments, "service_name")?;
        validate_name(&service_name, "service_name", MAX_ID_LEN)?;
        let result = self
            .client
            .zos_request(
                "GET",
                &format!("/zosConnect/services/{service_name}"),
                None,
            )
            .await?;
        ToolResult::json(&result)
    }
}

// ── Call Service ───────────────────────────────────────────────────

pub struct CallServiceTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for CallServiceTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "zos_connect_call_service".into(),
            description: "Call a z/OS Connect service".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "service_name": {"type": "string"},
                    "payload": {"type": "object"}
                },
                "required": ["service_name"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let service_name = require_string(&arguments, "service_name")?;
        validate_name(&service_name, "service_name", MAX_ID_LEN)?;
        let body = arguments
            .get("payload")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let result = self
            .client
            .zos_request(
                "POST",
                &format!("/zosConnect/services/{service_name}"),
                Some(body),
            )
            .await?;
        ToolResult::json(&result)
    }
}
