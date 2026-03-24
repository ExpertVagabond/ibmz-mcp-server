//! Key Protect tool handlers — list, create, get, delete, rotate, wrap, unwrap, policies.

use crate::client::IbmZClient;
use psm_mcp_core::error::PsmMcpError;
use psm_mcp_core::input::{require_string, validate_name};
use psm_mcp_core::tool::{ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use std::sync::Arc;

/// Maximum identifier length for Key Protect IDs and names.
const MAX_ID_LEN: usize = 256;

// ── List Keys ──────────────────────────────────────────────────────

pub struct ListKeysTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for ListKeysTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_list_keys".into(),
            description: "List all keys in Key Protect instance".into(),
            input_schema: json!({"type": "object", "properties": {}}),
        }
    }

    async fn handle(&self, _arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let result = self.client.kp_request("GET", "keys", None).await?;
        ToolResult::json(&result)
    }
}

// ── Create Key ─────────────────────────────────────────────────────

pub struct CreateKeyTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for CreateKeyTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_create_key".into(),
            description: "Create a new encryption key".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "key_type": {
                        "type": "string",
                        "enum": ["root_key", "standard_key"],
                        "default": "root_key"
                    },
                    "payload": {
                        "type": "string",
                        "description": "Optional key material (base64)"
                    }
                },
                "required": ["name"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_name = require_string(&arguments, "name")?;
        validate_name(&key_name, "name", MAX_ID_LEN)?;

        let payload_raw = arguments
            .get("payload")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let payload = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            payload_raw.as_bytes(),
        );
        let key_type = arguments
            .get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("root_key");
        let extractable = key_type != "root_key";

        let body = json!({
            "metadata": {
                "collectionType": "application/vnd.ibm.kms.key+json",
                "collectionTotal": 1
            },
            "resources": [{
                "type": "application/vnd.ibm.kms.key+json",
                "name": key_name,
                "extractable": extractable,
                "payload": payload
            }]
        });

        let result = self.client.kp_request("POST", "keys", Some(body)).await?;
        ToolResult::json(&result)
    }
}

// ── Get Key ────────────────────────────────────────────────────────

pub struct GetKeyTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for GetKeyTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_get_key".into(),
            description: "Get key details".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"key_id": {"type": "string"}},
                "required": ["key_id"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_id = require_string(&arguments, "key_id")?;
        validate_name(&key_id, "key_id", MAX_ID_LEN)?;
        let result = self
            .client
            .kp_request("GET", &format!("keys/{key_id}"), None)
            .await?;
        ToolResult::json(&result)
    }
}

// ── Delete Key ─────────────────────────────────────────────────────

pub struct DeleteKeyTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for DeleteKeyTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_delete_key".into(),
            description: "Delete a key".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"key_id": {"type": "string"}},
                "required": ["key_id"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_id = require_string(&arguments, "key_id")?;
        validate_name(&key_id, "key_id", MAX_ID_LEN)?;
        let result = self
            .client
            .kp_request("DELETE", &format!("keys/{key_id}"), None)
            .await?;
        ToolResult::json(&result)
    }
}

// ── Rotate Key ─────────────────────────────────────────────────────

pub struct RotateKeyTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for RotateKeyTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_rotate_key".into(),
            description: "Rotate a root key".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"key_id": {"type": "string"}},
                "required": ["key_id"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_id = require_string(&arguments, "key_id")?;
        validate_name(&key_id, "key_id", MAX_ID_LEN)?;
        let result = self
            .client
            .kp_request(
                "POST",
                &format!("keys/{key_id}/actions/rotate"),
                Some(json!({})),
            )
            .await?;
        ToolResult::json(&result)
    }
}

// ── Wrap Key ───────────────────────────────────────────────────────

pub struct WrapKeyTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for WrapKeyTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_wrap_key".into(),
            description: "Wrap (encrypt) data with a root key".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key_id": {"type": "string"},
                    "plaintext": {"type": "string"}
                },
                "required": ["key_id", "plaintext"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_id = require_string(&arguments, "key_id")?;
        validate_name(&key_id, "key_id", MAX_ID_LEN)?;
        let plaintext = require_string(&arguments, "plaintext")?;
        let result = self
            .client
            .kp_request(
                "POST",
                &format!("keys/{key_id}/actions/wrap"),
                Some(json!({"plaintext": plaintext})),
            )
            .await?;
        ToolResult::json(&result)
    }
}

// ── Unwrap Key ─────────────────────────────────────────────────────

pub struct UnwrapKeyTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for UnwrapKeyTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_unwrap_key".into(),
            description: "Unwrap (decrypt) data with a root key".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "key_id": {"type": "string"},
                    "ciphertext": {"type": "string"}
                },
                "required": ["key_id", "ciphertext"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_id = require_string(&arguments, "key_id")?;
        validate_name(&key_id, "key_id", MAX_ID_LEN)?;
        let ciphertext = require_string(&arguments, "ciphertext")?;
        let result = self
            .client
            .kp_request(
                "POST",
                &format!("keys/{key_id}/actions/unwrap"),
                Some(json!({"ciphertext": ciphertext})),
            )
            .await?;
        ToolResult::json(&result)
    }
}

// ── Get Key Policies ───────────────────────────────────────────────

pub struct GetKeyPoliciesTool {
    pub client: Arc<IbmZClient>,
}

#[async_trait::async_trait]
impl ToolHandler for GetKeyPoliciesTool {
    fn definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: "key_protect_get_key_policies".into(),
            description: "Get key rotation policies".into(),
            input_schema: json!({
                "type": "object",
                "properties": {"key_id": {"type": "string"}},
                "required": ["key_id"]
            }),
        }
    }

    async fn handle(&self, arguments: Value) -> Result<ToolResult, PsmMcpError> {
        let key_id = require_string(&arguments, "key_id")?;
        validate_name(&key_id, "key_id", MAX_ID_LEN)?;
        let result = self
            .client
            .kp_request("GET", &format!("keys/{key_id}/policies"), None)
            .await?;
        ToolResult::json(&result)
    }
}
