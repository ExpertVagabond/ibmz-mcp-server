//! IBM Z client — handles IAM token exchange, Key Protect, and z/OS Connect HTTP calls.

use psm_mcp_core::error::PsmMcpError;
use serde_json::Value;
use std::env;

/// Shared IBM Z client holding credentials and HTTP state.
pub struct IbmZClient {
    api_key: String,
    kp_instance_id: String,
    kp_url: String,
    zos_url: String,
    zos_user: String,
    zos_pass: String,
    http: reqwest::Client,
    iam_token: tokio::sync::Mutex<Option<String>>,
}

impl IbmZClient {
    pub fn new() -> Self {
        Self {
            api_key: env::var("IBM_CLOUD_API_KEY").unwrap_or_default(),
            kp_instance_id: env::var("KEY_PROTECT_INSTANCE_ID").unwrap_or_default(),
            kp_url: env::var("KEY_PROTECT_URL")
                .unwrap_or_else(|_| "https://us-south.kms.cloud.ibm.com".into()),
            zos_url: env::var("ZOS_CONNECT_URL").unwrap_or_default(),
            zos_user: env::var("ZOS_CONNECT_USERNAME").unwrap_or_default(),
            zos_pass: env::var("ZOS_CONNECT_PASSWORD").unwrap_or_default(),
            http: reqwest::Client::new(),
            iam_token: tokio::sync::Mutex::new(None),
        }
    }

    /// Log warnings about missing environment variables at startup.
    pub fn check_env_vars() {
        let required = ["IBM_CLOUD_API_KEY"];
        let optional = [
            "KEY_PROTECT_INSTANCE_ID",
            "KEY_PROTECT_URL",
            "ZOS_CONNECT_URL",
        ];
        for var in required {
            if env::var(var).unwrap_or_default().is_empty() {
                tracing::warn!("required env var {var} is not set");
            }
        }
        for var in optional {
            if env::var(var).unwrap_or_default().is_empty() {
                tracing::info!("optional env var {var} is not set — some tools will be unavailable");
            }
        }
    }

    /// Fetch (or reuse cached) IAM bearer token.
    pub async fn get_token(&self) -> Result<String, PsmMcpError> {
        let mut token = self.iam_token.lock().await;
        if let Some(t) = token.as_ref() {
            return Ok(t.clone());
        }

        let resp = self
            .http
            .post("https://iam.cloud.ibm.com/identity/token")
            .form(&[
                ("grant_type", "urn:ibm:params:oauth:grant-type:apikey"),
                ("apikey", &self.api_key),
            ])
            .send()
            .await
            .map_err(|e| PsmMcpError::Internal(anyhow::anyhow!("IAM auth error: {e}")))?;

        let body: Value = resp
            .json()
            .await
            .map_err(|e| PsmMcpError::Internal(anyhow::anyhow!("IAM parse error: {e}")))?;

        let t = body
            .get("access_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PsmMcpError::Internal(anyhow::anyhow!("no access_token in IAM response"))
            })?
            .to_string();

        *token = Some(t.clone());
        Ok(t)
    }

    /// Execute a Key Protect API request.
    pub async fn kp_request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, PsmMcpError> {
        let token = self.get_token().await?;
        let url = format!("{}/api/v2/{}", self.kp_url, path);
        let mut req = match method {
            "POST" => self.http.post(&url),
            "DELETE" => self.http.delete(&url),
            _ => self.http.get(&url),
        };
        req = req
            .bearer_auth(&token)
            .header("bluemix-instance", &self.kp_instance_id)
            .header("accept", "application/vnd.ibm.kms.key+json");

        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| PsmMcpError::Internal(anyhow::anyhow!("Key Protect error: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(PsmMcpError::Internal(anyhow::anyhow!(
                "Key Protect API error ({status}): {text}"
            )));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| PsmMcpError::Internal(anyhow::anyhow!("JSON parse error: {e}")))
    }

    /// Execute a z/OS Connect API request.
    pub async fn zos_request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, PsmMcpError> {
        if self.zos_url.is_empty() {
            return Err(PsmMcpError::Config("z/OS Connect not configured".into()));
        }
        let url = format!("{}{}", self.zos_url, path);
        let mut req = match method {
            "POST" => self.http.post(&url),
            _ => self.http.get(&url),
        };
        req = req.basic_auth(&self.zos_user, Some(&self.zos_pass));
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| PsmMcpError::Internal(anyhow::anyhow!("z/OS Connect error: {e}")))?;

        resp.json::<Value>()
            .await
            .map_err(|e| PsmMcpError::Internal(anyhow::anyhow!("JSON parse error: {e}")))
    }
}
