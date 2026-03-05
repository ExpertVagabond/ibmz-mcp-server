use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, Write};

struct IbmZClient {
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
    fn new() -> Self {
        Self {
            api_key: env::var("IBM_CLOUD_API_KEY").unwrap_or_default(),
            kp_instance_id: env::var("KEY_PROTECT_INSTANCE_ID").unwrap_or_default(),
            kp_url: env::var("KEY_PROTECT_URL").unwrap_or_else(|_| "https://us-south.kms.cloud.ibm.com".into()),
            zos_url: env::var("ZOS_CONNECT_URL").unwrap_or_default(),
            zos_user: env::var("ZOS_CONNECT_USERNAME").unwrap_or_default(),
            zos_pass: env::var("ZOS_CONNECT_PASSWORD").unwrap_or_default(),
            http: reqwest::Client::new(),
            iam_token: tokio::sync::Mutex::new(None),
        }
    }

    async fn get_token(&self) -> Result<String, String> {
        let mut token = self.iam_token.lock().await;
        if let Some(t) = token.as_ref() { return Ok(t.clone()); }

        let resp = self.http.post("https://iam.cloud.ibm.com/identity/token")
            .form(&[("grant_type", "urn:ibm:params:oauth:grant-type:apikey"), ("apikey", &self.api_key)])
            .send().await.map_err(|e| format!("IAM auth error: {e}"))?;

        let body: Value = resp.json().await.map_err(|e| format!("IAM parse error: {e}"))?;
        let t = body.get("access_token").and_then(|v| v.as_str()).ok_or("No access_token in IAM response")?.to_string();
        *token = Some(t.clone());
        Ok(t)
    }

    async fn kp_request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let token = self.get_token().await?;
        let url = format!("{}/api/v2/{}", self.kp_url, path);
        let mut req = match method {
            "POST" => self.http.post(&url),
            "DELETE" => self.http.delete(&url),
            _ => self.http.get(&url),
        };
        req = req.bearer_auth(&token)
            .header("bluemix-instance", &self.kp_instance_id)
            .header("accept", "application/vnd.ibm.kms.key+json");

        if let Some(b) = body { req = req.json(&b); }
        let resp = req.send().await.map_err(|e| format!("KP error: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Key Protect API error ({status}): {text}"));
        }
        resp.json::<Value>().await.map_err(|e| format!("JSON error: {e}"))
    }

    async fn zos_request(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        if self.zos_url.is_empty() { return Err("z/OS Connect not configured".into()); }
        let url = format!("{}{}", self.zos_url, path);
        let mut req = match method {
            "POST" => self.http.post(&url),
            _ => self.http.get(&url),
        };
        req = req.basic_auth(&self.zos_user, Some(&self.zos_pass));
        if let Some(b) = body { req = req.json(&b); }
        let resp = req.send().await.map_err(|e| format!("z/OS error: {e}"))?;
        resp.json::<Value>().await.map_err(|e| format!("JSON error: {e}"))
    }

    async fn call_tool(&self, name: &str, args: &Value) -> Result<Value, String> {
        let s = |key: &str| args.get(key).and_then(|v| v.as_str()).unwrap_or("");
        match name {
            "key_protect_list_keys" => self.kp_request("GET", "keys", None).await,
            "key_protect_create_key" => {
                let payload = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, s("payload").as_bytes());
                let extractable = s("key_type") != "root_key";
                self.kp_request("POST", "keys", Some(json!({"metadata":{"collectionType":"application/vnd.ibm.kms.key+json","collectionTotal":1},"resources":[{"type":"application/vnd.ibm.kms.key+json","name":s("name"),"extractable":extractable,"payload":payload}]}))).await
            }
            "key_protect_get_key" => self.kp_request("GET", &format!("keys/{}", s("key_id")), None).await,
            "key_protect_delete_key" => self.kp_request("DELETE", &format!("keys/{}", s("key_id")), None).await,
            "key_protect_rotate_key" => self.kp_request("POST", &format!("keys/{}/actions/rotate", s("key_id")), Some(json!({}))).await,
            "key_protect_wrap_key" => self.kp_request("POST", &format!("keys/{}/actions/wrap", s("key_id")), Some(json!({"plaintext": s("plaintext")}))).await,
            "key_protect_unwrap_key" => self.kp_request("POST", &format!("keys/{}/actions/unwrap", s("key_id")), Some(json!({"ciphertext": s("ciphertext")}))).await,
            "key_protect_get_key_policies" => self.kp_request("GET", &format!("keys/{}/policies", s("key_id")), None).await,
            "zos_connect_health" => self.zos_request("GET", "/zosConnect/healthz", None).await,
            "zos_connect_list_services" => self.zos_request("GET", "/zosConnect/services", None).await,
            "zos_connect_list_apis" => self.zos_request("GET", "/zosConnect/apis", None).await,
            "zos_connect_get_service" => self.zos_request("GET", &format!("/zosConnect/services/{}", s("service_name")), None).await,
            "zos_connect_call_service" => {
                let body = args.get("payload").cloned().unwrap_or(json!({}));
                self.zos_request("POST", &format!("/zosConnect/services/{}", s("service_name")), Some(body)).await
            }
            _ => Err(format!("Unknown tool: {name}")),
        }
    }
}

fn tool_definitions() -> Value {
    json!([
        {"name":"key_protect_list_keys","description":"List all keys in Key Protect instance","inputSchema":{"type":"object","properties":{}}},
        {"name":"key_protect_create_key","description":"Create a new encryption key","inputSchema":{"type":"object","properties":{"name":{"type":"string"},"key_type":{"type":"string","enum":["root_key","standard_key"],"default":"root_key"},"payload":{"type":"string","description":"Optional key material (base64)"}},"required":["name"]}},
        {"name":"key_protect_get_key","description":"Get key details","inputSchema":{"type":"object","properties":{"key_id":{"type":"string"}},"required":["key_id"]}},
        {"name":"key_protect_delete_key","description":"Delete a key","inputSchema":{"type":"object","properties":{"key_id":{"type":"string"}},"required":["key_id"]}},
        {"name":"key_protect_rotate_key","description":"Rotate a root key","inputSchema":{"type":"object","properties":{"key_id":{"type":"string"}},"required":["key_id"]}},
        {"name":"key_protect_wrap_key","description":"Wrap (encrypt) data with a root key","inputSchema":{"type":"object","properties":{"key_id":{"type":"string"},"plaintext":{"type":"string"}},"required":["key_id","plaintext"]}},
        {"name":"key_protect_unwrap_key","description":"Unwrap (decrypt) data with a root key","inputSchema":{"type":"object","properties":{"key_id":{"type":"string"},"ciphertext":{"type":"string"}},"required":["key_id","ciphertext"]}},
        {"name":"key_protect_get_key_policies","description":"Get key rotation policies","inputSchema":{"type":"object","properties":{"key_id":{"type":"string"}},"required":["key_id"]}},
        {"name":"zos_connect_health","description":"Check z/OS Connect health","inputSchema":{"type":"object","properties":{}}},
        {"name":"zos_connect_list_services","description":"List z/OS Connect services","inputSchema":{"type":"object","properties":{}}},
        {"name":"zos_connect_list_apis","description":"List z/OS Connect APIs","inputSchema":{"type":"object","properties":{}}},
        {"name":"zos_connect_get_service","description":"Get z/OS Connect service details","inputSchema":{"type":"object","properties":{"service_name":{"type":"string"}},"required":["service_name"]}},
        {"name":"zos_connect_call_service","description":"Call a z/OS Connect service","inputSchema":{"type":"object","properties":{"service_name":{"type":"string"},"payload":{"type":"object"}},"required":["service_name"]}}
    ])
}

#[derive(Deserialize)] struct JsonRpcRequest { #[allow(dead_code)] jsonrpc: String, id: Option<Value>, method: String, #[serde(default)] params: Value }
#[derive(Serialize)] struct JsonRpcResponse { jsonrpc: String, id: Value, #[serde(skip_serializing_if = "Option::is_none")] result: Option<Value>, #[serde(skip_serializing_if = "Option::is_none")] error: Option<Value> }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env()).with_writer(std::io::stderr).init();
    let client = IbmZClient::new();
    tracing::info!("ibmz-mcp-server starting");
    let stdin = io::stdin(); let stdout = io::stdout();
    for line in stdin.lock().lines() {
        let line = match line { Ok(l) => l, Err(_) => break };
        if line.trim().is_empty() { continue; }
        let req: JsonRpcRequest = match serde_json::from_str(&line) { Ok(r) => r, Err(_) => continue };
        let id = req.id.clone().unwrap_or(Value::Null);
        let response = match req.method.as_str() {
            "initialize" => Some(JsonRpcResponse { jsonrpc:"2.0".into(), id, result: Some(json!({"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"ibmz-mcp-server","version":env!("CARGO_PKG_VERSION")}})), error: None }),
            "notifications/initialized" => None,
            "tools/list" => Some(JsonRpcResponse { jsonrpc:"2.0".into(), id, result: Some(json!({"tools": tool_definitions()})), error: None }),
            "tools/call" => {
                let name = req.params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let args = req.params.get("arguments").cloned().unwrap_or(json!({}));
                let result = match client.call_tool(name, &args).await {
                    Ok(v) => json!({"content":[{"type":"text","text":serde_json::to_string_pretty(&v).unwrap_or_default()}]}),
                    Err(e) => json!({"content":[{"type":"text","text":format!("Error: {e}")}],"isError":true}),
                };
                Some(JsonRpcResponse { jsonrpc:"2.0".into(), id, result: Some(result), error: None })
            }
            other => Some(JsonRpcResponse { jsonrpc:"2.0".into(), id, result: None, error: Some(json!({"code":-32601,"message":format!("method not found: {other}")})) }),
        };
        if let Some(resp) = response {
            let mut out = stdout.lock();
            let _ = serde_json::to_writer(&mut out, &resp);
            let _ = out.write_all(b"\n"); let _ = out.flush();
        }
    }
}
