# IBM Z MCP Server

MCP server for IBM Z mainframe integration with Claude Code. Provides access to enterprise-grade security and mainframe capabilities.

## Features

- **Key Protect** - HSM-backed key management (FIPS 140-2 Level 3)
- **z/OS Connect** - REST APIs to mainframe programs (CICS, IMS, batch)

## Available Tools

### Key Protect (HSM Key Management)

| Tool | Description |
|------|-------------|
| `key_protect_list_keys` | List encryption keys in Key Protect |
| `key_protect_create_key` | Create root or standard keys |
| `key_protect_get_key` | Get key details and metadata |
| `key_protect_wrap_key` | Wrap (encrypt) DEKs with a root key |
| `key_protect_unwrap_key` | Unwrap (decrypt) wrapped DEKs |
| `key_protect_rotate_key` | Rotate a root key |
| `key_protect_delete_key` | Delete a key (irreversible) |
| `key_protect_get_key_policies` | Get key policies |

### z/OS Connect (Mainframe Integration)

| Tool | Description |
|------|-------------|
| `zos_connect_list_services` | List available mainframe services |
| `zos_connect_get_service` | Get service details and OpenAPI spec |
| `zos_connect_call_service` | Call a mainframe service via REST |
| `zos_connect_list_apis` | List API requester configurations |
| `zos_connect_health` | Check z/OS Connect server health |

## Setup

### 1. Install Dependencies

```bash
cd ~/ibmz-mcp-server
npm install
```

### 2. Configure Environment

**For Key Protect:**
```bash
IBM_CLOUD_API_KEY=your-ibm-cloud-api-key
KEY_PROTECT_INSTANCE_ID=your-key-protect-instance-id
KEY_PROTECT_URL=https://us-south.kms.cloud.ibm.com
```

**For z/OS Connect (requires mainframe access):**
```bash
ZOS_CONNECT_URL=https://your-mainframe:9443/zosConnect
ZOS_CONNECT_USERNAME=your-username
ZOS_CONNECT_PASSWORD=your-password
```

### 3. Add to Claude Code

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "ibmz": {
      "type": "stdio",
      "command": "node",
      "args": ["/Users/matthewkarsten/ibmz-mcp-server/index.js"],
      "env": {
        "IBM_CLOUD_API_KEY": "your-api-key",
        "KEY_PROTECT_INSTANCE_ID": "your-instance-id"
      }
    }
  }
}
```

## Architecture

```
Claude Code (Opus 4.5)
         │
         └──▶ IBM Z MCP Server
                    │
                    ├──▶ Key Protect (HSM)
                    │         │
                    │         └── FIPS 140-2 Level 3 HSM
                    │
                    └──▶ z/OS Connect
                              │
                              ├── CICS Transactions
                              ├── IMS Programs
                              └── Batch Jobs
```

## Key Concepts

### Envelope Encryption with Key Protect

Key Protect enables envelope encryption:

1. **Root Keys (KEK)** - Stored in HSM, never leave the hardware
2. **Data Encryption Keys (DEK)** - Wrapped by root keys
3. **Wrap/Unwrap** - Operations to protect DEKs

```
Data → Encrypt with DEK → Ciphertext
DEK  → Wrap with KEK   → Wrapped DEK (stored alongside ciphertext)
```

### z/OS Connect Integration

z/OS Connect provides REST APIs to mainframe programs:

- **CICS** - Online transaction processing
- **IMS** - Hierarchical database and transactions
- **Batch** - Scheduled batch processing
- **Db2** - Relational database access

JSON payloads are automatically mapped to COBOL copybooks.

## Use Cases

### Enterprise Key Management
- Manage encryption keys for cloud workloads
- Bring Your Own Key (BYOK) to IBM Cloud services
- Key rotation for compliance
- Envelope encryption for data at rest

### Mainframe Modernization
- Expose COBOL programs as REST APIs
- Integrate mainframe data with cloud applications
- AI-powered mainframe operations via Claude
- Modernize without rewriting legacy code

## IBM Cloud Resources

This MCP server can use:
- **Service**: Key Protect
- **Plan**: Tiered (first 20 keys free)
- **Region**: us-south

For z/OS Connect, you need:
- IBM mainframe with z/OS
- z/OS Connect EE installed
- Network access from your machine

## Demo Scripts

Run these demos to test the integration:

```bash
# Test envelope encryption (HSM wrap/unwrap)
node test-envelope-encryption.js

# Full Watson services suite (NLU, STT, TTS, Key Protect, Cloudant, watsonx)
node demo-watson-suite.js

# End-to-end workflow (NLU → Key Protect → Cloudant → Decrypt)
node demo-e2e-workflow.js

# Test watsonx.ai models
node test-watsonx-generation.js
```

### Watson Services Tested

| Service | Status | Details |
|---------|--------|---------|
| Watson NLU | ✅ | Sentiment, entities, emotions |
| Watson STT | ✅ | 87 speech models |
| Watson TTS | ✅ | 65 voices |
| Key Protect | ✅ | FIPS 140-2 Level 3 HSM |
| Cloudant | ✅ | NoSQL database |
| watsonx.ai | ✅ | 28 foundation models |

## Files

- `index.js` - MCP server implementation
- `package.json` - Dependencies
- `docs/` - GitHub Pages documentation
- `demo-watson-suite.js` - Complete Watson services test
- `demo-e2e-workflow.js` - End-to-end encryption workflow
- `test-envelope-encryption.js` - HSM wrap/unwrap test
- `test-watsonx-generation.js` - watsonx models test
- `ibm-integration-demo.js` - Quick integration test

## Related MCP Servers

- [watsonx-mcp-server](https://github.com/PurpleSquirrelMedia/watsonx-mcp-server) - Foundation models (Granite, Llama, Mistral)

## Author

Matthew Karsten

## License

MIT
