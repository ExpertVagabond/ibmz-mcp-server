# ibmz-mcp-server

[\![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[\![MCP](https://img.shields.io/badge/MCP-Compatible-blue.svg)](https://modelcontextprotocol.io)
[\![npm](https://img.shields.io/badge/npm-ibmz--mcp--server-red.svg)](https://www.npmjs.com/package/ibmz-mcp-server)

MCP server for IBM Z mainframe integration. Provides HSM-backed key management via IBM Key Protect (FIPS 140-2 Level 3) and REST API access to mainframe programs (CICS, IMS, batch) via z/OS Connect.

## Tools (12 total)

### Key Protect -- HSM Key Management

| Tool | Description |
|------|-------------|
| `key_protect_list_keys` | List encryption keys in Key Protect |
| `key_protect_create_key` | Create root or standard keys |
| `key_protect_get_key` | Get key details and metadata |
| `key_protect_wrap_key` | Wrap (encrypt) a DEK with a root key |
| `key_protect_unwrap_key` | Unwrap (decrypt) a wrapped DEK |
| `key_protect_rotate_key` | Rotate a root key |
| `key_protect_delete_key` | Delete a key (irreversible) |
| `key_protect_get_key_policies` | Get rotation and dual-auth policies |

### z/OS Connect -- Mainframe Integration

| Tool | Description |
|------|-------------|
| `zos_connect_list_services` | List available mainframe services |
| `zos_connect_get_service` | Get service details and OpenAPI spec |
| `zos_connect_call_service` | Call a mainframe program via REST (JSON to COBOL) |
| `zos_connect_list_apis` | List outbound API configurations |
| `zos_connect_health` | Check z/OS Connect server health |

## Install

```bash
npm install
```

## Configuration

```json
{
  "mcpServers": {
    "ibmz": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/ibmz-mcp-server/index.js"],
      "env": {
        "IBM_CLOUD_API_KEY": "your-api-key",
        "KEY_PROTECT_INSTANCE_ID": "your-instance-id",
        "KEY_PROTECT_URL": "https://us-south.kms.cloud.ibm.com"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `IBM_CLOUD_API_KEY` | IBM Cloud API key | Yes (Key Protect) |
| `KEY_PROTECT_INSTANCE_ID` | Key Protect instance OCID | Yes (Key Protect) |
| `KEY_PROTECT_URL` | Key Protect endpoint | No (defaults to us-south) |
| `ZOS_CONNECT_URL` | z/OS Connect base URL | Yes (z/OS Connect) |
| `ZOS_CONNECT_USERNAME` | Mainframe username | Yes (z/OS Connect) |
| `ZOS_CONNECT_PASSWORD` | Mainframe password | Yes (z/OS Connect) |

## Key Concepts

### Envelope Encryption

Root keys (KEK) are stored in the HSM and never leave the hardware. Data encryption keys (DEK) are wrapped by root keys for safe storage alongside ciphertext.

### z/OS Connect

REST APIs that automatically map JSON payloads to COBOL copybooks, enabling access to CICS transactions, IMS programs, and batch jobs.

## Dependencies

- `@modelcontextprotocol/sdk` -- MCP protocol SDK
- `@ibm-cloud/ibm-key-protect` -- Key Protect client
- `ibm-cloud-sdk-core` -- IBM Cloud authentication

## License

[MIT](LICENSE)
