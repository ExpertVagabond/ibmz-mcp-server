#!/usr/bin/env node

/**
 * IBM Z MCP Server
 *
 * MCP server for IBM Z mainframe integration with Claude Code.
 * Provides access to:
 * - Key Protect: HSM-backed key management (FIPS 140-2 Level 3)
 * - z/OS Connect: REST APIs to mainframe programs (CICS, IMS, batch)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import IbmKeyProtectApiV2 from "@ibm-cloud/ibm-key-protect/ibm-key-protect-api/v2.js";
import { IamAuthenticator } from "ibm-cloud-sdk-core";

// Key Protect configuration
const IBM_CLOUD_API_KEY = process.env.IBM_CLOUD_API_KEY;
const KEY_PROTECT_INSTANCE_ID = process.env.KEY_PROTECT_INSTANCE_ID;
const KEY_PROTECT_URL = process.env.KEY_PROTECT_URL || "https://us-south.kms.cloud.ibm.com";

// z/OS Connect configuration (requires mainframe access)
const ZOS_CONNECT_URL = process.env.ZOS_CONNECT_URL;
const ZOS_CONNECT_USERNAME = process.env.ZOS_CONNECT_USERNAME;
const ZOS_CONNECT_PASSWORD = process.env.ZOS_CONNECT_PASSWORD;

// Initialize Key Protect client
let keyProtectClient = null;

function getKeyProtectClient() {
  if (!keyProtectClient && IBM_CLOUD_API_KEY && KEY_PROTECT_INSTANCE_ID) {
    keyProtectClient = new IbmKeyProtectApiV2({
      authenticator: new IamAuthenticator({
        apikey: IBM_CLOUD_API_KEY,
      }),
      serviceUrl: KEY_PROTECT_URL,
    });
  }
  return keyProtectClient;
}

// z/OS Connect API helper
async function callZosConnect(endpoint, method = "GET", body = null) {
  if (!ZOS_CONNECT_URL) {
    throw new Error("z/OS Connect not configured. Set ZOS_CONNECT_URL environment variable.");
  }

  const url = `${ZOS_CONNECT_URL}${endpoint}`;
  const headers = {
    "Content-Type": "application/json",
    "Accept": "application/json",
  };

  // Basic auth for z/OS Connect
  if (ZOS_CONNECT_USERNAME && ZOS_CONNECT_PASSWORD) {
    const auth = Buffer.from(`${ZOS_CONNECT_USERNAME}:${ZOS_CONNECT_PASSWORD}`).toString("base64");
    headers["Authorization"] = `Basic ${auth}`;
  }

  const options = { method, headers };
  if (body && (method === "POST" || method === "PUT" || method === "PATCH")) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(url, options);

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`z/OS Connect error ${response.status}: ${errorText}`);
  }

  const contentType = response.headers.get("content-type");
  if (contentType && contentType.includes("application/json")) {
    return response.json();
  }
  return response.text();
}

// Create MCP server
const server = new Server(
  {
    name: "ibmz-mcp-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      // ============ Key Protect Tools ============
      {
        name: "key_protect_list_keys",
        description: "List encryption keys from IBM Key Protect (HSM-backed on IBM Z infrastructure, FIPS 140-2 Level 3 certified)",
        inputSchema: {
          type: "object",
          properties: {
            limit: {
              type: "number",
              description: "Maximum number of keys to return (default: 100)",
              default: 100,
            },
            offset: {
              type: "number",
              description: "Number of keys to skip for pagination",
              default: 0,
            },
            state: {
              type: "array",
              items: { type: "number" },
              description: "Filter by key states: 1=Active, 2=Suspended, 3=Deactivated, 5=Destroyed",
            },
          },
        },
      },
      {
        name: "key_protect_create_key",
        description: "Create a new encryption key in IBM Key Protect HSM. Root keys protect other keys (envelope encryption). Standard keys encrypt data directly.",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Unique name for the key",
            },
            description: {
              type: "string",
              description: "Description of the key's purpose",
            },
            type: {
              type: "string",
              enum: ["root_key", "standard_key"],
              description: "root_key for wrapping other keys, standard_key for direct encryption",
              default: "standard_key",
            },
            extractable: {
              type: "boolean",
              description: "If true, key material can be exported (only for standard_key)",
              default: false,
            },
            payload: {
              type: "string",
              description: "Optional: Base64-encoded key material to import (for BYOK scenarios)",
            },
          },
          required: ["name"],
        },
      },
      {
        name: "key_protect_get_key",
        description: "Get metadata and details of a specific key from IBM Key Protect",
        inputSchema: {
          type: "object",
          properties: {
            key_id: {
              type: "string",
              description: "The unique ID of the key",
            },
          },
          required: ["key_id"],
        },
      },
      {
        name: "key_protect_wrap_key",
        description: "Wrap (encrypt) a data encryption key using a root key. Used for envelope encryption - protects DEKs with a KEK stored in HSM.",
        inputSchema: {
          type: "object",
          properties: {
            key_id: {
              type: "string",
              description: "ID of the root key to use for wrapping",
            },
            plaintext: {
              type: "string",
              description: "Base64-encoded plaintext data encryption key (DEK) to wrap",
            },
            aad: {
              type: "array",
              items: { type: "string" },
              description: "Additional authenticated data for AEAD (optional, must match on unwrap)",
            },
          },
          required: ["key_id", "plaintext"],
        },
      },
      {
        name: "key_protect_unwrap_key",
        description: "Unwrap (decrypt) a wrapped data encryption key using a root key",
        inputSchema: {
          type: "object",
          properties: {
            key_id: {
              type: "string",
              description: "ID of the root key used to wrap the DEK",
            },
            ciphertext: {
              type: "string",
              description: "Base64-encoded wrapped (encrypted) data encryption key",
            },
            aad: {
              type: "array",
              items: { type: "string" },
              description: "Additional authenticated data (must match what was used during wrap)",
            },
          },
          required: ["key_id", "ciphertext"],
        },
      },
      {
        name: "key_protect_rotate_key",
        description: "Rotate a root key. Creates new key version while maintaining ability to unwrap data encrypted with previous versions.",
        inputSchema: {
          type: "object",
          properties: {
            key_id: {
              type: "string",
              description: "ID of the root key to rotate",
            },
            payload: {
              type: "string",
              description: "Optional: Base64-encoded new key material for BYOK rotation",
            },
          },
          required: ["key_id"],
        },
      },
      {
        name: "key_protect_delete_key",
        description: "Delete a key from IBM Key Protect. WARNING: This is irreversible and data encrypted with this key becomes unrecoverable.",
        inputSchema: {
          type: "object",
          properties: {
            key_id: {
              type: "string",
              description: "ID of the key to delete",
            },
            force: {
              type: "boolean",
              description: "Force delete even if key has associated resources",
              default: false,
            },
          },
          required: ["key_id"],
        },
      },
      {
        name: "key_protect_get_key_policies",
        description: "Get policies applied to a key (rotation, dual authorization)",
        inputSchema: {
          type: "object",
          properties: {
            key_id: {
              type: "string",
              description: "ID of the key",
            },
          },
          required: ["key_id"],
        },
      },

      // ============ z/OS Connect Tools ============
      {
        name: "zos_connect_list_services",
        description: "List all available z/OS Connect services (REST APIs exposing mainframe programs). Each service maps to CICS transactions, IMS programs, or batch jobs.",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "zos_connect_get_service",
        description: "Get detailed information about a z/OS Connect service including its OpenAPI specification and endpoint mappings",
        inputSchema: {
          type: "object",
          properties: {
            service_name: {
              type: "string",
              description: "Name of the z/OS Connect service",
            },
          },
          required: ["service_name"],
        },
      },
      {
        name: "zos_connect_call_service",
        description: "Call a z/OS Connect REST API to interact with mainframe programs. Maps JSON to COBOL copybooks automatically.",
        inputSchema: {
          type: "object",
          properties: {
            service_name: {
              type: "string",
              description: "Name of the z/OS Connect service to invoke",
            },
            operation: {
              type: "string",
              description: "API operation path (e.g., /accounts, /customers/{id})",
              default: "/",
            },
            method: {
              type: "string",
              enum: ["GET", "POST", "PUT", "DELETE", "PATCH"],
              description: "HTTP method",
              default: "POST",
            },
            payload: {
              type: "object",
              description: "JSON request body (automatically mapped to COBOL structures)",
            },
            path_params: {
              type: "object",
              description: "Path parameters for URL template substitution",
            },
            query_params: {
              type: "object",
              description: "Query string parameters",
            },
          },
          required: ["service_name"],
        },
      },
      {
        name: "zos_connect_list_apis",
        description: "List all deployed API requester configurations (outbound calls from z/OS to external services)",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "zos_connect_health",
        description: "Check the health status of the z/OS Connect server and connected subsystems",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    // ============ Key Protect Tool Handlers ============
    if (name.startsWith("key_protect_")) {
      const kpClient = getKeyProtectClient();

      if (!kpClient) {
        return {
          content: [{
            type: "text",
            text: "Error: Key Protect not configured. Set IBM_CLOUD_API_KEY and KEY_PROTECT_INSTANCE_ID environment variables.",
          }],
        };
      }

      switch (name) {
        case "key_protect_list_keys": {
          const response = await kpClient.getKeys({
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            limit: args.limit || 100,
            offset: args.offset || 0,
            state: args.state,
          });

          const keys = response.result.resources?.map(k => ({
            id: k.id,
            name: k.name,
            type: k.type,
            state: k.state,
            extractable: k.extractable,
            crn: k.crn,
            createdBy: k.createdBy,
            creationDate: k.creationDate,
            lastRotateDate: k.lastRotateDate,
            deleted: k.deleted,
          })) || [];

          return {
            content: [{
              type: "text",
              text: JSON.stringify({ total: keys.length, keys }, null, 2),
            }],
          };
        }

        case "key_protect_create_key": {
          const isRootKey = args.type === "root_key";

          const keyResource = {
            type: "application/vnd.ibm.kms.key+json",
            name: args.name,
            extractable: isRootKey ? false : (args.extractable || false),
          };

          if (args.description) {
            keyResource.description = args.description;
          }

          if (args.payload) {
            keyResource.payload = args.payload;
          }

          const keyCreateBody = {
            metadata: {
              collectionType: "application/vnd.ibm.kms.key+json",
              collectionTotal: 1,
            },
            resources: [keyResource],
          };

          const response = await kpClient.createKey({
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            keyCreateBody,
          });

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                message: `Key "${args.name}" created successfully`,
                key: {
                  id: response.result.resources?.[0]?.id,
                  name: response.result.resources?.[0]?.name,
                  type: response.result.resources?.[0]?.type,
                  crn: response.result.resources?.[0]?.crn,
                },
              }, null, 2),
            }],
          };
        }

        case "key_protect_get_key": {
          const response = await kpClient.getKey({
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            id: args.key_id,
          });

          const key = response.result.resources?.[0];
          return {
            content: [{
              type: "text",
              text: JSON.stringify(key, null, 2),
            }],
          };
        }

        case "key_protect_wrap_key": {
          const keyActionWrapBody = {
            plaintext: args.plaintext,
          };

          if (args.aad) {
            keyActionWrapBody.aad = args.aad;
          }

          const response = await kpClient.wrapKey({
            id: args.key_id,
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            keyActionWrapBody,
          });

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                message: "Key wrapped successfully",
                ciphertext: response.result.ciphertext,
                keyVersion: response.result.keyVersion,
              }, null, 2),
            }],
          };
        }

        case "key_protect_unwrap_key": {
          const keyActionUnwrapBody = {
            ciphertext: args.ciphertext,
          };

          if (args.aad) {
            keyActionUnwrapBody.aad = args.aad;
          }

          const response = await kpClient.unwrapKey({
            id: args.key_id,
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            keyActionUnwrapBody,
          });

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                message: "Key unwrapped successfully",
                plaintext: response.result.plaintext,
                keyVersion: response.result.keyVersion,
              }, null, 2),
            }],
          };
        }

        case "key_protect_rotate_key": {
          const params = {
            id: args.key_id,
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
          };

          if (args.payload) {
            params.keyActionRotateBody = {
              payload: args.payload,
            };
          }

          await kpClient.rotateKey(params);

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                message: `Key ${args.key_id} rotated successfully`,
                keyId: args.key_id,
              }, null, 2),
            }],
          };
        }

        case "key_protect_delete_key": {
          await kpClient.deleteKey({
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            id: args.key_id,
            force: args.force || false,
          });

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                message: `Key ${args.key_id} deleted successfully`,
                warning: "This action is irreversible. Data encrypted with this key is now unrecoverable.",
              }, null, 2),
            }],
          };
        }

        case "key_protect_get_key_policies": {
          const response = await kpClient.getKeyMetadata({
            bluemixInstance: KEY_PROTECT_INSTANCE_ID,
            id: args.key_id,
          });

          return {
            content: [{
              type: "text",
              text: JSON.stringify(response.result, null, 2),
            }],
          };
        }
      }
    }

    // ============ z/OS Connect Tool Handlers ============
    if (name.startsWith("zos_connect_")) {
      if (!ZOS_CONNECT_URL) {
        return {
          content: [{
            type: "text",
            text: "Error: z/OS Connect not configured. Set ZOS_CONNECT_URL environment variable. This requires access to an IBM mainframe with z/OS Connect EE installed.",
          }],
        };
      }

      switch (name) {
        case "zos_connect_list_services": {
          const services = await callZosConnect("/zosConnect/services");
          return {
            content: [{
              type: "text",
              text: JSON.stringify(services, null, 2),
            }],
          };
        }

        case "zos_connect_get_service": {
          const service = await callZosConnect(`/zosConnect/services/${args.service_name}`);
          return {
            content: [{
              type: "text",
              text: JSON.stringify(service, null, 2),
            }],
          };
        }

        case "zos_connect_call_service": {
          let endpoint = `/zosConnect/services/${args.service_name}${args.operation || "/"}`;

          // Substitute path parameters
          if (args.path_params) {
            for (const [key, value] of Object.entries(args.path_params)) {
              endpoint = endpoint.replace(`{${key}}`, encodeURIComponent(String(value)));
            }
          }

          // Add query parameters
          if (args.query_params) {
            const queryString = new URLSearchParams(args.query_params).toString();
            endpoint += `?${queryString}`;
          }

          const result = await callZosConnect(endpoint, args.method || "POST", args.payload);

          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                service: args.service_name,
                operation: args.operation || "/",
                method: args.method || "POST",
                response: result,
              }, null, 2),
            }],
          };
        }

        case "zos_connect_list_apis": {
          const apis = await callZosConnect("/zosConnect/apis");
          return {
            content: [{
              type: "text",
              text: JSON.stringify(apis, null, 2),
            }],
          };
        }

        case "zos_connect_health": {
          const health = await callZosConnect("/zosConnect/health");
          return {
            content: [{
              type: "text",
              text: JSON.stringify(health, null, 2),
            }],
          };
        }
      }
    }

    return {
      content: [{
        type: "text",
        text: `Unknown tool: ${name}`,
      }],
    };

  } catch (error) {
    return {
      content: [{
        type: "text",
        text: `Error: ${error.message}`,
      }],
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("IBM Z MCP server running on stdio");
}

main().catch(console.error);
