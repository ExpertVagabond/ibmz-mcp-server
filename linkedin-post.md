# LinkedIn Post - IBM Z MCP Server

---

## Post Option 1 (Technical Focus)

**Just shipped: IBM Z MCP Server** 🔐

I built an MCP server that brings IBM Z mainframe capabilities to Claude Code.

The result? Claude can now manage HSM-backed encryption keys and call mainframe APIs directly.

**Key Protect Integration:**
• Create/manage encryption keys in FIPS 140-2 Level 3 HSMs
• Envelope encryption for securing data at rest
• Key rotation and lifecycle management

**z/OS Connect Integration:**
• REST APIs to CICS, IMS, and batch programs
• OpenAPI spec discovery
• Bridge modern AI agents to legacy systems

This pairs with my watsonx MCP server for a complete IBM Cloud + AI integration:
- Claude orchestrates complex tasks
- watsonx.ai handles foundation model workloads
- Key Protect secures sensitive data
- z/OS Connect bridges to enterprise systems

📖 Demo: https://purplesquirrelmedia.github.io/ibmz-mcp-server/
💻 Source: https://github.com/PurpleSquirrelMedia/ibmz-mcp-server

#IBM #IBMz #Mainframe #Claude #MCP #Anthropic #Security #EnterpriseAI

---

## Post Option 2 (Enterprise Value Focus)

**Connecting AI Agents to Enterprise Mainframes** 🏢

Just released an open-source integration that lets Claude Code interact with IBM Z infrastructure.

Why this matters:
→ 70% of Fortune 500 companies run mission-critical workloads on IBM Z
→ AI agents need access to enterprise data and systems
→ Security can't be compromised

What I built:
1. **Key Protect MCP Tools** - Claude can create and manage encryption keys stored in hardware security modules
2. **z/OS Connect Tools** - Claude can discover and call mainframe APIs

The security model:
- Keys never leave the HSM
- All operations are audited
- Claude handles orchestration, not secrets

Real use case: An AI agent analyzing financial data can request a wrapped DEK, decrypt locally, process, then discard - the root key stays in the HSM the entire time.

Links:
🔗 https://github.com/PurpleSquirrelMedia/ibmz-mcp-server
📖 https://purplesquirrelmedia.github.io/ibmz-mcp-server/

#EnterpriseAI #IBMz #Security #CloudSecurity #MCP

---

## Post Option 3 (Short & Punchy)

Two new MCP servers for IBM Cloud:

**watsonx-mcp-server**
→ Claude delegates to Granite, Llama, Mistral models
→ Two-agent AI architecture

**ibmz-mcp-server**
→ HSM-backed key management
→ z/OS Connect mainframe APIs

The stack:
☁️ IBM Cloud free tier
🔐 Key Protect HSM
🤖 watsonx.ai foundation models
🏢 z/OS Connect (optional)
🧠 Claude Code orchestration

All tested. All working. All open source.

🔗 watsonx: https://github.com/PurpleSquirrelMedia/watsonx-mcp-server
🔗 IBM Z: https://github.com/PurpleSquirrelMedia/ibmz-mcp-server

#MCP #IBM #Claude #OpenSource
