# Troubleshooting Guide

Common issues and solutions for the IBM Z MCP Server.

## Key Protect Issues

### `401 Unauthorized`

**Cause**: Invalid or expired IBM Cloud API key.

**Solutions**:
1. Generate a new API key in IBM Cloud console
2. Verify key has Key Protect service access
3. Check IAM permissions include "Key Protect Reader" or higher

### `403 Forbidden - Insufficient permissions`

**Cause**: API key lacks required Key Protect permissions.

**Solutions**:
1. In IBM Cloud IAM, assign one of these roles:
   - **Reader**: List and view keys
   - **Writer**: Create, wrap, unwrap keys
   - **Manager**: Full access including delete and rotate
2. Wait 5 minutes for IAM changes to propagate

### `Key not found`

**Cause**: Key ID doesn't exist or wrong instance.

**Solutions**:
1. Verify `KEY_PROTECT_INSTANCE_ID` is correct
2. Use `key_protect_list_keys` to see available keys
3. Check you're using the key ID, not the key name

### `Instance not found`

**Cause**: Invalid Key Protect instance ID.

**Solution**:
1. Go to IBM Cloud > Resource List > Key Protect
2. Click your instance
3. Copy the GUID from the URL: `https://cloud.ibm.com/services/kms/KEY_PROTECT_INSTANCE_ID`

### `Wrap/Unwrap failed`

**Cause**: Using wrong key type or invalid ciphertext.

**Solutions**:
1. Only **root keys** can wrap/unwrap (not standard keys)
2. For unwrap, use the exact ciphertext returned by wrap
3. Check key hasn't been rotated (re-wrap with new version)

### `Key rotation failed`

**Cause**: Can't rotate standard keys or key is disabled.

**Solutions**:
1. Only root keys support rotation
2. Check key state is "Active"
3. Verify Manager role permissions

## z/OS Connect Issues

### `Connection refused`

**Cause**: z/OS Connect server not reachable.

**Solutions**:
1. Verify `ZOS_CONNECT_URL` format: `https://host:port/zosConnect`
2. Check firewall allows connection to mainframe
3. Confirm z/OS Connect EE is running:
   ```bash
   # On z/OS
   /D A,ZCON*
   ```
4. Test with curl:
   ```bash
   curl -k -u user:pass https://your-mainframe:9443/zosConnect/services
   ```

### `401 Unauthorized` (z/OS)

**Cause**: Invalid mainframe credentials.

**Solutions**:
1. Verify `ZOS_CONNECT_USERNAME` and `ZOS_CONNECT_PASSWORD`
2. Check RACF/ACF2/TSS password hasn't expired
3. Ensure user ID has access to z/OS Connect resources

### `Service not found`

**Cause**: Service not deployed or wrong name.

**Solutions**:
1. Use `zos_connect_list_services` to see available services
2. Check service is deployed in z/OS Connect
3. Service names are case-sensitive

### `500 Internal Server Error`

**Cause**: Mainframe program failed.

**Solutions**:
1. Check z/OS Connect server logs
2. Verify CICS region/IMS system is active
3. Review COBOL program for ABEND codes
4. Check input data matches copybook format

### `CICS transaction failed`

**Cause**: Transaction abend or timeout.

**Solutions**:
1. Check CICS logs for abend code (e.g., ASRA, AICA)
2. Increase transaction timeout if needed
3. Verify CICS region resources (files, queues)
4. Check transaction is installed and enabled

### `JSON mapping error`

**Cause**: JSON doesn't match COBOL copybook.

**Solutions**:
1. Review the service's OpenAPI specification
2. Match field names exactly (case-sensitive)
3. Use correct data types (string for PIC X, number for PIC 9)
4. Check field lengths don't exceed copybook definitions

## Configuration Issues

### `Missing environment variable`

**Cause**: Required env var not set.

**Required for Key Protect**:
```bash
export IBM_CLOUD_API_KEY="your-key"
export KEY_PROTECT_INSTANCE_ID="your-instance-id"
export KEY_PROTECT_URL="https://us-south.kms.cloud.ibm.com"
```

**Required for z/OS Connect**:
```bash
export ZOS_CONNECT_URL="https://host:port/zosConnect"
export ZOS_CONNECT_USERNAME="user"
export ZOS_CONNECT_PASSWORD="password"
```

### `Invalid region URL`

**Key Protect regions**:
```bash
# US South (Dallas)
KEY_PROTECT_URL=https://us-south.kms.cloud.ibm.com

# US East (Washington DC)
KEY_PROTECT_URL=https://us-east.kms.cloud.ibm.com

# EU Germany (Frankfurt)
KEY_PROTECT_URL=https://eu-de.kms.cloud.ibm.com

# EU Great Britain (London)
KEY_PROTECT_URL=https://eu-gb.kms.cloud.ibm.com

# Asia Pacific (Tokyo)
KEY_PROTECT_URL=https://jp-tok.kms.cloud.ibm.com

# Asia Pacific (Sydney)
KEY_PROTECT_URL=https://au-syd.kms.cloud.ibm.com
```

## MCP Server Issues

### Server not appearing in Claude Code

**Solutions**:
1. Verify `~/.claude.json` syntax is valid JSON
2. Check path to `index.js` is correct
3. Restart Claude Code after config changes
4. Test server directly: `node /path/to/index.js`

### `Cannot find module` errors

**Solution**:
```bash
cd ~/ibmz-mcp-server
npm install
```

### SSL certificate errors

**Cause**: Self-signed cert on z/OS Connect.

**Solutions**:
1. Add CA certificate to Node.js:
   ```bash
   export NODE_EXTRA_CA_CERTS=/path/to/cert.pem
   ```
2. Or disable verification (development only):
   ```bash
   export NODE_TLS_REJECT_UNAUTHORIZED=0
   ```

## Debugging

### Enable verbose logging

```bash
# Run server directly to see errors
DEBUG=* node /path/to/ibmz-mcp-server/index.js
```

### Test Key Protect connection

```bash
# Get IAM token
TOKEN=$(curl -s -X POST "https://iam.cloud.ibm.com/identity/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ibm:params:oauth:grant-type:apikey&apikey=$IBM_CLOUD_API_KEY" \
  | jq -r '.access_token')

# List keys
curl -s "https://us-south.kms.cloud.ibm.com/api/v2/keys" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Bluemix-Instance: $KEY_PROTECT_INSTANCE_ID"
```

### Test z/OS Connect

```bash
curl -k -u $ZOS_CONNECT_USERNAME:$ZOS_CONNECT_PASSWORD \
  "$ZOS_CONNECT_URL/services"
```

## Getting Help

- [Key Protect Documentation](https://cloud.ibm.com/docs/key-protect)
- [z/OS Connect Documentation](https://www.ibm.com/docs/en/zosconnect)
- [IBM Cloud Status](https://cloud.ibm.com/status)
- [GitHub Issues](https://github.com/PurpleSquirrelMedia/ibmz-mcp-server/issues)
