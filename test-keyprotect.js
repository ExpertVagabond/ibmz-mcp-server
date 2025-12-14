#!/usr/bin/env node
import IbmKeyProtectApiV2 from '@ibm-cloud/ibm-key-protect/ibm-key-protect-api/v2.js';
import { IamAuthenticator } from 'ibm-cloud-sdk-core';
import crypto from 'crypto';

const client = new IbmKeyProtectApiV2({
  authenticator: new IamAuthenticator({
    apikey: process.env.IBM_CLOUD_API_KEY,
  }),
  serviceUrl: process.env.KEY_PROTECT_URL,
});

const instanceId = process.env.KEY_PROTECT_INSTANCE_ID;
const rootKeyId = 'dcd74ed6-5e33-45db-a25c-38f668f2f664';

// Generate a random data encryption key (DEK) - 32 bytes for AES-256
const dek = crypto.randomBytes(32);
const dekBase64 = dek.toString('base64');
console.log('Original DEK:', dekBase64);

// Wrap the DEK with our root key (envelope encryption)
console.log('\nWrapping DEK with root key...');
const wrapResult = await client.wrapKey({
  bluemixInstance: instanceId,
  id: rootKeyId,
  keyActionWrapBody: {
    plaintext: dekBase64
  }
});

const wrappedDek = wrapResult.result.ciphertext;
console.log('Wrapped DEK:', wrappedDek.substring(0, 50) + '...');

// Unwrap the DEK to verify it works
console.log('\nUnwrapping DEK...');
const unwrapResult = await client.unwrapKey({
  bluemixInstance: instanceId,
  id: rootKeyId,
  keyActionUnwrapBody: {
    ciphertext: wrappedDek
  }
});

const unwrappedDek = unwrapResult.result.plaintext;
console.log('Unwrapped DEK:', unwrappedDek);
console.log('\n✅ Envelope encryption test:', dekBase64 === unwrappedDek ? 'SUCCESS!' : 'FAILED');
