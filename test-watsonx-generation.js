#!/usr/bin/env node
/**
 * Test watsonx.ai text generation
 * Requires either a project_id or space_id
 */

import { WatsonXAI } from '@ibm-cloud/watsonx-ai';
import { IamAuthenticator } from 'ibm-cloud-sdk-core';

const apiKey = process.env.WATSONX_API_KEY || 'YveH06g9T_XKZoKapGJsjm9q9xCz6WJ6z4GBRM_LJ9R5';
const projectId = process.env.WATSONX_PROJECT_ID;

const client = WatsonXAI.newInstance({
  version: '2024-05-31',
  serviceUrl: 'https://us-south.ml.cloud.ibm.com',
  authenticator: new IamAuthenticator({ apikey: apiKey }),
});

console.log('=== watsonx.ai Text Generation Test ===\n');

// First, list models to confirm connection
console.log('1. Checking available models...');
const modelsResp = await client.listFoundationModelSpecs({ limit: 20 });
const models = modelsResp.result.resources || [];

// Find text generation capable models
const textGenModels = models.filter(m =>
  m.model_id?.includes('granite') ||
  m.model_id?.includes('llama') ||
  m.model_id?.includes('mistral')
);

console.log(`   Found ${textGenModels.length} text generation models:`);
textGenModels.slice(0, 5).forEach(m => console.log(`   • ${m.model_id}`));

if (!projectId) {
  console.log('\n⚠️  No WATSONX_PROJECT_ID set.');
  console.log('\nTo enable text generation:');
  console.log('1. Go to https://dataplatform.cloud.ibm.com');
  console.log('2. Create a new project');
  console.log('3. Copy the Project ID from Settings → General');
  console.log('4. Add to ~/.claude.json under mcpServers.watsonx.env:');
  console.log('   "WATSONX_PROJECT_ID": "your-project-id"');
  console.log('\nOr set environment variable:');
  console.log('   export WATSONX_PROJECT_ID=your-project-id');
  process.exit(0);
}

// Test generation if project ID is available
console.log('\n2. Testing text generation...');
console.log(`   Using project: ${projectId}`);

try {
  const response = await client.generateText({
    input: 'Explain envelope encryption in one sentence:',
    modelId: 'ibm/granite-3-8b-instruct',
    projectId: projectId,
    parameters: {
      max_new_tokens: 100,
      temperature: 0.7,
    }
  });

  console.log('\n   Generated response:');
  console.log(`   "${response.result.results[0].generated_text.trim()}"`);
  console.log('\n✅ Text generation working!');
} catch (error) {
  console.log('\n❌ Generation failed:', error.message);
  if (error.message.includes('project_id')) {
    console.log('\n   The project ID may be invalid or not properly configured.');
  }
}
