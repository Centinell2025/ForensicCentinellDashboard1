const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', '..');

test('enterprise frontend includes SPA routing, metric metadata, and technical modal', () => {
  const script = fs.readFileSync(path.join(root, 'frontend/public/enterprise-dashboard.js'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'frontend/public/index.html'), 'utf8');
  assert.match(script, /history\.pushState/);
  assert.match(script, /dataset\.metric/);
  assert.match(script, /centinell:metric-selected/);
  assert.match(script, /\/api\/v1\/dashboard\/summary/);
  assert.match(script, /\/api\/v1\/analysis/);
  assert.match(html, /id="technicalModal"|technical-modal/);
});

test('tenant-scoped dashboard, evidence, and analysis endpoints are declared', () => {
  const server = fs.readFileSync(path.join(root, 'backend/src/server.js'), 'utf8');
  assert.match(server, /app\.get\('\/api\/v1\/dashboard\/summary', requireAuth/);
  assert.match(server, /app\.get\('\/api\/v1\/evidence', requireAuth/);
  assert.match(server, /app\.get\('\/api\/v1\/analysis', requireAuth/);
  assert.match(server, /withTenant\(req\.auth\.org/);
  assert.doesNotMatch(server, /encrypted_data_key "encryptedDataKey"/);
});
