const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', '..');

test('enterprise frontend includes SPA routing, metric metadata, and technical modal', () => {
  const script = fs.readFileSync(path.join(root, 'frontend/public/enterprise-dashboard.js'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'frontend/public/index.html'), 'utf8');
  assert.match(script, /CentinellRouter\.navigate/);
  assert.match(script, /dataset\.metric/);
  assert.match(script, /centinell:metric-selected/);
  assert.match(script, /wireRecordRows/);
  assert.match(script, /record-navigable/);
  assert.match(script, /URL\.createObjectURL/);
  assert.match(script, /localStorage\.setItem/);
  assert.match(script, /page\.classList\.toggle\('active'/);
  assert.match(script, /corporateModules/);
  assert.match(script, /window\.CentinellState/);
  assert.match(script, /command\/ai-forensics/);
  assert.match(script, /command\/support-center/);
  assert.match(script, /command\/crm-integration/);
  assert.match(script, /commandModuleHost/);
  assert.match(script, /corporateViews/);
  assert.match(script, /data-run-correlation/);
  assert.match(script, /data-seal-evidence/);
  assert.match(script, /sha256Text/);
  assert.match(script, /data-report-kind/);
  assert.match(script, /data-module-settings/);
  assert.match(script, /\/api\/v1\/corporate\//);
  assert.match(html, /corporate-launch-grid/);
  assert.match(script, /\/api\/v1\/dashboard\/summary/);
  assert.match(script, /\/api\/v1\/analysis/);
  assert.match(html, /id="technicalModal"|technical-modal/);
  assert.doesNotMatch(html, /anthropic-dangerous-direct-browser-access|x-api-key|apiKeyInput/);
  assert.doesNotMatch(html, /demo environment|demo only/i);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/app.js'), 'utf8'), /if \(staticPreview\) \{\s*auth\.remove\(\)/);
  const analysis = fs.readFileSync(path.join(root, 'frontend/public/technical-analysis.html'), 'utf8');
  assert.match(analysis, /evidenceFile/);
  assert.match(analysis, /SHA-256/);
  assert.match(analysis, /sourceAuthorized/);
  assert.match(analysis, /utcNormalized/);
  assert.match(analysis, /peerReviewer/);
  assert.match(analysis, /Generated UTC/);
});

test('every metric card is promoted to an interactive keyboard-accessible analysis control', () => {
  const script = fs.readFileSync(path.join(root, 'frontend/public/card-navigation.js'), 'utf8');
  assert.match(script, /querySelectorAll\('\.page \.card'\)/);
  assert.match(script, /navigable-card/);
  assert.match(script, /setAttribute\('tabindex', '0'\)/);
  assert.match(script, /centinell:metric-selected/);
  assert.match(script, /event\.key === 'Enter'.*event\.key === ' '/s);
  assert.match(script, /panelRoutes/);
  assert.match(script, /investigative-panel/);
  assert.match(script, /data-action-route|actionRoute/);
});

test('tenant-scoped dashboard, evidence, and analysis endpoints are declared', () => {
  const server = fs.readFileSync(path.join(root, 'backend/src/server.js'), 'utf8');
  assert.match(server, /app\.get\('\/api\/v1\/dashboard\/summary', requireAuth/);
  assert.match(server, /app\.get\('\/api\/v1\/command\/modules', requireAuth/);
  assert.match(server, /app\.get\('\/api\/v1\/evidence', requireAuth/);
  assert.match(server, /app\.get\('\/api\/v1\/analysis', requireAuth/);
  assert.match(server, /app\.post\('\/api\/v1\/investigation\/execute', requireAuth/);
  assert.match(server, /withTenant\(req\.auth\.org/);
  assert.match(server, /app\.get\('\/api\/v1\/corporate\/:module', requireAuth/);
  assert.match(server, /app\.post\('\/api\/v1\/corporate\/:module', requireAuth/);
  assert.match(server, /app\.delete\('\/api\/v1\/corporate\/:module\/:id', requireAuth/);
  assert.match(server, /app\.get\('\/api\/v1\/settings\/organization', requireAuth/);
  assert.match(server, /app\.put\('\/api\/v1\/settings\/organization', requireAuth/);
  assert.match(server, /Cross-site request rejected/);
  assert.match(server, /Cache-Control', 'no-store/);
  assert.doesNotMatch(server, /encrypted_data_key "encryptedDataKey"/);
});

test('every rendered HTML button declares an actionable contract', () => {
  const sources = ['frontend/public/index.html','frontend/public/enterprise-dashboard.js','frontend/public/app.js','frontend/public/ui/runtime-components.js'];
  const unactionable = [];
  sources.forEach(file => {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    for (const match of source.matchAll(/<button\b([^>]*)>/g)) {
      const attributes = match[1];
      if (!/(?:\bid=|\bdata-[\w-]+|\btype=["']submit["']|download-btn)/.test(attributes)) unactionable.push(`${file}: ${match[0]}`);
    }
  });
  assert.deepEqual(unactionable, []);
});

test('frontend architecture separates router, store, API, lifecycle, cache, and runtime UI', () => {
  const files = ['router/hash-router.js','state/centinell-store.js','services/api-client.js','services/local-data.js','core/lifecycle.js','utils/performance.js','ui/runtime-components.js'];
  files.forEach(file => assert.ok(fs.existsSync(path.join(root, 'frontend/public', file)), `${file} must exist`));
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/router/hash-router.js'), 'utf8'), /URLSearchParams|hashchange/);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/state/centinell-store.js'), 'utf8'), /CentinellStore/);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/services/api-client.js'), 'utf8'), /AbortController/);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/services/local-data.js'), 'utf8'), /indexedDB/);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/core/lifecycle.js'), 'utf8'), /destroyAll/);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/utils/performance.js'), 'utf8'), /debounce|throttle/);
  assert.match(fs.readFileSync(path.join(root, 'frontend/public/ui/runtime-components.js'), 'utf8'), /applyRBAC|Export CSV|global\.print/);
});

test('reviewer guide documents test, RLS, offline, security, and accessibility review', () => {
  const guide = fs.readFileSync(path.join(root, 'docs/REVIEWERS-GUIDE.md'), 'utf8');
  assert.match(guide, /Test coverage matrix/);
  assert.match(guide, /sequenceDiagram/);
  assert.match(guide, /FORCE ROW LEVEL SECURITY/);
  assert.match(guide, /flowchart TD/);
  assert.match(guide, /npm run security-scan/);
  assert.match(guide, /Accessibility compliance log/);
  assert.match(guide, /not queued or replayed automatically/i);
});
