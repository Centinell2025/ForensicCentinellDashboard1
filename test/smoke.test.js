const test = require('node:test');
const assert = require('node:assert/strict');
test('required deployment files are loadable', () => {
  const pkg = require('../package.json');
  const railway = require('../railway.json');
  assert.equal(pkg.engines.node, '>=20');
  assert.equal(railway.deploy.healthcheckPath, '/api/v1/health');
});
test('server module loads without starting a listener', () => {
  process.env.JWT_SECRET = 'test-only-secret-with-more-than-32-characters';
  assert.ok(require('../src/server').app);
});
