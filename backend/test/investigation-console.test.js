const test = require('node:test');
const assert = require('node:assert/strict');
const { COMMANDS, classifyIndicator, packetSummary } = require('../src/security/investigation-console');

test('investigation console exposes only the defensive allowlist', () => {
  assert.deepEqual(COMMANDS, ['help','cases','evidence','audit','chain-verify','ioc','packet-summary']);
  assert.equal(COMMANDS.includes('shell'), false);
  assert.equal(COMMANDS.includes('scan'), false);
});

test('IOC classifier accepts IP, domain, and SHA-256 but rejects shell syntax', () => {
  assert.equal(classifyIndicator('198.51.100.19').type, 'ip');
  assert.equal(classifyIndicator('example.org').type, 'domain');
  assert.equal(classifyIndicator('a'.repeat(64)).type, 'sha256');
  assert.throws(() => classifyIndicator('example.org; id'));
});

test('packet summary aggregates bounded metadata and seals it with SHA-256', () => {
  const result = packetSummary(JSON.stringify([
    { source:'10.0.0.4', destination:'198.51.100.19', protocol:'tcp', length:120 },
    { source:'10.0.0.4', destination:'8.8.8.8', protocol:'dns', length:80 }
  ]));
  assert.equal(result.packetCount, 2);
  assert.equal(result.totalBytes, 200);
  assert.match(result.sha256, /^[a-f0-9]{64}$/);
});
