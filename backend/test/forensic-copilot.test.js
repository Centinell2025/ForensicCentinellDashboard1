const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { DEFAULT_ADVISOR_DIRECTIVE, buildEvidenceContext } = require('../../forensic-advisor');

test('forensic advisor loads the exact default and labels context by verification state', () => {
  assert.match(DEFAULT_ADVISOR_DIRECTIVE, /^Eres el asesor forense de Centinell Forensics Enterprise\./);
  assert.match(DEFAULT_ADVISOR_DIRECTIVE, /Nunca inventes hechos/);
  const context = buildEvidenceContext([
    { id: 'verified-1', source: 'hayabusa', status: 'verified', title: 'Confirmed event' },
    { id: 'pending-1', source: 'oletools', status: 'pending_verification', title: 'Unverified macro' }
  ]);
  assert.match(context, /"verifiedFindings"/);
  assert.match(context, /"pendingVerification"/);
  assert.match(context, /Pending findings are NOT confirmed/);
});

if (!process.env.DATABASE_URL) {
  test('forensic copilot persistence integration requires DATABASE_URL', { skip: 'DATABASE_URL is not configured in this environment' }, () => {});
} else {
  process.env.JWT_SECRET ||= 'ci-only-secret-longer-than-thirty-two-characters';
  process.env.NODE_ENV ||= 'test';

  const { app } = require('../src/server');
  const { getPool, migrate, query, withTenant } = require('../src/db');

  let httpServer;
  let baseUrl;
  let organizationId;
  let userId;
  let sessionCookie;
  const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const email = `copilot-${suffix}@example.test`;
  const password = 'Copilot-Test-Password-2026!';

  async function jsonRequest(path, options = {}) {
    const response = await fetch(`${baseUrl}${path}`, {
      ...options,
      headers: { 'content-type': 'application/json', ...(options.headers || {}), ...(sessionCookie ? { cookie: sessionCookie } : {}) }
    });
    const body = await response.json().catch(() => ({}));
    return { response, body };
  }

  before(async () => {
    await migrate();
    httpServer = await new Promise(resolve => {
      const server = app.listen(0, () => resolve(server));
    });
    baseUrl = `http://127.0.0.1:${httpServer.address().port}`;

    const health = await jsonRequest('/api/v1/health');
    assert.equal(health.response.status, 200);
    assert.equal(health.body.status, 'ok');

    const registered = await jsonRequest('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify({ organization: `Copilot Test ${suffix}`, fullName: 'Copilot Test Analyst', email, password })
    });
    assert.equal(registered.response.status, 201);
    const setCookie = registered.response.headers.get('set-cookie') || '';
    sessionCookie = setCookie.split(';')[0];
    assert.match(sessionCookie, /^centinell_session=/);

    const user = await query('SELECT id,organization_id FROM users WHERE email=$1', [email]);
    userId = user.rows[0].id;
    organizationId = user.rows[0].organization_id;
  });

  after(async () => {
    if (organizationId) await query('DELETE FROM organizations WHERE id=$1', [organizationId]);
    if (httpServer) await new Promise(resolve => httpServer.close(resolve));
  });

  test('loads the default directive, persists and audits changes, and stores AI output as a pending report draft', async () => {
    const initial = await jsonRequest('/api/v1/advisor-directive');
    assert.equal(initial.response.status, 200);
    assert.equal(initial.body.directive, DEFAULT_ADVISOR_DIRECTIVE);
    assert.equal(initial.body.isDefault, true);

    const customDirective = `${DEFAULT_ADVISOR_DIRECTIVE}\nAdditional analyst instruction: state uncertainty before recommendations.`;
    const saved = await jsonRequest('/api/v1/advisor-directive', {
      method: 'PUT',
      body: JSON.stringify({ directive: customDirective })
    });
    assert.equal(saved.response.status, 200);
    assert.equal(saved.body.directive, customDirective);
    assert.equal(saved.body.isDefault, false);

    const reloaded = await jsonRequest('/api/v1/advisor-directive');
    assert.equal(reloaded.body.directive, customDirective);
    assert.equal(reloaded.body.isDefault, false);

    const directiveAudit = await withTenant(organizationId, client => client.query(`
      SELECT action,actor_id,metadata->>'directive' directive
      FROM audit_events
      WHERE organization_id=$1 AND action='ai.advisor_directive.updated'
      ORDER BY id DESC LIMIT 1`, [organizationId]));
    assert.equal(directiveAudit.rows[0].action, 'ai.advisor_directive.updated');
    assert.equal(directiveAudit.rows[0].actor_id, userId);
    assert.equal(directiveAudit.rows[0].directive, customDirective);

    const seeded = await withTenant(organizationId, async client => {
      const caseResult = await client.query(`INSERT INTO cases
        (organization_id,case_number,title,case_type,priority,created_by)
        VALUES($1,$2,'Windows event review','Digital Forensics','High',$3) RETURNING id,case_number "caseNumber"`,
        [organizationId, `CASE-${String(Math.floor(Math.random() * 9000) + 1000)}`, userId]);
      const findingResult = await client.query(`INSERT INTO forensic_findings
        (organization_id,case_id,source,status,title,summary,artifact_id,tool_version)
        VALUES($1,$2,'hayabusa','verified','Suspicious logon event','Event 4624 correlated to the tenant case.','Security.evtx:4624','Hayabusa 3.x')
        RETURNING id`, [organizationId, caseResult.rows[0].id]);
      return { caseId: caseResult.rows[0].id, caseNumber: caseResult.rows[0].caseNumber, findingId: findingResult.rows[0].id };
    });

    const findings = await jsonRequest(`/api/v1/forensic-findings?caseId=${seeded.caseId}`);
    assert.equal(findings.response.status, 200);
    assert.equal(findings.body.findings.length, 1);
    assert.equal(findings.body.findings[0].source, 'hayabusa');
    assert.equal(findings.body.findings[0].status, 'verified');

    const draft = await jsonRequest('/api/v1/reports/drafts', {
      method: 'POST',
      body: JSON.stringify({
        title: 'AI case draft',
        body: 'Draft response citing Security.evtx:4624 and Hayabusa 3.x.',
        caseId: seeded.caseId,
        citedFindingIds: [seeded.findingId],
        status: 'verified'
      })
    });
    assert.equal(draft.response.status, 201);
    assert.equal(draft.body.draft.status, 'pending_verification');
    assert.equal(draft.body.draft.caseNumber, seeded.caseNumber);
    assert.deepEqual(draft.body.draft.citedFindingIds, [seeded.findingId]);

    const storedDraft = await withTenant(organizationId, client => client.query(`
      SELECT status,source FROM report_drafts WHERE organization_id=$1 AND id=$2`, [organizationId, draft.body.draft.id]));
    assert.equal(storedDraft.rows[0].status, 'pending_verification');
    assert.equal(storedDraft.rows[0].source, 'centinell_ai');

    const draftAudit = await withTenant(organizationId, client => client.query(`
      SELECT action,metadata->>'status' status FROM audit_events
      WHERE organization_id=$1 AND entity_id=$2`, [organizationId, draft.body.draft.id]));
    assert.ok(draftAudit.rows.some(row => row.action === 'ai.report_draft.created' && row.status === 'pending_verification'));
  });
}
