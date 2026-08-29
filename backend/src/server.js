/* Copyright © 2026 Beacon of the Eagle LLC. All Rights Reserved. Proprietary software. */
require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const { query, transaction, withTenant, migrate } = require('./db');
const { emitSecurityEvent } = require('./security/telemetry');
const metrics = require('./metrics');
const { anchorAllTenants } = require('./security/audit-anchor');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin(origin, done) {
  const allowed = (process.env.ALLOWED_ORIGINS || '').split(',').map(v => v.trim()).filter(Boolean);
  const permitted = !origin || allowed.includes(origin) || (process.env.NODE_ENV !== 'production' && !allowed.length);
  done(permitted ? null : new Error('Origin is not allowed'), permitted);
}, credentials: true }));
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  const started = Date.now();
  res.on('finish', () => metrics.increment('centinell_http_requests_total', { method:req.method, status:res.statusCode, route:(req.route && req.route.path) || 'unmatched' }));
  res.on('finish', () => { if (Date.now()-started > 2000) metrics.increment('centinell_slow_requests_total'); });
  next();
});

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 180, standardHeaders: 'draft-8', legacyHeaders: false });
app.use('/api/', apiLimiter);

function secret() {
  const value = process.env.JWT_SECRET;
  if (!value || value.length < 32) throw new Error('JWT_SECRET must contain at least 32 characters');
  return value;
}
function issueToken(user) {
  return jwt.sign({ sub: user.id, org: user.organization_id, role: user.role }, secret(), { expiresIn: '8h', issuer: 'centinell-forensics', audience: 'centinell-web' });
}
function setSession(res, token) {
  res.cookie('centinell_session', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000, path: '/' });
}
function requireAuth(req, res, next) {
  try {
    req.auth = jwt.verify(req.cookies.centinell_session || '', secret(), { issuer: 'centinell-forensics', audience: 'centinell-web' });
    next();
  } catch (_) { res.status(401).json({ type: 'about:blank', title: 'Authentication required', status: 401 }); }
}
function allow(...roles) { return (req, res, next) => roles.includes(req.auth.role) ? next() : res.status(403).json({ title: 'Insufficient permission', status: 403 }); }
async function audit(req, action, entityType, entityId, metadata = {}, client) {
  const insert = tenantClient => query('INSERT INTO audit_events (organization_id, actor_id, action, entity_type, entity_id, metadata, ip) VALUES ($1,$2,$3,$4,$5,$6,$7)', [req.auth.org, req.auth.sub, action, entityType, entityId, metadata, req.ip], tenantClient);
  if (client) await insert(client); else await withTenant(req.auth.org, insert);
  emitSecurityEvent({ organizationId:req.auth.org, actorId:req.auth.sub, action, entityType, entityId, metadata }).catch(error => console.error(JSON.stringify({ level:'error', event:'siem.delivery_failed', message:error.message })));
}
function asyncRoute(handler) { return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next); }

const registerSchema = z.object({ organization: z.string().trim().min(2).max(120), fullName: z.string().trim().min(2).max(120), email: z.email().max(254), password: z.string().min(12).max(128) });
app.post('/api/v1/auth/register', authLimiter, asyncRoute(async (req, res) => {
  const input = registerSchema.parse(req.body);
  const hash = await bcrypt.hash(input.password, 12);
  const slugBase = input.organization.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'organization';
  const user = await transaction(async client => {
    const org = await client.query('INSERT INTO organizations (name, slug) VALUES ($1,$2) RETURNING id,name', [input.organization, `${slugBase}-${crypto.randomBytes(3).toString('hex')}`]);
    const result = await client.query('INSERT INTO users (organization_id,email,password_hash,full_name,role) VALUES ($1,lower($2),$3,$4,$5) RETURNING id,organization_id,email,full_name,role', [org.rows[0].id, input.email, hash, input.fullName, 'admin']);
    await client.query("SELECT set_config('app.current_organization_id', $1, true)", [org.rows[0].id]);
    await client.query('INSERT INTO audit_events (organization_id,actor_id,action,entity_type,entity_id) VALUES ($1,$2,$3,$4,$5)', [org.rows[0].id, result.rows[0].id, 'organization.created', 'organization', org.rows[0].id]);
    return { ...result.rows[0], organization_name: org.rows[0].name };
  });
  setSession(res, issueToken(user));
  res.status(201).json({ user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, organization: user.organization_name } });
}));

const loginSchema = z.object({ email: z.email(), password: z.string().min(1).max(128) });
app.post('/api/v1/auth/login', authLimiter, asyncRoute(async (req, res) => {
  const input = loginSchema.parse(req.body);
  const result = await query('SELECT u.*,o.name organization_name FROM users u JOIN organizations o ON o.id=u.organization_id WHERE lower(u.email)=lower($1)', [input.email]);
  const user = result.rows[0];
  if (!user || (user.locked_until && new Date(user.locked_until) > new Date()) || !(await bcrypt.compare(input.password, user.password_hash))) {
    if (user) await query("UPDATE users SET failed_attempts=failed_attempts+1, locked_until=CASE WHEN failed_attempts>=4 THEN now()+interval '15 minutes' ELSE locked_until END WHERE id=$1", [user.id]);
    return res.status(401).json({ title: 'Invalid email or password', status: 401 });
  }
  await query('UPDATE users SET failed_attempts=0,locked_until=NULL,last_login_at=now() WHERE id=$1', [user.id]);
  setSession(res, issueToken(user));
  res.json({ user: { id: user.id, email: user.email, fullName: user.full_name, role: user.role, organization: user.organization_name } });
}));
app.post('/api/v1/auth/logout', (req, res) => { res.clearCookie('centinell_session', { path: '/' }); res.status(204).end(); });
app.get('/api/v1/auth/me', requireAuth, asyncRoute(async (req, res) => {
  const result = await query('SELECT u.id,u.email,u.full_name,u.role,o.name organization FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.id=$1 AND u.organization_id=$2', [req.auth.sub, req.auth.org]);
  if (!result.rows[0]) return res.status(401).json({ title: 'Session not found', status: 401 });
  const u = result.rows[0]; res.json({ user: { id: u.id, email: u.email, fullName: u.full_name, role: u.role, organization: u.organization } });
}));

const caseSchema = z.object({ title: z.string().trim().min(3).max(180), caseType: z.string().trim().min(2).max(80), priority: z.enum(['Critical','High','Medium','Low']), description: z.string().trim().max(4000).default('') });
app.get('/api/v1/cases', requireAuth, asyncRoute(async (req, res) => {
  const result = await withTenant(req.auth.org, client => client.query('SELECT id,case_number "caseNumber",title,case_type "caseType",priority,status,description,created_at "createdAt" FROM cases WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 200', [req.auth.org]));
  res.json({ cases: result.rows });
}));

app.get('/api/v1/dashboard/summary', requireAuth, asyncRoute(async (req, res) => {
  const summary = await withTenant(req.auth.org, async client => {
    const [cases, evidence, auditEvents, chain] = await Promise.all([
      client.query(`SELECT
        count(*) FILTER (WHERE status NOT IN ('Closed','Closing'))::int AS active_cases,
        count(*) FILTER (WHERE priority='Critical' AND status NOT IN ('Closed','Closing'))::int AS critical_cases,
        count(*) FILTER (WHERE status='In Review')::int AS cases_in_review,
        count(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS cases_this_month
        FROM cases WHERE organization_id=$1`, [req.auth.org]),
      client.query(`SELECT count(*)::int AS evidence_items,
        count(*) FILTER (WHERE plaintext_sha256 ~ '^[0-9a-f]{64}$')::int AS verified_hashes,
        coalesce(sum(size_bytes),0)::text AS storage_bytes
        FROM evidence_objects WHERE organization_id=$1`, [req.auth.org]),
      client.query(`SELECT count(*) FILTER (WHERE created_at >= now()-interval '24 hours')::int AS audit_events_24h,
        max(created_at) AS last_audit_at FROM audit_events WHERE organization_id=$1`, [req.auth.org]),
      client.query('SELECT centinell_verify_audit_chain($1) AS valid', [req.auth.org])
    ]);
    return { ...cases.rows[0], ...evidence.rows[0], ...auditEvents.rows[0], audit_chain_valid: chain.rows[0].valid };
  });
  res.json({ summary, generatedAt: new Date().toISOString() });
}));

app.get('/api/v1/evidence', requireAuth, asyncRoute(async (req, res) => {
  const result = await withTenant(req.auth.org, client => client.query(`
    SELECT e.id,e.object_key "objectKey",e.plaintext_sha256 "sha256",e.cipher,e.kms_key_id "kmsKeyId",
      e.size_bytes "sizeBytes",e.created_at "createdAt",c.case_number "caseNumber",c.title "caseTitle"
    FROM evidence_objects e JOIN cases c ON c.id=e.case_id
    WHERE e.organization_id=$1 ORDER BY e.created_at DESC LIMIT 200`, [req.auth.org]));
  res.json({ evidence: result.rows });
}));

const analysisQuerySchema = z.object({
  module: z.string().trim().regex(/^[a-z-]{2,40}$/).default('command'),
  metric: z.string().trim().min(2).max(100).default('security-metric')
});
app.get('/api/v1/analysis', requireAuth, asyncRoute(async (req, res) => {
  const input = analysisQuerySchema.parse(req.query);
  const analysis = await withTenant(req.auth.org, async client => {
    const [cases, evidence, events, chain] = await Promise.all([
      client.query(`SELECT id,case_number "caseNumber",title,case_type "caseType",priority,status,
        created_at "createdAt",updated_at "updatedAt" FROM cases WHERE organization_id=$1
        ORDER BY updated_at DESC LIMIT 12`, [req.auth.org]),
      client.query(`SELECT e.id,e.object_key "objectKey",e.plaintext_sha256 "sha256",e.cipher,
        e.size_bytes "sizeBytes",e.created_at "createdAt",c.case_number "caseNumber"
        FROM evidence_objects e JOIN cases c ON c.id=e.case_id
        WHERE e.organization_id=$1 ORDER BY e.created_at DESC LIMIT 12`, [req.auth.org]),
      client.query(`SELECT id,action,entity_type "entityType",entity_id "entityId",metadata,
        event_hash "eventHash",previous_hash "previousHash",created_at "createdAt"
        FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 20`, [req.auth.org]),
      client.query('SELECT centinell_verify_audit_chain($1) AS valid', [req.auth.org])
    ]);
    return { module: input.module, metric: input.metric, cases: cases.rows, evidence: evidence.rows,
      auditEvents: events.rows, auditChainValid: chain.rows[0].valid };
  });
  res.json({ analysis, generatedAt: new Date().toISOString(), tenant: req.auth.org });
}));
app.post('/api/v1/cases', requireAuth, allow('admin','analyst'), asyncRoute(async (req, res) => {
  const input = caseSchema.parse(req.body);
  const created = await transaction(async client => {
    await client.query("SELECT set_config('app.current_organization_id', $1, true)", [req.auth.org]);
    const seq = await client.query("SELECT 'CASE-' || lpad((coalesce(max(substring(case_number from 6)::int),2000)+1)::text,4,'0') value FROM cases WHERE organization_id=$1", [req.auth.org]);
    const result = await client.query('INSERT INTO cases (organization_id,case_number,title,case_type,priority,description,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,case_number "caseNumber",title,case_type "caseType",priority,status,description,created_at "createdAt"', [req.auth.org, seq.rows[0].value, input.title, input.caseType, input.priority, input.description, req.auth.sub]);
    await audit(req, 'case.created', 'case', result.rows[0].id, { caseNumber: result.rows[0].caseNumber }, client);
    return result.rows[0];
  });
  res.status(201).json({ case: created });
}));

app.get('/api/v1/audit', requireAuth, allow('admin','auditor'), asyncRoute(async (req, res) => {
  const result = await withTenant(req.auth.org, client => client.query('SELECT id,action,entity_type "entityType",entity_id "entityId",metadata,previous_hash "previousHash",event_hash "eventHash",created_at "createdAt" FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 250', [req.auth.org]));
  res.json({ events: result.rows });
}));

const aiSchema = z.object({ message: z.string().trim().min(2).max(6000) });
app.post('/api/v1/ai/chat', requireAuth, asyncRoute(async (req, res) => {
  const { message } = aiSchema.parse(req.body);
  if (!process.env.ANTHROPIC_API_KEY) return res.status(503).json({ title: 'AI service is not configured', status: 503 });
  const response = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type':'application/json', 'x-api-key':process.env.ANTHROPIC_API_KEY, 'anthropic-version':'2023-06-01' }, body: JSON.stringify({ model:'claude-sonnet-4-20250514', max_tokens:1200, system:'You are Centinell AI, a careful DFIR assistant. Never claim evidence that is not supplied. Flag legal conclusions for human review.', messages:[{ role:'user', content:message }] }) });
  if (!response.ok) return res.status(502).json({ title: 'AI provider request failed', status: 502 });
  const data = await response.json();
  await audit(req, 'ai.requested', 'ai_session', null, { characters: message.length });
  res.json({ reply: (data.content || []).filter(x => x.type === 'text').map(x => x.text).join('\n') });
}));

app.get('/api/v1/health', asyncRoute(async (_req, res) => {
  const db = await query('SELECT 1 ok');
  res.json({ status: db.rows[0].ok === 1 ? 'ok' : 'degraded', service: 'centinell-forensics-enterprise', timestamp: new Date().toISOString() });
}));
app.get('/api/v1/ready', (_req, res) => res.json({ status: 'ready' }));
app.get('/metrics', (req, res) => {
  const expected = process.env.METRICS_TOKEN;
  if (!expected || req.get('authorization') !== `Bearer ${expected}`) return res.status(401).end();
  res.type('text/plain; version=0.0.4').send(metrics.render());
});

const frontendPath = path.join(__dirname, '..', '..', 'frontend', 'public');
app.use(express.static(frontendPath, { extensions: ['html'], maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));
app.get('/{*splat}', (_req, res) => res.sendFile(path.join(frontendPath, 'index.html')));
app.use((error, _req, res, _next) => {
  if (error instanceof z.ZodError) return res.status(400).json({ title: 'Validation failed', status: 400, errors: error.issues.map(i => ({ path: i.path.join('.'), message: i.message })) });
  if (error.code === '23505') return res.status(409).json({ title: 'That account or record already exists', status: 409 });
  console.error(error); res.status(500).json({ title: 'Internal server error', status: 500, traceId: crypto.randomUUID() });
});

async function start() {
  secret();
  await migrate();
  const port = Number(process.env.PORT || 3000);
  app.listen(port, () => console.log(`Centinell Forensics listening on ${port}`));
  if (process.env.AUDIT_ANCHOR_URL) {
    setInterval(() => anchorAllTenants().catch(error => console.error(JSON.stringify({ level:'error', event:'audit.anchor_failed', message:error.message }))), 15 * 60 * 1000).unref();
  }
}
if (require.main === module) start().catch(error => { console.error(error); process.exit(1); });
module.exports = { app };
