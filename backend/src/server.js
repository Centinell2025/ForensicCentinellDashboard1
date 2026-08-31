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
const { anchorAllTenants, anchorTenant } = require('./security/audit-anchor');
const { COMMANDS, classifyIndicator, virusTotalLookup, taxiiLookup, packetSummary } = require('./security/investigation-console');
const { DEFAULT_ADVISOR_DIRECTIVE, CENTINELL_AI_MODEL, normalizeFinding } = require('../../forensic-advisor');

const app = express();
const PLATFORM_VERSION = '1.1.0';
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
function configuredOrigins() {
  return (process.env.ALLOWED_ORIGINS || '').split(',').map(value => value.trim()).filter(Boolean);
}
app.use(cors({ origin(origin, done) {
  const allowed = configuredOrigins();
  const permitted = !origin || allowed.includes(origin) || (process.env.NODE_ENV !== 'production' && !allowed.length);
  done(permitted ? null : new Error('Origin is not allowed'), permitted);
}, credentials: true }));
app.use(express.json({ limit: '256kb' }));
app.use(cookieParser());
app.use((req, res, next) => {
  if (['GET','HEAD','OPTIONS'].includes(req.method)) return next();
  const origin = req.get('origin');
  const fetchSite = req.get('sec-fetch-site');
  const ownOrigin = `${req.protocol}://${req.get('host')}`;
  const trusted = new Set([ownOrigin, ...configuredOrigins()]);
  if (fetchSite === 'cross-site' || (origin && !trusted.has(origin))) {
    return res.status(403).json({ type:'about:blank', title:'Cross-site request rejected', status:403 });
  }
  next();
});
app.use((req, res, next) => {
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
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
  const insert = tenantClient => query('INSERT INTO audit_events (organization_id, actor_id, action, entity_type, entity_id, metadata, ip) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id,action,entity_type "entityType",entity_id "entityId",metadata,previous_hash "previousHash",event_hash "eventHash",created_at "createdAt"', [req.auth.org, req.auth.sub, action, entityType, entityId, metadata, req.ip], tenantClient);
  const result = client ? await insert(client) : await withTenant(req.auth.org, insert);
  const event = result.rows[0] || null;
  emitSecurityEvent({ organizationId:req.auth.org, actorId:req.auth.sub, action, entityType, entityId, metadata }).catch(error => console.error(JSON.stringify({ level:'error', event:'siem.delivery_failed', message:error.message })));
  return event;
}
function asyncRoute(handler) { return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next); }
function httpError(status, title) { const error = new Error(title); error.status = status; return error; }
function optionalUuid(value) { return value == null || String(value).trim() === '' ? null : z.uuid().parse(String(value)); }
function requestAuditAnchor(organizationId) {
  if (!process.env.AUDIT_ANCHOR_URL) return;
  anchorTenant(organizationId).catch(error => console.error(JSON.stringify({ level:'error', event:'audit.anchor_failed', message:error.message })));
}
async function assertCaseTenant(client, organizationId, caseId) {
  if (!caseId) return;
  const result = await client.query('SELECT id FROM cases WHERE id=$1 AND organization_id=$2', [caseId, organizationId]);
  if (!result.rowCount) throw httpError(404, 'Case is not available in this tenant');
}

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
app.post('/api/v1/auth/logout', (req, res) => { res.clearCookie('centinell_session', { httpOnly:true, secure:process.env.NODE_ENV==='production', sameSite:'strict', path:'/' }); res.status(204).end(); });
app.get('/api/v1/auth/me', requireAuth, asyncRoute(async (req, res) => {
  const result = await query('SELECT u.id,u.email,u.full_name,u.role,o.name organization FROM users u JOIN organizations o ON o.id=u.organization_id WHERE u.id=$1 AND u.organization_id=$2', [req.auth.sub, req.auth.org]);
  if (!result.rows[0]) return res.status(401).json({ title: 'Session not found', status: 401 });
  const u = result.rows[0]; res.json({ user: { id: u.id, email: u.email, fullName: u.full_name, role: u.role, organization: u.organization } });
}));

const organizationSettingsSchema = z.object({
  name: z.string().trim().min(2).max(120),
  timezone: z.string().trim().min(2).max(80).regex(/^[A-Za-z_+\/-]+$/),
  evidenceRetentionDays: z.number().int().min(1).max(36500),
  notifications: z.object({ criticalEmail:z.boolean(), p1Sms:z.boolean(), executiveDigest:z.boolean(), complianceReminders:z.boolean() }).default({ criticalEmail:true,p1Sms:true,executiveDigest:true,complianceReminders:false })
});
app.get('/api/v1/settings/organization', requireAuth, asyncRoute(async (req, res) => {
  const result=await query(`SELECT name,timezone,evidence_retention_days "evidenceRetentionDays",notification_preferences notifications
    FROM organizations WHERE id=$1`,[req.auth.org]);
  if(!result.rows[0])return res.status(404).json({title:'Organization not found',status:404});res.json({settings:result.rows[0]});
}));
app.put('/api/v1/settings/organization', requireAuth, allow('admin'), asyncRoute(async (req, res) => {
  const input=organizationSettingsSchema.parse(req.body);
  const settings=await transaction(async client=>{await client.query("SELECT set_config('app.current_organization_id',$1,true)",[req.auth.org]);const result=await client.query(`UPDATE organizations SET name=$1,timezone=$2,evidence_retention_days=$3,notification_preferences=$4
      WHERE id=$5 RETURNING name,timezone,evidence_retention_days "evidenceRetentionDays",notification_preferences notifications`,[input.name,input.timezone,input.evidenceRetentionDays,JSON.stringify(input.notifications),req.auth.org]);await audit(req,'organization.settings_updated','organization',req.auth.org,{timezone:input.timezone,evidenceRetentionDays:input.evidenceRetentionDays},client);return result.rows[0]});
  res.json({settings});
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

const kpiSubscribers = new Map();
function toNonNegativeBigInt(value) {
  const text = String(value == null ? '0' : value);
  return /^\d+$/.test(text) ? BigInt(text) : 0n;
}
function formatBytes(value) {
  const bytes = toNonNegativeBigInt(value);
  const units = ['B','KB','MB','GB','TB','PB'];
  let amount = Number(bytes);
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return amount.toFixed(index ? 1 : 0) + ' ' + units[index];
}
function configuredStorageCapacity() {
  const value = process.env.STORAGE_CAPACITY_BYTES;
  return /^\d+$/.test(value || '') && toNonNegativeBigInt(value) > 0n ? value : null;
}
function storagePercent(used, capacity) {
  const usedBytes = toNonNegativeBigInt(used);
  const capacityBytes = toNonNegativeBigInt(capacity);
  if (!capacityBytes) return null;
  return Number((usedBytes * 10000n) / capacityBytes) / 100;
}
async function loadKpiSnapshot(organizationId) {
  const capacity = configuredStorageCapacity();
  return withTenant(organizationId, async client => {
    const [cases, evidence, auditEvents, chain] = await Promise.all([
      client.query(`SELECT
        count(*) FILTER (WHERE status NOT IN ('Closed','Closing'))::int AS active_cases,
        count(*) FILTER (WHERE priority='Critical' AND status NOT IN ('Closed','Closing'))::int AS critical_alerts,
        count(*) FILTER (WHERE status='In Review')::int AS cases_in_review,
        count(*) FILTER (WHERE created_at >= date_trunc('month', now()))::int AS cases_this_month
        FROM cases WHERE organization_id=$1`, [organizationId]),
      client.query(`SELECT count(*)::int AS evidence_items,
        count(*) FILTER (WHERE plaintext_sha256 ~ '^[0-9a-f]{64}$')::int AS verified_hashes,
        coalesce(sum(size_bytes),0)::text AS storage_bytes
        FROM evidence_objects WHERE organization_id=$1`, [organizationId]),
      client.query(`SELECT count(*) FILTER (WHERE created_at >= now()-interval '24 hours')::int AS events_24h,
        max(created_at) AS last_event_at FROM audit_events WHERE organization_id=$1`, [organizationId]),
      client.query('SELECT centinell_verify_audit_chain($1) AS valid', [organizationId])
    ]);
    const caseRow = cases.rows[0] || {};
    const evidenceRow = evidence.rows[0] || {};
    const auditRow = auditEvents.rows[0] || {};
    const totalEvidence = Number(evidenceRow.evidence_items || 0);
    const verifiedHashes = Number(evidenceRow.verified_hashes || 0);
    const pendingIntake = Math.max(totalEvidence - verifiedHashes, 0);
    const usedBytes = String(evidenceRow.storage_bytes || '0');
    return {
      version: PLATFORM_VERSION,
      generatedAt: new Date().toISOString(),
      source: 'tenant_database',
      tenantScoped: true,
      kpis: {
        activeCases: Number(caseRow.active_cases || 0),
        criticalAlerts: Number(caseRow.critical_alerts || 0),
        casesInReview: Number(caseRow.cases_in_review || 0),
        casesThisMonth: Number(caseRow.cases_this_month || 0),
        totalEvidenceItems: totalEvidence,
        verifiedHashes,
        pendingIntake,
        storageUsedBytes: usedBytes,
        storageUsedLabel: formatBytes(usedBytes),
        storageCapacityBytes: capacity,
        storageCapacityLabel: capacity ? formatBytes(capacity) : null,
        assetsAtRisk: null
      },
      evidenceIntegrity: {
        algorithm: 'SHA-256',
        totalItems: totalEvidence,
        verifiedHashes,
        pendingIntake,
        percentage: totalEvidence ? Number((verifiedHashes * 100 / totalEvidence).toFixed(2)) : 100
      },
      storage: {
        usedBytes,
        usedLabel: formatBytes(usedBytes),
        allocatedBytes: capacity,
        allocatedLabel: capacity ? formatBytes(capacity) : null,
        utilizationPercent: storagePercent(usedBytes, capacity)
      },
      audit: {
        events24h: Number(auditRow.events_24h || 0),
        lastEventAt: auditRow.last_event_at || null,
        chainValid: Boolean(chain.rows[0] && chain.rows[0].valid)
      },
      unavailableMetrics: ['assetsAtRisk']
    };
  });
}
function sendKpiEvent(response, eventName, payload) {
  if (response.writableEnded || response.destroyed) return false;
  response.write('event: ' + eventName + '\ndata: ' + JSON.stringify(payload) + '\n\n');
  return true;
}
function publishKpiEvent(organizationId, payload) {
  const subscribers = kpiSubscribers.get(organizationId);
  if (!subscribers) return;
  subscribers.forEach(response => {
    try {
      if (!sendKpiEvent(response, 'kpi.event', payload)) subscribers.delete(response);
    } catch (_) {
      subscribers.delete(response);
    }
  });
  if (!subscribers.size) kpiSubscribers.delete(organizationId);
}

app.get('/api/v1/dashboard/kpis', requireAuth, asyncRoute(async (req, res) => {
  res.json(await loadKpiSnapshot(req.auth.org));
}));

app.get('/api/v1/dashboard/kpis/stream', requireAuth, asyncRoute(async (req, res) => {
  res.status(200).set({
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-store, must-revalidate',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  if (typeof res.flushHeaders === 'function') res.flushHeaders();
  req.setTimeout(0);
  const subscribers = kpiSubscribers.get(req.auth.org) || new Set();
  subscribers.add(res);
  kpiSubscribers.set(req.auth.org, subscribers);
  let closed = false;
  let heartbeat;
  let refresh;
  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(heartbeat);
    clearInterval(refresh);
    subscribers.delete(res);
    if (!subscribers.size) kpiSubscribers.delete(req.auth.org);
  };
  req.on('close', cleanup);
  const pushSnapshot = async () => {
    try {
      const snapshot = await loadKpiSnapshot(req.auth.org);
      if (!closed) sendKpiEvent(res, 'kpi.snapshot', snapshot);
    } catch (error) {
      if (!closed) sendKpiEvent(res, 'kpi.error', { version: PLATFORM_VERSION, title: 'KPI snapshot unavailable', status: 503 });
      console.error(JSON.stringify({ level:'error', event:'dashboard.kpi_snapshot_failed', message:error.message }));
    }
  };
  await pushSnapshot();
  heartbeat = setInterval(() => { if (!closed) res.write(': keep-alive\n\n'); }, 15000);
  refresh = setInterval(pushSnapshot, 30000);
}));

app.get('/api/v1/command/modules', requireAuth, (_req, res) => res.json({ modules:[
  { id:'operations-volume', route:'soc', capability:'Tenant-scoped SOC telemetry and investigation' },
  { id:'priority-activity', route:'soc', capability:'Alert triage and correlated activity' },
  { id:'open-cases', route:'cases', capability:'Case investigation and evidence workflow' },
  { id:'compliance-posture', route:'risk', capability:'Control coverage and finding review' },
  { id:'real-time-operations', route:'soc', capability:'Operational telemetry workspace' }
], generatedAt:new Date().toISOString() }));

app.get('/api/v1/evidence', requireAuth, asyncRoute(async (req, res) => {
  const result = await withTenant(req.auth.org, client => client.query(`
    SELECT e.id,e.object_key "objectKey",e.plaintext_sha256 "sha256",e.cipher,e.kms_key_id "kmsKeyId",
      e.size_bytes "sizeBytes",e.created_at "createdAt",c.case_number "caseNumber",c.title "caseTitle"
    FROM evidence_objects e JOIN cases c ON c.id=e.case_id
    WHERE e.organization_id=$1 ORDER BY e.created_at DESC LIMIT 200`, [req.auth.org]));
  res.json({ evidence: result.rows });
}));

const evidenceDetailProjection = 'SELECT e.id,e.object_key "objectKey",e.plaintext_sha256 "sha256",e.ciphertext_sha256 "ciphertextSha256",e.cipher,e.kms_key_id "kmsKeyId",e.size_bytes::text "sizeBytes",e.created_at "createdAt",e.created_by "createdById",u.full_name "createdByName",u.email "createdByEmail",c.id "caseId",c.case_number "caseNumber",c.title "caseTitle" FROM evidence_objects e JOIN cases c ON c.id=e.case_id LEFT JOIN users u ON u.id=e.created_by';
function isSha256(value) {
  return /^[0-9a-f]{64}$/i.test(String(value || ''));
}
function acquisitionMetadata(row) {
  return {
    objectKey: row.objectKey,
    caseId: row.caseId,
    caseNumber: row.caseNumber,
    caseTitle: row.caseTitle,
    sha256: row.sha256,
    ciphertextSha256: row.ciphertextSha256,
    cipher: row.cipher,
    kmsKeyId: row.kmsKeyId,
    sizeBytes: row.sizeBytes,
    createdAt: row.createdAt,
    createdBy: { id: row.createdById, name: row.createdByName, email: row.createdByEmail }
  };
}
async function loadEvidenceDetail(organizationId, evidenceKey) {
  return withTenant(organizationId, async client => {
    const result = await client.query(evidenceDetailProjection + ' WHERE e.organization_id=$1 AND (e.object_key=$2 OR e.id::text=$2) LIMIT 1', [organizationId, evidenceKey]);
    if (!result.rowCount) return null;
    const row = result.rows[0];
    const events = await client.query('SELECT id,action,entity_type,entity_id,metadata,event_hash,previous_hash,created_at FROM audit_events WHERE organization_id=$1 AND (entity_id=$2 OR entity_id=$3 OR metadata->>$4=$2 OR metadata->>$5=$2) ORDER BY created_at DESC LIMIT 100', [organizationId, evidenceKey, row.id, 'objectKey', 'evidenceKey']);
    const chain = await client.query('SELECT centinell_verify_audit_chain($1) AS valid', [organizationId]);
    const verified = isSha256(row.sha256);
    return {
      version: PLATFORM_VERSION,
      generatedAt: new Date().toISOString(),
      source: 'tenant_database',
      tenantScoped: true,
      evidence: row,
      acquisitionMetadata: acquisitionMetadata(row),
      processing: {
        status: verified ? 'verified' : 'pending_verification',
        algorithm: 'SHA-256',
        hashPresent: verified,
        retryAvailable: !verified
      },
      history: events.rows.map(event => ({
        id: event.id,
        event: event.action,
        action: event.action,
        entityType: event.entity_type,
        entityId: event.entity_id,
        reference: event.entity_id,
        metadata: event.metadata,
        eventHash: event.event_hash,
        previousHash: event.previous_hash,
        timestamp: event.created_at
      })),
      audit: {
        chainValid: Boolean(chain.rows[0] && chain.rows[0].valid),
        events: events.rows
      }
    };
  });
}
app.get('/api/v1/evidence/:evidenceKey', requireAuth, asyncRoute(async (req, res) => {
  const detail = await loadEvidenceDetail(req.auth.org, String(req.params.evidenceKey));
  if (!detail) return res.status(404).json({ title: 'Evidence is not available in this tenant', status: 404 });
  res.json(detail);
}));

const hashRetrySchema = z.object({
  reason: z.string().trim().min(1).max(240).default('KPI drawer retry action')
});
app.post('/api/v1/evidence/:evidenceKey/retry', requireAuth, allow('admin','analyst'), asyncRoute(async (req, res) => {
  const input = hashRetrySchema.parse(req.body || {});
  const evidenceKey = String(req.params.evidenceKey);
  const accepted = await transaction(async client => {
    await client.query("SELECT set_config('app.current_organization_id',$1,true)", [req.auth.org]);
    const result = await client.query(evidenceDetailProjection + ' WHERE e.organization_id=$1 AND (e.object_key=$2 OR e.id::text=$2) LIMIT 1', [req.auth.org, evidenceKey]);
    if (!result.rowCount) throw httpError(404, 'Evidence is not available in this tenant');
    const row = result.rows[0];
    if (isSha256(row.sha256)) throw httpError(409, 'Evidence hash is already verified; no retry was queued');
    const retryRequestId = crypto.randomUUID();
    const event = await audit(req, 'evidence.hash_retry_requested', 'evidence', row.id, {
      evidenceKey: row.objectKey,
      caseNumber: row.caseNumber,
      algorithm: 'SHA-256',
      retryRequestId,
      reason: input.reason,
      immutableEvidence: true
    }, client);
    return { row, event, retryRequestId };
  });
  requestAuditAnchor(req.auth.org);
  publishKpiEvent(req.auth.org, {
    version: PLATFORM_VERSION,
    type: 'evidence.hash_retry_requested',
    generatedAt: new Date().toISOString(),
    evidenceKey: accepted.row.objectKey,
    retryRequestId: accepted.retryRequestId,
    auditEventId: accepted.event && accepted.event.id,
    auditEventHash: accepted.event && accepted.event.eventHash
  });
  let snapshot = null;
  try { snapshot = await loadKpiSnapshot(req.auth.org); } catch (_) {}
  res.status(202).json({
    version: PLATFORM_VERSION,
    accepted: true,
    status: 'retry_requested',
    retryRequestId: accepted.retryRequestId,
    evidence: accepted.row,
    acquisitionMetadata: acquisitionMetadata(accepted.row),
    processing: { status: 'pending_verification', algorithm: 'SHA-256', hashUnchanged: true, retryAvailable: true },
    audit: {
      chainStatus: 'event_appended',
      event: accepted.event,
      eventHash: accepted.event && accepted.event.eventHash,
      previousHash: accepted.event && accepted.event.previousHash
    },
    kpis: snapshot ? snapshot.kpis : null
  });
}));

const custodyStateSchema = z.object({
  status: z.enum(['in_review','legal_hold','released']).default('in_review'),
  reason: z.string().trim().min(1).max(240).default('KPI drawer custody action')
});
app.post('/api/v1/evidence/:evidenceKey/custody-state', requireAuth, allow('admin','analyst'), asyncRoute(async (req, res) => {
  const input = custodyStateSchema.parse(req.body || {});
  const evidenceKey = String(req.params.evidenceKey);
  const accepted = await transaction(async client => {
    await client.query("SELECT set_config('app.current_organization_id',$1,true)", [req.auth.org]);
    const result = await client.query(evidenceDetailProjection + ' WHERE e.organization_id=$1 AND (e.object_key=$2 OR e.id::text=$2) LIMIT 1', [req.auth.org, evidenceKey]);
    if (!result.rowCount) throw httpError(404, 'Evidence is not available in this tenant');
    const row = result.rows[0];
    const event = await audit(req, 'evidence.custody_state_recorded', 'evidence', row.id, {
      evidenceKey: row.objectKey,
      caseNumber: row.caseNumber,
      custodyState: input.status,
      reason: input.reason,
      appendOnly: true
    }, client);
    return { row, event };
  });
  requestAuditAnchor(req.auth.org);
  publishKpiEvent(req.auth.org, {
    version: PLATFORM_VERSION,
    type: 'evidence.custody_state_recorded',
    generatedAt: new Date().toISOString(),
    evidenceKey: accepted.row.objectKey,
    custodyState: input.status,
    auditEventId: accepted.event && accepted.event.id,
    auditEventHash: accepted.event && accepted.event.eventHash
  });
  res.status(202).json({
    version: PLATFORM_VERSION,
    accepted: true,
    status: 'custody_state_recorded',
    custodyState: input.status,
    evidence: accepted.row,
    acquisitionMetadata: acquisitionMetadata(accepted.row),
    history: [{
      id: accepted.event && accepted.event.id,
      event: accepted.event && accepted.event.action,
      action: accepted.event && accepted.event.action,
      status: input.status,
      reference: accepted.row.objectKey,
      timestamp: accepted.event && accepted.event.createdAt,
      eventHash: accepted.event && accepted.event.eventHash,
      previousHash: accepted.event && accepted.event.previousHash
    }],
    audit: {
      chainStatus: 'event_appended',
      event: accepted.event,
      eventHash: accepted.event && accepted.event.eventHash,
      previousHash: accepted.event && accepted.event.previousHash
    }
  });
}));

const corporateModules = ['ai-operations','operator-support','crm','websites','social-intelligence','call-reviews'];
const corporateModuleSchema = z.enum(corporateModules);
const corporateRecordSchema = z.object({
  fields: z.array(z.string().trim().min(1).max(120)).length(3)
});
app.get('/api/v1/corporate/:module', requireAuth, asyncRoute(async (req, res) => {
  const moduleName = corporateModuleSchema.parse(req.params.module);
  const result = await withTenant(req.auth.org, client => client.query(`SELECT id,module,fields,updated_at "updatedAt"
    FROM corporate_records WHERE organization_id=$1 AND module=$2 ORDER BY updated_at DESC LIMIT 500`, [req.auth.org,moduleName]));
  res.json({ module:moduleName, records:result.rows });
}));
app.post('/api/v1/corporate/:module', requireAuth, allow('admin','analyst'), asyncRoute(async (req, res) => {
  const moduleName = corporateModuleSchema.parse(req.params.module),input=corporateRecordSchema.parse(req.body);
  const record = await withTenant(req.auth.org, async client => {
    const result=await client.query(`INSERT INTO corporate_records (organization_id,module,fields,created_by)
      VALUES ($1,$2,$3,$4) RETURNING id,module,fields,updated_at "updatedAt"`,[req.auth.org,moduleName,JSON.stringify(input.fields),req.auth.sub]);
    await audit(req,'corporate_record.created','corporate_record',result.rows[0].id,{module:moduleName},client);return result.rows[0];
  });
  res.status(201).json({ record });
}));
app.delete('/api/v1/corporate/:module/:id', requireAuth, allow('admin','analyst'), asyncRoute(async (req, res) => {
  const moduleName=corporateModuleSchema.parse(req.params.module),recordId=z.uuid().parse(req.params.id);
  const removed=await withTenant(req.auth.org,async client=>{const result=await client.query('DELETE FROM corporate_records WHERE id=$1 AND organization_id=$2 AND module=$3 RETURNING id',[recordId,req.auth.org,moduleName]);if(!result.rowCount)return false;await audit(req,'corporate_record.deleted','corporate_record',recordId,{module:moduleName},client);return true});
  if(!removed)return res.status(404).json({title:'Record not found',status:404});res.status(204).end();
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

const investigationSchema = z.object({
  command: z.enum(COMMANDS),
  argument: z.string().max(120000).default('')
});
app.post('/api/v1/investigation/execute', requireAuth, allow('admin','analyst','auditor'), asyncRoute(async (req, res) => {
  const input = investigationSchema.parse(req.body);
  let result;
  if (input.command === 'help') {
    result = { commands: COMMANDS, safety: 'Allowlisted defensive operations only; no operating-system shell is exposed.' };
  } else if (input.command === 'packet-summary') {
    result = packetSummary(input.argument);
  } else if (input.command === 'ioc') {
    const indicator = classifyIndicator(input.argument);
    const local = await withTenant(req.auth.org, client => client.query(`SELECT id,action,entity_type "entityType",
      entity_id "entityId",created_at "createdAt" FROM audit_events WHERE organization_id=$1
      AND (metadata::text ILIKE $2 OR entity_id ILIKE $2) ORDER BY created_at DESC LIMIT 25`, [req.auth.org, `%${indicator.value}%`]));
    const [virusTotal, taxii] = await Promise.all([virusTotalLookup(indicator), taxiiLookup(indicator)]);
    result = { indicator, localMatches: local.rows, virusTotal, taxii };
  } else {
    result = await withTenant(req.auth.org, async client => {
      if (input.command === 'cases') return { rows:(await client.query(`SELECT case_number "caseNumber",title,priority,status,updated_at "updatedAt" FROM cases WHERE organization_id=$1 ORDER BY updated_at DESC LIMIT 25`, [req.auth.org])).rows };
      if (input.command === 'evidence') return { rows:(await client.query(`SELECT e.object_key "objectKey",e.plaintext_sha256 "sha256",e.cipher,e.size_bytes "sizeBytes",c.case_number "caseNumber",e.created_at "createdAt" FROM evidence_objects e JOIN cases c ON c.id=e.case_id WHERE e.organization_id=$1 ORDER BY e.created_at DESC LIMIT 25`, [req.auth.org])).rows };
      if (input.command === 'audit') return { rows:(await client.query(`SELECT id,action,entity_type "entityType",entity_id "entityId",event_hash "eventHash",created_at "createdAt" FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 25`, [req.auth.org])).rows };
      return { valid:(await client.query('SELECT centinell_verify_audit_chain($1) AS valid', [req.auth.org])).rows[0].valid };
    });
  }
  await audit(req, 'investigation.command_executed', 'investigation_console', null, { command:input.command, argumentCharacters:input.argument.length });
  res.json({ command:input.command, result, executedAt:new Date().toISOString() });
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
  publishKpiEvent(req.auth.org, {
    version: PLATFORM_VERSION,
    type: 'case.created',
    generatedAt: new Date().toISOString(),
    caseNumber: created.caseNumber,
    caseId: created.id
  });
  res.status(201).json({ case: created });
}));

app.get('/api/v1/audit', requireAuth, allow('admin','auditor'), asyncRoute(async (req, res) => {
  const result = await withTenant(req.auth.org, client => client.query('SELECT id,action,entity_type "entityType",entity_id "entityId",metadata,previous_hash "previousHash",event_hash "eventHash",created_at "createdAt" FROM audit_events WHERE organization_id=$1 ORDER BY created_at DESC LIMIT 250', [req.auth.org]));
  res.json({ events: result.rows });
}));

const findingProjection = `SELECT f.id,f.case_id "caseId",f.source,f.status,f.title,f.summary,
  f.artifact_id "artifactId",f.artifact_sha256 "artifactSha256",f.tool_version "toolVersion",
  f.created_at "createdAt",f.verified_at "verifiedAt" FROM forensic_findings f`;
const advisorDirectiveSchema = z.object({ directive: z.string().trim().min(1).max(12000), caseId: z.uuid().nullable().optional() });
const reportDraftSchema = z.object({
  title: z.string().trim().min(3).max(180).default('Centinell AI Forensic Draft'),
  body: z.string().trim().min(1).max(30000),
  caseId: z.uuid().nullable().optional(),
  citedFindingIds: z.array(z.uuid()).max(100).default([])
});

app.get('/api/v1/advisor-directive', requireAuth, asyncRoute(async (req, res) => {
  const caseId = optionalUuid(req.query.caseId);
  const result = await withTenant(req.auth.org, client => client.query(`
    SELECT directive,case_id "caseId",updated_at "updatedAt"
    FROM advisor_directives
    WHERE organization_id=$1 AND user_id=$2 AND (case_id=$3 OR case_id IS NULL)
    ORDER BY (case_id=$3) DESC, updated_at DESC LIMIT 1`, [req.auth.org, req.auth.sub, caseId]));
  const row = result.rows[0];
  res.json({ directive: row ? row.directive : DEFAULT_ADVISOR_DIRECTIVE, isDefault: !row, caseId: row ? row.caseId : caseId, updatedAt: row ? row.updatedAt : null });
}));

app.put('/api/v1/advisor-directive', requireAuth, allow('admin','analyst'), asyncRoute(async (req, res) => {
  const input = advisorDirectiveSchema.parse(req.body);
  const caseId = input.caseId || null;
  const saved = await transaction(async client => {
    await client.query("SELECT set_config('app.current_organization_id',$1,true)", [req.auth.org]);
    await assertCaseTenant(client, req.auth.org, caseId);
    const existing = await client.query(`SELECT id FROM advisor_directives
      WHERE organization_id=$1 AND user_id=$2 AND case_id IS NOT DISTINCT FROM $3::uuid FOR UPDATE`, [req.auth.org, req.auth.sub, caseId]);
    const result = existing.rowCount
      ? await client.query(`UPDATE advisor_directives SET directive=$1,updated_at=now()
          WHERE id=$2 RETURNING id,directive,case_id "caseId",updated_at "updatedAt"`, [input.directive, existing.rows[0].id])
      : await client.query(`INSERT INTO advisor_directives(organization_id,user_id,case_id,directive)
          VALUES($1,$2,$3,$4) RETURNING id,directive,case_id "caseId",updated_at "updatedAt"`, [req.auth.org, req.auth.sub, caseId, input.directive]);
    const row = result.rows[0];
    await audit(req, 'ai.advisor_directive.updated', 'advisor_directive', row.id, {
      caseId: row.caseId,
      directive: input.directive,
      directiveSha256: crypto.createHash('sha256').update(input.directive, 'utf8').digest('hex'),
      directiveLength: input.directive.length
    }, client);
    return row;
  });
  requestAuditAnchor(req.auth.org);
  res.json({ directive: saved.directive, isDefault: false, caseId: saved.caseId, updatedAt: saved.updatedAt });
}));

app.get('/api/v1/forensic-findings', requireAuth, asyncRoute(async (req, res) => {
  const caseId = optionalUuid(req.query.caseId);
  const result = await withTenant(req.auth.org, client => client.query(`${findingProjection}
    WHERE f.organization_id=$1 AND ($2::uuid IS NULL OR f.case_id=$2)
    ORDER BY f.created_at DESC LIMIT 500`, [req.auth.org, caseId]));
  res.json({ findings: result.rows.map(normalizeFinding) });
}));

app.get('/api/v1/reports/drafts', requireAuth, asyncRoute(async (req, res) => {
  const caseId = optionalUuid(req.query.caseId);
  const result = await withTenant(req.auth.org, client => client.query(`
    SELECT d.id,d.title,d.body,d.source,d.status,d.case_id "caseId",c.case_number "caseNumber",
      d.cited_finding_ids "citedFindingIds",d.context_snapshot "contextSnapshot",d.created_at "createdAt"
    FROM report_drafts d LEFT JOIN cases c ON c.id=d.case_id
    WHERE d.organization_id=$1 AND ($2::uuid IS NULL OR d.case_id=$2)
    ORDER BY d.created_at DESC LIMIT 100`, [req.auth.org, caseId]));
  res.json({ drafts: result.rows });
}));

app.post('/api/v1/reports/drafts', requireAuth, allow('admin','analyst','auditor'), asyncRoute(async (req, res) => {
  const input = reportDraftSchema.parse(req.body);
  const caseId = input.caseId || null;
  const citedFindingIds = [...new Set(input.citedFindingIds || [])];
  const draft = await transaction(async client => {
    await client.query("SELECT set_config('app.current_organization_id',$1,true)", [req.auth.org]);
    await assertCaseTenant(client, req.auth.org, caseId);
    const findings = citedFindingIds.length
      ? await client.query(`${findingProjection}
          WHERE f.organization_id=$1 AND f.id=ANY($2::uuid[])
            AND ($3::uuid IS NULL OR f.case_id=$3)`, [req.auth.org, citedFindingIds, caseId])
      : { rows: [] };
    if (findings.rows.length !== citedFindingIds.length) throw httpError(400, 'One or more cited findings are not available in this tenant or case');
    const contextSnapshot = findings.rows.map(normalizeFinding);
    const inserted = await client.query(`INSERT INTO report_drafts
      (organization_id,case_id,created_by,title,body,status,cited_finding_ids,context_snapshot)
      VALUES($1,$2,$3,$4,$5,'pending_verification',$6,$7)
      RETURNING id,title,body,source,status,case_id "caseId",cited_finding_ids "citedFindingIds",
        context_snapshot "contextSnapshot",created_at "createdAt"`,
      [req.auth.org, caseId, req.auth.sub, input.title, input.body, citedFindingIds, JSON.stringify(contextSnapshot)]);
    const row = inserted.rows[0];
    if (caseId) {
      const caseResult = await client.query('SELECT case_number "caseNumber" FROM cases WHERE id=$1 AND organization_id=$2', [caseId, req.auth.org]);
      row.caseNumber = caseResult.rows[0] ? caseResult.rows[0].caseNumber : null;
    } else row.caseNumber = null;
    await audit(req, 'ai.report_draft.created', 'report_draft', row.id, {
      source: 'centinell_ai',
      status: 'pending_verification',
      caseId,
      citedFindingIds,
      bodySha256: crypto.createHash('sha256').update(input.body, 'utf8').digest('hex')
    }, client);
    return row;
  });
  requestAuditAnchor(req.auth.org);
  res.status(201).json({ draft });
}));

const aiSchema = z.object({ message: z.string().trim().min(2).max(6000) });
app.post('/api/v1/ai/chat', requireAuth, asyncRoute(async (req, res) => {
  const { message } = aiSchema.parse(req.body);
  if (!process.env.ANTHROPIC_API_KEY) return res.status(503).json({ title: 'AI service is not configured', status: 503 });
  const response = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'content-type':'application/json', 'x-api-key':process.env.ANTHROPIC_API_KEY, 'anthropic-version':'2023-06-01' }, body: JSON.stringify({ model:CENTINELL_AI_MODEL, max_tokens:1200, system:DEFAULT_ADVISOR_DIRECTIVE, messages:[{ role:'user', content:message }] }) });
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

const frontendPath = path.join(__dirname, '..', '..');
const publicStatic = express.static(frontendPath, { extensions: ['html'], maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 });
const publicRootFiles = new Set(['/','/index.html','/technical-analysis','/technical-analysis.html','/app.js','/card-navigation.js','/enterprise-dashboard.js','/forensic-advisor.js','/forensic-copilot.js','/interactive-workbench.js']);
const publicDirectories = /^(?:\/assets|\/core|\/router|\/services|\/state|\/ui|\/utils)\/[A-Za-z0-9._/-]+$/;
const isPublicPath = pathname => publicRootFiles.has(pathname) || (publicDirectories.test(pathname) && !pathname.split('/').includes('..') && !/%2e/i.test(pathname));
app.use((req, res, next) => isPublicPath(req.path) ? publicStatic(req, res, next) : next());
app.get('/{*splat}', (_req, res) => res.sendFile(path.join(frontendPath, 'index.html')));
app.use((error, _req, res, _next) => {
  if (error instanceof z.ZodError) return res.status(400).json({ title: 'Validation failed', status: 400, errors: error.issues.map(i => ({ path: i.path.join('.'), message: i.message })) });
  if (error.status) return res.status(error.status).json({ type:'about:blank', title:error.message, status:error.status });
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
