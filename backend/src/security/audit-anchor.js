const crypto = require('crypto');
const { query, withTenant } = require('../db');

async function anchorTenant(organizationId) {
  const url = process.env.AUDIT_ANCHOR_URL, secret = process.env.AUDIT_ANCHOR_SECRET;
  if (!url || !secret) return { skipped:true };
  const head = await withTenant(organizationId, client => client.query('SELECT id,event_hash FROM audit_events ORDER BY id DESC LIMIT 1'));
  if (!head.rows[0]) return { skipped:true };
  const payload = JSON.stringify({ organizationId, lastEventId:head.rows[0].id, chainHash:head.rows[0].event_hash, anchoredAt:new Date().toISOString() });
  const signature = crypto.createHmac('sha256',secret).update(payload).digest('hex');
  const response = await fetch(url,{ method:'POST',headers:{'content-type':'application/json','x-centinell-signature':`sha256=${signature}`,'idempotency-key':`${organizationId}:${head.rows[0].id}`},body:payload,signal:AbortSignal.timeout(8000) });
  if (!response.ok) throw new Error(`Audit anchor failed with ${response.status}`);
  const receipt = await response.json();
  await withTenant(organizationId, client => client.query('INSERT INTO audit_anchors(organization_id,last_event_id,chain_hash,external_provider,external_reference) VALUES($1,$2,$3,$4,$5)',[organizationId,head.rows[0].id,head.rows[0].event_hash,receipt.provider || 'external',receipt.reference]));
  return receipt;
}

async function anchorAllTenants() {
  const orgs = await query('SELECT id FROM organizations');
  return Promise.allSettled(orgs.rows.map(row => anchorTenant(row.id)));
}
module.exports = { anchorTenant, anchorAllTenants };
