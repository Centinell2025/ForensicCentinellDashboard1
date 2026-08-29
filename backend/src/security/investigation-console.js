const net = require('node:net');
const crypto = require('node:crypto');

const COMMANDS = Object.freeze(['help','cases','evidence','audit','chain-verify','ioc','packet-summary']);

function classifyIndicator(value) {
  const input = String(value || '').trim().toLowerCase();
  if (net.isIP(input)) return { type: 'ip', value: input, vtPath: `ip_addresses/${input}` };
  if (/^[a-f0-9]{64}$/.test(input)) return { type: 'sha256', value: input, vtPath: `files/${input}` };
  if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(input)) return { type: 'domain', value: input, vtPath: `domains/${input}` };
  throw new Error('IOC must be a valid IP address, domain, or SHA-256 hash');
}

async function virusTotalLookup(indicator) {
  if (!process.env.VIRUSTOTAL_API_KEY) return { configured: false };
  const response = await fetch(`https://www.virustotal.com/api/v3/${indicator.vtPath}`, {
    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, accept: 'application/json' },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) return { configured: true, status: response.status, available: false };
  const body = await response.json();
  const attributes = body.data && body.data.attributes || {};
  return { configured: true, available: true, reputation: attributes.reputation ?? null,
    lastAnalysisStats: attributes.last_analysis_stats || null, lastAnalysisDate: attributes.last_analysis_date || null };
}

async function taxiiLookup(indicator) {
  if (!process.env.TAXII_OBJECTS_URL || !process.env.TAXII_TOKEN) return { configured: false };
  const response = await fetch(`${process.env.TAXII_OBJECTS_URL}?match[type]=indicator&limit=20`, {
    headers: { authorization: `Bearer ${process.env.TAXII_TOKEN}`, accept: 'application/taxii+json;version=2.1' },
    signal: AbortSignal.timeout(8000)
  });
  if (!response.ok) return { configured: true, status: response.status, available: false };
  const body = await response.json();
  const objects = (body.objects || []).filter(item => JSON.stringify(item).toLowerCase().includes(indicator.value)).slice(0, 10);
  return { configured: true, available: true, matches: objects.map(item => ({ id:item.id, type:item.type, created:item.created, modified:item.modified, pattern:item.pattern, labels:item.labels || [] })) };
}

function packetSummary(raw) {
  let packets;
  try { packets = JSON.parse(raw); } catch (_) { throw new Error('packet-summary expects a JSON array of packet metadata'); }
  if (!Array.isArray(packets) || packets.length > 500) throw new Error('Provide between 0 and 500 packet metadata records');
  const protocols = {}, sources = {}, destinations = {}; let bytes = 0;
  packets.forEach(packet => {
    const protocol = String(packet.protocol || 'unknown').toUpperCase().slice(0, 20);
    const source = String(packet.source || 'unknown').slice(0, 100);
    const destination = String(packet.destination || 'unknown').slice(0, 100);
    const length = Math.max(0, Math.min(Number(packet.length) || 0, 10_000_000));
    protocols[protocol] = (protocols[protocol] || 0) + 1; sources[source] = (sources[source] || 0) + 1;
    destinations[destination] = (destinations[destination] || 0) + 1; bytes += length;
  });
  const top = object => Object.entries(object).sort((a,b) => b[1]-a[1]).slice(0,10).map(([value,count]) => ({ value,count }));
  return { packetCount:packets.length, totalBytes:bytes, protocols:top(protocols), topSources:top(sources), topDestinations:top(destinations), sha256:crypto.createHash('sha256').update(JSON.stringify(packets)).digest('hex') };
}

module.exports = { COMMANDS, classifyIndicator, virusTotalLookup, taxiiLookup, packetSummary };
