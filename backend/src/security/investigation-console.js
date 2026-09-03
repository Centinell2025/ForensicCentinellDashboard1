const net = require('node:net');
const crypto = require('node:crypto');

const COMMANDS = Object.freeze(['help','cases','evidence','audit','chain-verify','ioc','packet-summary','network-summary','url-analysis','email-headers','timeline-summary']);

function urlId(value) { return Buffer.from(value, 'utf8').toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
function analyzeUrl(value) {
  const raw = String(value || '').trim(); let parsed;
  try { parsed = new URL(raw); } catch (_) { throw new Error('URL must be a valid absolute HTTP or HTTPS URL'); }
  if (!['http:','https:'].includes(parsed.protocol)) throw new Error('Only HTTP and HTTPS URLs may be analyzed');
  const host = parsed.hostname.toLowerCase(), signals = [];
  if (parsed.username || parsed.password) signals.push('embedded-credentials');
  if (host.includes('xn--')) signals.push('punycode-hostname');
  if (parsed.port && !['80','443'].includes(parsed.port)) signals.push('nonstandard-port');
  if (host.split('.').length > 4) signals.push('deep-subdomain');
  return { type:'url', value:parsed.href, host, protocol:parsed.protocol, port:parsed.port || null, path:parsed.pathname,
    queryPresent:Boolean(parsed.search), suspiciousSignals:signals, vtPath:`urls/${urlId(parsed.href)}` };
}
function classifyIndicator(value) {
  const raw = String(value || '').trim(), input = raw.toLowerCase();
  if (/^https?:\/\//i.test(raw)) return analyzeUrl(raw);
  if (net.isIP(input)) return { type: 'ip', value: input, vtPath: `ip_addresses/${input}` };
  if (/^[a-f0-9]{64}$/.test(input)) return { type: 'sha256', value: input, vtPath: `files/${input}` };
  if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(input)) return { type: 'domain', value: input, vtPath: `domains/${input}` };
  throw new Error('IOC must be a valid IP address, domain, URL, or SHA-256 hash');
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

function networkSummary(raw) {
  const base = packetSummary(raw), packets = JSON.parse(raw), conversations = new Map(); let privateSourceCount = 0;
  packets.forEach(packet => { const source=String(packet.source || 'unknown').slice(0,100), destination=String(packet.destination || 'unknown').slice(0,100), protocol=String(packet.protocol || 'unknown').toUpperCase().slice(0,20), key=source+' → '+destination+' · '+protocol; conversations.set(key,(conversations.get(key)||0)+1); if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(source)) privateSourceCount += 1; });
  return { ...base, uniqueConversations:conversations.size, privateSourceCount, topConversations:[...conversations.entries()].sort((a,b)=>b[1]-a[1]).slice(0,10).map(([value,count])=>({value,count})) };
}
function emailHeaderSummary(raw) {
  const headerText=String(raw || '').split(/\r?\n\r?\n/,1)[0]; if(!headerText || headerText.length>32768)throw new Error('Provide email headers up to 32 KB');
  const headers={}, unfolded=headerText.replace(/\r?\n[ \t]+/g,' ');
  unfolded.split(/\r?\n/).forEach(line=>{const m=line.match(/^([A-Za-z0-9-]{1,78}):\s*(.*)$/);if(m){const key=m[1].toLowerCase();(headers[key]||=[]).push(m[2].trim());}});
  const first=key=>headers[key]?.[0]||null, domain=value=>(String(value||'').match(/@([^>\s]+)/)||[])[1]?.toLowerCase()||null;
  const fromDomain=domain(first('from')), replyToDomain=domain(first('reply-to')), returnPathDomain=domain(first('return-path')), signals=[];
  if(!first('message-id'))signals.push('missing-message-id'); if(!headers.received?.length)signals.push('missing-received-chain');
  if(replyToDomain&&fromDomain&&replyToDomain!==fromDomain)signals.push('reply-to-domain-mismatch'); if(returnPathDomain&&fromDomain&&returnPathDomain!==fromDomain)signals.push('return-path-domain-mismatch');
  const parsedDate=Date.parse(first('date')||'');
  return {from:first('from'),to:first('to'),subject:first('subject'),messageId:first('message-id'),receivedHops:(headers.received||[]).length,fromDomain,replyToDomain,returnPathDomain,dateUtc:Number.isNaN(parsedDate)?null:new Date(parsedDate).toISOString(),suspiciousSignals:signals,sha256:crypto.createHash('sha256').update(headerText).digest('hex')};
}
function timelineSummary(raw) {
  let events; try{events=JSON.parse(raw);}catch(_){throw new Error('timeline-summary expects a JSON array of events');}
  if(!Array.isArray(events)||events.length>1000)throw new Error('Provide between 0 and 1000 timeline events');
  const normalized=events.map((event,index)=>{const timestamp=new Date(event.timestamp||event.time||'');if(Number.isNaN(timestamp.getTime()))throw new Error('Each timeline event needs a valid timestamp');return {timestamp:timestamp.toISOString(),type:String(event.type||'event').slice(0,80),source:String(event.source||'unknown').slice(0,120),description:String(event.description||'').slice(0,1000),index};}).sort((a,b)=>a.timestamp.localeCompare(b.timestamp)||a.index-b.index);
  return {eventCount:normalized.length,earliest:normalized[0]?.timestamp||null,latest:normalized.at(-1)?.timestamp||null,events:normalized.map(({index,...event})=>event),sha256:crypto.createHash('sha256').update(JSON.stringify(normalized)).digest('hex')};
}

module.exports = { COMMANDS, classifyIndicator, analyzeUrl, virusTotalLookup, taxiiLookup, packetSummary, networkSummary, emailHeaderSummary, timelineSummary };
