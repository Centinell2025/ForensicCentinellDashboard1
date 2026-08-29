const crypto = require('crypto');

async function emitSecurityEvent(event) {
  const payload = JSON.stringify({ ...event, emittedAt: new Date().toISOString() });
  console.log(payload);
  if (!process.env.SIEM_WEBHOOK_URL || !process.env.SIEM_WEBHOOK_SECRET) return;
  const timestamp = Date.now().toString();
  const signature = crypto.createHmac('sha256', process.env.SIEM_WEBHOOK_SECRET).update(`${timestamp}.${payload}`).digest('hex');
  const response = await fetch(process.env.SIEM_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'content-type':'application/json', 'x-centinell-timestamp':timestamp, 'x-centinell-signature':`sha256=${signature}` },
    body: payload,
    signal: AbortSignal.timeout(5000)
  });
  if (!response.ok) throw new Error(`SIEM export failed with ${response.status}`);
}

module.exports = { emitSecurityEvent };
