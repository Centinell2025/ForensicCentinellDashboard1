const crypto = require('crypto');

async function emitSecurityEvent(event) {
  const eventId = crypto.randomUUID();
  const payload = JSON.stringify({ eventId, ...event, emittedAt: new Date().toISOString() });
  console.log(payload);
  if (!process.env.SIEM_WEBHOOK_URL || !process.env.SIEM_WEBHOOK_SECRET) return;
  const timestamp = Date.now().toString();
  const signature = crypto.createHmac('sha256', process.env.SIEM_WEBHOOK_SECRET).update(`${timestamp}.${payload}`).digest('hex');
  let lastError;
  for (let attempt=1;attempt<=3;attempt++) {
    try {
      const response = await fetch(process.env.SIEM_WEBHOOK_URL, {
        method:'POST', headers:{'content-type':'application/json','x-centinell-timestamp':timestamp,'x-centinell-signature':`sha256=${signature}`,'idempotency-key':eventId}, body:payload, signal:AbortSignal.timeout(5000)
      });
      if (response.ok) return;
      lastError = new Error(`SIEM export failed with ${response.status}`);
    } catch (error) { lastError = error; }
    await new Promise(resolve => setTimeout(resolve, attempt * 250));
  }
  throw lastError;
}

module.exports = { emitSecurityEvent };
