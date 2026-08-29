const counters = new Map();
const startedAt = Date.now();
function increment(name, labels = {}) {
  const key = `${name}|${JSON.stringify(labels)}`;
  const item = counters.get(key) || { name, labels, value:0 };
  item.value += 1; counters.set(key, item);
}
function render() {
  const lines = [`# HELP centinell_uptime_seconds Process uptime`, `# TYPE centinell_uptime_seconds gauge`, `centinell_uptime_seconds ${Math.floor((Date.now()-startedAt)/1000)}`];
  for (const item of counters.values()) {
    const labels = Object.entries(item.labels).map(([k,v]) => `${k}="${String(v).replace(/["\\]/g,'\\$&')}"`).join(',');
    lines.push(`${item.name}${labels ? `{${labels}}` : ''} ${item.value}`);
  }
  return `${lines.join('\n')}\n`;
}
module.exports = { increment, render };
