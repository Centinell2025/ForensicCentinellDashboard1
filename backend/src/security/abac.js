function matchPattern(pattern, action) {
  if (pattern === '*') return true;
  if (pattern.endsWith('*')) return action.startsWith(pattern.slice(0, -1));
  return pattern === action;
}

function conditionMatches(conditions, context) {
  if (conditions.roles && !conditions.roles.includes(context.role)) return false;
  if (conditions.countries && !conditions.countries.includes(context.country)) return false;
  if (conditions.deviceTrusted === true && context.deviceTrusted !== true) return false;
  if (conditions.mfaRequired === true && context.mfaVerified !== true) return false;
  if (conditions.hoursUtc) {
    const hour = new Date(context.now || Date.now()).getUTCHours();
    const [start, end] = conditions.hoursUtc;
    if (start <= end ? (hour < start || hour >= end) : (hour < start && hour >= end)) return false;
  }
  return true;
}

function authorize(policies, action, context) {
  const applicable = policies.filter(p => p.enabled !== false && matchPattern(p.action_pattern || p.actionPattern, action) && conditionMatches(p.conditions || {}, context));
  if (applicable.some(p => p.effect === 'deny')) return false;
  return applicable.some(p => p.effect === 'allow');
}

module.exports = { authorize, conditionMatches, matchPattern };
