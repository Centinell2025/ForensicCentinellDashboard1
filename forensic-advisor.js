/* Shared forensic-advisor contract used by the browser and the Node API. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CentinellForensicAdvisor = factory();
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var DEFAULT_ADVISOR_DIRECTIVE = "Eres el asesor forense de Centinell Forensics Enterprise. Asistes a analistas DFIR. REGLAS INQUEBRANTABLES: (1) Nunca inventes hechos, hashes, IOCs, rutas ni artefactos; si no está en la evidencia provista, dilo explícitamente. (2) Cada afirmación fáctica debe citar el artefacto y la herramienta determinista de origen (p. ej. Hayabusa, oletools, pdfid, ExifTool). (3) Solo trata como confirmados los hallazgos en estado 'verified'; marca todo lo 'pending_verification' como no verificado. (4) No eres fuente de verdad: propones hipótesis y redactas borradores que SIEMPRE requieren revisión y sign-off humano antes de entrar a un reporte. (5) Mantén cadena de custodia e integridad probatoria como prioridad. Responde en el idioma del analista.";
  var CENTINELL_AI_MODEL = 'claude-sonnet-4-20250514';
  var SOURCES = Object.freeze(['hayabusa', 'oletools', 'pdfid', 'exiftool', 'email']);
  var STATUSES = Object.freeze(['pending_verification', 'verified']);

  function text(value, maxLength) {
    var result = String(value == null ? '' : value).trim();
    return maxLength ? result.slice(0, maxLength) : result;
  }

  function normalizedValue(value, allowed, fallback) {
    var candidate = text(value, 80).toLowerCase();
    return allowed.indexOf(candidate) >= 0 ? candidate : fallback;
  }

  function normalizeFinding(finding) {
    finding = finding || {};
    return {
      id: text(finding.id, 128),
      caseId: text(finding.caseId || finding.case_id, 128) || null,
      source: normalizedValue(finding.source, SOURCES, 'email'),
      status: normalizedValue(finding.status, STATUSES, 'pending_verification'),
      title: text(finding.title, 240) || 'Untitled forensic finding',
      summary: text(finding.summary, 2000),
      artifactId: text(finding.artifactId || finding.artifact_id, 240),
      artifactSha256: text(finding.artifactSha256 || finding.artifact_sha256, 128),
      toolVersion: text(finding.toolVersion || finding.tool_version, 160),
      createdAt: text(finding.createdAt || finding.created_at, 80),
      verifiedAt: text(finding.verifiedAt || finding.verified_at, 80) || null
    };
  }

  function buildEvidenceContext(findings) {
    var normalized = (Array.isArray(findings) ? findings : []).map(normalizeFinding);
    return [
      'FORENSIC FINDINGS CONTEXT (tenant-authorized and normalized):',
      'Verified findings are confirmed within the evidence store. Pending findings are NOT confirmed and must be labeled as unverified.',
      JSON.stringify({
        verifiedFindings: normalized.filter(function (finding) { return finding.status === 'verified'; }),
        pendingVerification: normalized.filter(function (finding) { return finding.status === 'pending_verification'; })
      }, null, 2)
    ].join('\n');
  }

  function buildAdvisorUserMessage(question, findings) {
    var prompt = text(question, 12000);
    var selected = Array.isArray(findings) ? findings : [];
    return prompt + '\n\n' + (selected.length ? buildEvidenceContext(selected) : 'No tenant-authorized forensic findings were attached to this request. Do not infer or invent evidence.');
  }

  return Object.freeze({
    DEFAULT_ADVISOR_DIRECTIVE: DEFAULT_ADVISOR_DIRECTIVE,
    CENTINELL_AI_MODEL: CENTINELL_AI_MODEL,
    SOURCES: SOURCES,
    STATUSES: STATUSES,
    normalizeFinding: normalizeFinding,
    buildEvidenceContext: buildEvidenceContext,
    buildAdvisorUserMessage: buildAdvisorUserMessage
  });
}));
