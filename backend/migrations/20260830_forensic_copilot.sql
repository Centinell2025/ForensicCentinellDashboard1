-- Centinell Forensics Enterprise: forensic copilot persistence.
-- This migration is idempotent and is executed after the core tenant schema.

CREATE TABLE IF NOT EXISTS forensic_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  case_id uuid REFERENCES cases(id) ON DELETE CASCADE,
  source text NOT NULL CHECK (source IN ('hayabusa','oletools','pdfid','exiftool','email')),
  status text NOT NULL DEFAULT 'pending_verification' CHECK (status IN ('pending_verification','verified')),
  title text NOT NULL,
  summary text NOT NULL DEFAULT '',
  artifact_id text,
  artifact_sha256 text,
  tool_version text,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  verified_by uuid REFERENCES users(id) ON DELETE SET NULL,
  verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS forensic_findings_tenant_case_idx
  ON forensic_findings (organization_id, case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS forensic_findings_tenant_status_idx
  ON forensic_findings (organization_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS advisor_directives (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  case_id uuid REFERENCES cases(id) ON DELETE CASCADE,
  directive text NOT NULL CHECK (char_length(directive) BETWEEN 1 AND 12000),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS advisor_directives_workspace_uq
  ON advisor_directives (organization_id, user_id)
  WHERE case_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS advisor_directives_case_uq
  ON advisor_directives (organization_id, user_id, case_id)
  WHERE case_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS report_drafts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  case_id uuid REFERENCES cases(id) ON DELETE SET NULL,
  created_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title text NOT NULL,
  body text NOT NULL,
  source text NOT NULL DEFAULT 'centinell_ai' CHECK (source = 'centinell_ai'),
  status text NOT NULL DEFAULT 'pending_verification' CHECK (status IN ('pending_verification','verified','rejected')),
  cited_finding_ids uuid[] NOT NULL DEFAULT '{}'::uuid[],
  context_snapshot jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS report_drafts_tenant_created_idx
  ON report_drafts (organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS report_drafts_tenant_case_idx
  ON report_drafts (organization_id, case_id, created_at DESC);

ALTER TABLE forensic_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE forensic_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE advisor_directives ENABLE ROW LEVEL SECURITY;
ALTER TABLE advisor_directives FORCE ROW LEVEL SECURITY;
ALTER TABLE report_drafts ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_drafts FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS forensic_findings_tenant_isolation ON forensic_findings;
CREATE POLICY forensic_findings_tenant_isolation ON forensic_findings
  USING (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid);

DROP POLICY IF EXISTS advisor_directives_tenant_isolation ON advisor_directives;
CREATE POLICY advisor_directives_tenant_isolation ON advisor_directives
  USING (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid);

DROP POLICY IF EXISTS report_drafts_tenant_isolation ON report_drafts;
CREATE POLICY report_drafts_tenant_isolation ON report_drafts
  USING (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid)
  WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id', true), '')::uuid);
