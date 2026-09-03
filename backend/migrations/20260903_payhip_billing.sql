CREATE TABLE IF NOT EXISTS payhip_entitlements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider_event_id text NOT NULL UNIQUE,
  purchase_id text,
  subscription_id text,
  buyer_email text NOT NULL,
  product_key text NOT NULL,
  plan_name text,
  status text NOT NULL CHECK (status IN ('active','refunded','canceled')),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS payhip_entitlements_purchase_uq
  ON payhip_entitlements (purchase_id) WHERE purchase_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS payhip_entitlements_subscription_uq
  ON payhip_entitlements (subscription_id) WHERE subscription_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS payhip_entitlements_email_status_idx
  ON payhip_entitlements (lower(buyer_email), status, updated_at DESC);

CREATE TABLE IF NOT EXISTS organization_billing (
  organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider = 'payhip'),
  entitlement_id uuid NOT NULL REFERENCES payhip_entitlements(id),
  status text NOT NULL CHECK (status IN ('active','refunded','canceled')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
