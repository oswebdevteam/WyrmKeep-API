-- audits
CREATE TABLE IF NOT EXISTS audits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    contract_id UUID NOT NULL REFERENCES contracts(id),
    status TEXT NOT NULL DEFAULT 'queued',  -- queued|running|complete|failed
    slither_raw JSONB,
    abstract_pattern JSONB,
    memory_matches JSONB,
    report JSONB,
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_audits_tenant_status ON audits(tenant_id, status);
