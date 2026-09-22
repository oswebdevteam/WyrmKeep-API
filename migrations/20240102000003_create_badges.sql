CREATE TABLE IF NOT EXISTS audit_badges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_id UUID NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    contract_name TEXT NOT NULL,
    certificate_hash TEXT NOT NULL UNIQUE,
    grade TEXT NOT NULL,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    high_severity_count INTEGER NOT NULL DEFAULT 0,
    chain TEXT NOT NULL DEFAULT 'solidity',
    issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata_json JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_badges_tenant ON audit_badges(tenant_id);
CREATE INDEX IF NOT EXISTS idx_badges_cert ON audit_badges(certificate_hash);
