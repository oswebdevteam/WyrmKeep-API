-- contracts
CREATE TABLE contracts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source_hash TEXT NOT NULL,
    source_code TEXT NOT NULL,
    language TEXT NOT NULL DEFAULT 'solidity',
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
