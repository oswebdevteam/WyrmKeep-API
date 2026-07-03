-- tenants
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    api_key_hash TEXT NOT NULL,
    cognee_dataset_private TEXT NOT NULL,   -- wyrmkeep:{id}:private
    cognee_dataset_session TEXT NOT NULL,   -- wyrmkeep:{id}:session
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
