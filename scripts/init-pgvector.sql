-- Initialize pgvector extension and tenant partitioning
CREATE EXTENSION IF NOT EXISTS vector;

-- Document Chunks Table with Physical Tenant Partitioning
CREATE TABLE IF NOT EXISTS document_chunks (
    id UUID NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    document_id VARCHAR(128) NOT NULL,
    department VARCHAR(64) NOT NULL,
    chunk_index INT NOT NULL,
    content TEXT NOT NULL,
    embedding vector(1536) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
) PARTITION BY LIST (tenant_id);

-- Default Tenant Partitions
CREATE TABLE IF NOT EXISTS document_chunks_tenant_a 
    PARTITION OF document_chunks FOR VALUES IN ('tenant-alpha');

CREATE TABLE IF NOT EXISTS document_chunks_tenant_b 
    PARTITION OF document_chunks FOR VALUES IN ('tenant-beta');

CREATE TABLE IF NOT EXISTS document_chunks_default 
    PARTITION OF document_chunks DEFAULT;

-- HNSW Cosine Distance Index on each partition
CREATE INDEX IF NOT EXISTS idx_chunks_hnsw_alpha 
    ON document_chunks_tenant_a USING hnsw (embedding vector_cosine_ops) 
    WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS idx_chunks_hnsw_beta 
    ON document_chunks_tenant_b USING hnsw (embedding vector_cosine_ops) 
    WITH (m = 16, ef_construction = 64);
