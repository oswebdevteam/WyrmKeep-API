# WyrmKeep API

<div align="center">

**A Smart Contract Audit Platform with Memory-Augmented Pattern Recognition**

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Built with Axum](https://img.shields.io/badge/built%20with-Axum-green.svg)](https://github.com/tokio-rs/axum)

</div>


---

##  Overview

WyrmKeep is a next-generation smart contract auditing platform that combines traditional static analysis with memory-augmented pattern recognition. It leverages historical vulnerability data to identify security issues in smart contracts with unprecedented accuracy.

### Key Capabilities

- **Automated Vulnerability Detection**: Integrates with Slither for comprehensive static analysis
- **Pattern Extraction**: Converts vulnerability findings into abstract graph patterns
- **Memory-Augmented Recall**: Uses Cognee for semantic search across historical vulnerabilities
- **Real-time Streaming**: Server-Sent Events (SSE) for live audit progress updates
- **Multi-tenant Architecture**: Secure isolation with JWT and API key authentication
- **Production-Ready**: Cursor-based pagination, CORS, compression, timeouts, and request tracing

---

##  Features

###  Smart Contract Analysis

- **Slither Integration**: Comprehensive vulnerability scanning
- **Pattern Abstraction**: Automated extraction of vulnerability patterns into graph structures
- **Historical Context**: Matches current vulnerabilities against known exploit patterns
- **Causal Chain Analysis**: Tracks the flow of vulnerable operations

###  Security & Multi-tenancy

- **JWT Authentication**: Secure token-based auth
- **API Key Support**: Alternative authentication for machine-to-machine
- **Tenant Isolation**: Complete data segregation per tenant
- **Role-Based Access**: Admin and tenant-level permissions

###  Advanced Features

- **Real-time Streaming**: SSE for audit progress updates
- **Dataset Management**: Separate shared, private, and session memory datasets
- **Pagination**: Efficient cursor-based pagination for all list endpoints
- **GDPR Compliance**: Complete memory cleanup capabilities

###  Production-Ready

- **Request Tracing**: Unique request IDs for debugging
- **Compression**: Brotli compression for all responses
- **CORS Support**: Configurable cross-origin resource sharing
- **Health Checks**: Standard `/health` endpoint
- **Database Migrations**: Automatic schema management

---

##  Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    API Layer (Axum)                     │
│  ┌──────────────┬──────────────┬─────────────────────┐ │
│  │  Auth        │  Routes      │  Middleware         │ │
│  │  Middleware  │  Handlers    │  (CORS, Trace, etc) │ │
│  └──────────────┴──────────────┴─────────────────────┘ │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                   Business Logic Layer                  │
│  ┌──────────────────────┬──────────────────────────┐   │
│  │  Audit Pipeline      │  Pattern Abstractor      │   │
│  │  - Slither Analysis  │  - Graph Extraction      │   │
│  │  - Memory Ops        │  - Edge Inference        │   │
│  │  - Report Generation │  - Anonymization         │   │
│  └──────────────────────┴──────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                            │
          ┌─────────────────┼─────────────────┐
          ▼                 ▼                 ▼
┌─────────────────┐  ┌──────────────┐  ┌──────────────┐
│   PostgreSQL    │  │   Cognee     │  │   Sidecar    │
│   (Supabase)    │  │   Memory     │  │   Service    │
│                 │  │   Store      │  │   (Slither)  │
│  - Tenants      │  │              │  │              │
│  - Contracts    │  │  - Patterns  │  │  - Analysis  │
│  - Audits       │  │  - Recall    │  │  - Detection │
│  - Findings     │  │  - Datasets  │  │              │
└─────────────────┘  └──────────────┘  └──────────────┘
```

### Technology Stack

- **Framework**: Axum 0.7 (Tokio-based async web framework)
- **Database**: PostgreSQL 14+ (via Supabase)
- **ORM**: SQLx (compile-time verified queries)
- **Authentication**: JWT + Argon2 password hashing
- **Memory System**: Cognee (graph-based knowledge storage)
- **Analysis Engine**: Slither (via sidecar service)
- **Middleware**: Tower HTTP (compression, CORS, tracing, timeouts)

---

##  Quick Start

### Prerequisites

- Rust 1.75+
- PostgreSQL 14+ (or Supabase account)
- CMake, Ninja, Protocol Buffers compiler (for dependencies)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/wyrmkeep.git
   cd wyrmkeep
   ```

2. **Set up environment:**
   ```bash
   cp .env.example .env
   # Edit .env with your database URL and API keys
   ```

3. **Configure Supabase (or local PostgreSQL):**
   
   Get your connection string from Supabase:
   - Dashboard → Settings → Database → Connection String (URI)
   - Add to `.env` as `DATABASE_URL`

4. **Run migrations (automatic on startup):**
   ```bash
   cargo run
   ```

5. **Server starts on:**
   ```
   http://localhost:8000
   ```

### Verify Installation

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "version": "0.1.0",
  "timestamp": "2026-07-03T12:00:00Z"
}
```

---

##  API Documentation

### Base URL

```
http://localhost:8000/v1
```

All endpoints return JSON and include a `request_id` field for tracing.

### Authentication

Two authentication methods are supported:

**1. JWT Bearer Token:**
```bash
Authorization: Bearer <jwt_token>
```

**2. API Key:**
```bash
X-API-Key: <tenant_id>.<api_key>
```

---

##  Authentication Endpoints

### Health Check

```http
GET /health
```

No authentication required.

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0",
  "timestamp": "2026-07-03T12:00:00.000Z"
}
```

---

##  Tenant Management

### Create Tenant

```http
POST /v1/tenants
```

**Admin only.** Creates a new tenant account.

**Request Body:**
```json
{
  "name": "Acme Security",
  "raw_api_key": "your-secret-api-key"
}
```

**Response:**
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Security",
    "api_key_hash": "$argon2id$v=19$m=19456,t=2,p=1$...",
    "cognee_dataset_private": "wyrmkeep:550e8400-...:private",
    "cognee_dataset_session": "wyrmkeep:550e8400-...:session",
    "created_at": "2026-07-03T12:00:00.000Z"
  },
  "api_key": "your-secret-api-key",
  "session_token": "eyJhbGciOiJIUzI1NiIs...",
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Get Current Tenant

```http
GET /v1/tenants/me
```

Returns the authenticated tenant's information.

**Response:**
```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Acme Security",
    "api_key_hash": "$argon2id$...",
    "cognee_dataset_private": "wyrmkeep:550e8400-...:private",
    "cognee_dataset_session": "wyrmkeep:550e8400-...:session",
    "created_at": "2026-07-03T12:00:00.000Z"
  },
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

##  Contract Management

### Upload Contract

```http
POST /v1/contracts
Content-Type: multipart/form-data
```

Upload a smart contract for auditing.

**Form Fields:**
- `name` (required): Contract name
- `file` or `source_code` (required): Contract source code
- `language` (optional): Programming language (default: "solidity")

**Example (curl):**
```bash
curl -X POST http://localhost:8000/v1/contracts \
  -H "Authorization: Bearer $TOKEN" \
  -F "name=MyToken" \
  -F "file=@contracts/MyToken.sol" \
  -F "language=solidity"
```

**Response:**
```json
{
  "data": {
    "id": "650e8400-e29b-41d4-a716-446655440000",
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "MyToken",
    "source_hash": "5d41402abc4b2a76b9719d911017c592",
    "source_code": "pragma solidity ^0.8.0...",
    "language": "solidity",
    "uploaded_at": "2026-07-03T12:00:00.000Z"
  },
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### List Contracts

```http
GET /v1/contracts?limit=20&after=<cursor>
```

List uploaded contracts with cursor-based pagination.

**Query Parameters:**
- `limit` (optional): Number of results (default: 20, max: 100)
- `after` (optional): Cursor UUID for pagination

**Response:**
```json
{
  "data": [
    {
      "id": "650e8400-e29b-41d4-a716-446655440000",
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "MyToken",
      "source_hash": "5d41402abc4b2a76b9719d911017c592",
      "source_code": "pragma solidity ^0.8.0...",
      "language": "solidity",
      "uploaded_at": "2026-07-03T12:00:00.000Z"
    }
  ],
  "next_cursor": "650e8400-e29b-41d4-a716-446655440000",
  "has_more": true,
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Get Contract

```http
GET /v1/contracts/:id
```

Retrieve a specific contract by ID.

**Response:**
```json
{
  "data": {
    "id": "650e8400-e29b-41d4-a716-446655440000",
    "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "MyToken",
    "source_hash": "5d41402abc4b2a76b9719d911017c592",
    "source_code": "pragma solidity ^0.8.0...",
    "language": "solidity",
    "uploaded_at": "2026-07-03T12:00:00.000Z"
  },
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

##  Audit Management

### Create Audit

```http
POST /v1/audits
```

Start a new security audit for a contract.

**Request Body:**
```json
{
  "contract_id": "650e8400-e29b-41d4-a716-446655440000",
  "vuln_class_tags": ["reentrancy", "access-control", "solidity"]
}
```

**Response:**
```json
{
  "audit_id": "750e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Stream Audit Progress

```http
GET /v1/audits/:id/stream
Content-Type: text/event-stream
```

Real-time Server-Sent Events stream for audit progress.

**Event Types:**

**Status Update:**
```json
{
  "type": "status_update",
  "stage": "starting",
  "message": "Audit initiated"
}
```

**Slither Complete:**
```json
{
  "type": "slither_complete",
  "finding_count": 5
}
```

**Pattern Extracted:**
```json
{
  "type": "pattern_extracted",
  "node_count": 12,
  "edge_count": 8
}
```

**Memory Ingested:**
```json
{
  "type": "memory_ingested",
  "dataset": "wyrmkeep:shared:patterns"
}
```

**Cognify Complete:**
```json
{
  "type": "cognify_complete",
  "elapsed_ms": 1500
}
```

**Recall Complete:**
```json
{
  "type": "recall_complete",
  "match_count": 3
}
```

**Report Ready:**
```json
{
  "type": "report_ready",
  "audit_id": "750e8400-e29b-41d4-a716-446655440000"
}
```

**Error:**
```json
{
  "type": "error",
  "message": "Analysis failed: ..."
}
```

### Get Audit Report

```http
GET /v1/audits/:id/report
```

Retrieve the final audit report.

**Response:**
```json
{
  "slither_findings_count": 5,
  "memory_matches_count": 3
}
```

---

##  Findings

### List Findings

```http
GET /v1/findings?limit=20&after=<cursor>
```

List vulnerability findings with pagination.

**Query Parameters:**
- `limit` (optional): Number of results (default: 20)
- `after` (optional): Cursor UUID for pagination

**Response:**
```json
{
  "data": [
    {
      "id": "850e8400-e29b-41d4-a716-446655440000",
      "audit_id": "750e8400-e29b-41d4-a716-446655440000",
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "vuln_class": "reentrancy-eth",
      "severity": "High",
      "description": "Reentrancy vulnerability detected in withdraw function",
      "affected_functions": [...],
      "causal_chain": {...},
      "historical_matches": 3,
      "created_at": "2026-07-03T12:00:00.000Z"
    }
  ],
  "next_cursor": "850e8400-e29b-41d4-a716-446655440000",
  "has_more": false,
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Get Causal Chain

```http
GET /v1/findings/:id/chain
```

Retrieve the detailed causal chain for a finding.

**Response:**
```json
{
  "nodes": [...],
  "edges": [...],
  "vuln_class": "reentrancy-eth"
}
```

---

##  Memory Operations

### Recall Memory

```http
POST /v1/memory/recall
```

Query the memory system for similar vulnerability patterns.

**Request Body:**
```json
{
  "query": "reentrancy pattern in withdraw function",
  "top_k": 5,
  "scope": "shared"
}
```

**Scopes:**
- `shared`: Query shared vulnerability patterns (default)
- `private`: Query tenant-specific patterns
- `session`: Query current session patterns

**Response:**
```json
{
  "data": [
    {
      "id": "950e8400-e29b-41d4-a716-446655440000",
      "content": "VulnClass: Reentrancy\nSeverity: High\n...",
      "score": 0.95
    }
  ],
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

### Prune Memory

```http
DELETE /v1/memory/prune
```

Delete all private and session memory for the authenticated tenant (GDPR compliance).

**Response:**
```
204 No Content
```

### Memory Statistics

```http
GET /v1/memory/stats
```

Get memory dataset statistics.

**Response:**
```json
{
  "shared_patterns": {
    "name": "wyrmkeep:shared:patterns",
    "nodes": 1250,
    "edges": 3400
  },
  "private_dataset": {
    "name": "wyrmkeep:550e8400-...:private",
    "nodes": 45,
    "edges": 120
  },
  "session_dataset": {
    "name": "wyrmkeep:550e8400-...:session",
    "nodes": 12,
    "edges": 30
  },
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

##  Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database Configuration
DATABASE_URL=postgresql://postgres:[password]@db.xxx.supabase.co:5432/postgres

# Server Configuration
PORT=8000

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-min-32-chars

# Cognee Sidecar Configuration
COGNEE_SIDECAR_URL=http://localhost:8080
COGNEE_SIDECAR_TOKEN=your-sidecar-auth-token

# LLM API Configuration
LLM_API_KEY=your-llm-api-key
```

### Configuration Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `PORT` | No | Server port (default: 8000) | `8000` |
| `JWT_SECRET` | Yes | Secret for JWT signing (32+ chars) | `your-secret-key-here` |
| `COGNEE_SIDECAR_URL` | Yes | Cognee sidecar service URL | `http://localhost:8080` |
| `COGNEE_SIDECAR_TOKEN` | Yes | Authentication token for sidecar | `your-token` |
| `LLM_API_KEY` | Yes | LLM service API key | `sk-...` |

---

##  Development

### Project Structure

```
wyrmkeep/
├── src/
│   ├── auth/              # Authentication & middleware
│   ├── models/            # Data models
│   ├── routes/            # API route handlers
│   ├── services/          # Business logic
│   │   ├── pipeline.rs    # Audit processing pipeline
│   │   ├── pattern.rs     # Pattern extraction
│   │   ├── cognee_client.rs
│   │   └── sidecar_client.rs
│   ├── config.rs          # Configuration
│   ├── error.rs           # Error handling
│   ├── state.rs           # Application state
│   └── main.rs            # Entry point
├── migrations/            # Database migrations
├── Dockerfile
├── .env.example
└── README.md
```

### Running Tests

```bash
cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Check compilation
cargo check
```

### Database Migrations

Create a new migration:
```bash
cargo sqlx migrate add <migration_name>
```

Run migrations:
```bash
cargo sqlx migrate run
```

---

##  API Design Principles

1. **RESTful**: Standard HTTP methods and status codes
2. **Versioned**: All endpoints under `/v1` for future compatibility
3. **Idempotent**: Safe retries for GET, PUT, DELETE
4. **Paginated**: Cursor-based pagination for all list endpoints
5. **Traced**: Unique request IDs for debugging
6. **Documented**: Comprehensive error messages
7. **Secure**: JWT + API key authentication


##  Acknowledgments

- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Database toolkit
- [Tower](https://github.com/tower-rs/tower) - Middleware
- [Slither](https://github.com/crytic/slither) - Static analyzer
- [Cognee](https://github.com/topoteretes/cognee) - Memory system

---



<div align="center">

**Shipped in Rust**

</div>