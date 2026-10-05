# WyrmKeep API

<div align="center">

**Multi-Language Smart Contract Audit Platform — Native Static Analysis + LLM Enrichment**

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Built with Axum](https://img.shields.io/badge/built%20with-Axum-green.svg)](https://github.com/tokio-rs/axum)
[![Clippy](https://img.shields.io/badge/clippy-clean-brightgreen.svg)](https://github.com/rust-lang/rust-clippy)

</div>

---

## Overview

WyrmKeep is a smart contract auditing platform. Upload a contract, queue an audit, and watch results stream in over Server-Sent Events: an in-process detection engine (57 rules across 7 languages) finds candidate vulnerabilities, an LLM enriches each finding with a plain-English explanation and a suggested fix, and the pipeline mints a verifiable audit badge with a SHA-256 certificate hash.

### Key Capabilities

- **Native multi-language detection**: 57 `DetectionRule`s for Solidity, Rust/Solana, Move, Cairo, Aiken, Compact, and Quorlin — no external analyzer required
- **LLM enrichment**: per-finding plain-English explanations and `PATCHED:`/`EXPLANATION:` fix suggestions (OpenRouter-compatible, failures degrade gracefully to rule hints)
- **Bounty estimation**: deterministic High/Medium/Low/Informational payout table
- **Audit badges**: NFT-style metadata + `sha256(audit_id ‖ report)` certificate, publicly verifiable
- **Call graphs & attack paths**: nodes/edges derived from each finding's attack path
- **Real-time streaming**: SSE broadcast per audit (`analysis_started` → `report_ready`)
- **Multi-tenant**: JWT + API-key auth, tenant-scoped queries, admin-only tenant creation
- **Production-ready**: cursor pagination, rate limiting, CORS, Brotli compression, 30s timeouts, request IDs, tracing

> **Note on stale docs:** `SPEC_COMPLIANCE_REPORT.md` (2026-07-04) describes an older Slither-sidecar + Cognee-memory design. That design is not implemented: there is no `sidecar_client`/`cognee_client`, no `/v1/memory/*` endpoints, and the `slither_raw` / `abstract_pattern` / `memory_matches` columns are legacy leftovers. This README describes the code as it exists.

---

## Architecture

### System diagram

```
                         ┌────────────────────────────────────────┐
                         │              Axum router               │
                         │  /health   /v1/badges/verify/* (public)│
                         │  /v1/* (AuthUser: JWT or X-API-Key)    │
                         │  Timeout(30s) · RateLimit · CORS       │
                         │  Compression · Trace · RequestId       │
                         └───────────────┬────────────────────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    ▼                    ▼                    ▼
           ┌────────────────┐  ┌─────────────────┐  ┌─────────────────┐
           │    routes/     │  │  AuditPipeline  │  │   job_queue     │
           │ tenants,       │  │  run(job)       │  │ mpsc ch (100)   │
           │ contracts,     │  │  9 stages,      │◄─┤ per-job spawn   │
           │ audits (+SSE), │  │  emits          │  │ logs errors     │
           │ findings,      │  │  broadcast events│ └─────────────────┘
           │ call_graph,    │  └────────┬────────┘
           │ badges         │           │
           └────────────────┘           ▼
                    ┌──────────────────────────────────────┐
                    │            AnalysisEngine            │
                    │  rules_for(language) → rule.detect() │
                    │  RuleMatch → DetectedVulnerability   │
                    └──────┬───────────────┬───────────────┘
                           ▼               ▼
                  ┌─────────────────┐ ┌──────────────────┐
                  │ LlmClient       │ │ BountyEstimator  │
                  │ explain + fix   │ │ 50k/10k/1k/0 USD │
                  │ (OpenRouter,    │ └────────┬─────────┘
                  │  60s, best-     │          ▼
                  │  effort)        │ ┌──────────────────┐
                  └────────┬────────┘ │  BadgeIssuer     │
                           ▼         │  grade + sha256  │
                  ┌─────────────────┐│  audit_badges    │
                  │   PostgreSQL    │└──────────────────┘
                  │ tenants         │
                  │ contracts       │
                  │ audits (report) │
                  │ findings        │
                  │ audit_badges    │
                  └─────────────────┘
```

### Audit pipeline sequence

`POST /v1/audits` inserts a `queued` row and pushes an `AuditJob` onto the mpsc queue. The background worker spawns `AuditPipeline::run`, which executes these stages in order, emitting an SSE event after each:

```
create_audit → [queued] ──mpsc──► worker ──spawn──► pipeline
  1. status → running; emit status_update{starting}
  2. parse ContractLanguage; emit analysis_started{language}
  3. AnalysisEngine::analyze() in-process; emit analysis_complete{count, elapsed_ms}
  4. build nodes/edges/attack_paths from vuln.attack_path; emit call_graph_ready
  5. severity counts; emit pattern_extracted{node_count, edge_count} (call-graph counts)
  6. BountyEstimator::estimate() total
  7. per finding: emit enrichment_started → extract snippet →
     llm.explain_vulnerability().ok() → llm.suggest_fix().ok()
     (fallback: rule fix_hint) → INSERT INTO findings → emit enrichment_complete
  8. BadgeIssuer::issue().ok() → final report (badge_id or None)
  9. UPDATE audits SET report, status=complete; emit report_ready{audit_id}
```

### Detection engine internals

```
source: &str ──► rules_for(&ContractLanguage) ──► Vec<Box<dyn DetectionRule>>
                                                        │ .detect(source)
                                                        ▼
                                              Vec<RuleMatch> { check_name, vuln_class,
                                                severity, description, affected_lines,
                                                affected_functions, confidence,
                                                action_hint, fix_hint }
                                                        │ engine maps each match
                                                        ▼
                                    DetectedVulnerability { + attack_path: Vec<AttackStep>,
                                      suggested_fix: Option<CodeDiff> }  (sorted High → Info)
```

```rust
// src/services/analyzer/rules.rs
pub trait DetectionRule: Send + Sync {
    fn check_name(&self) -> &str;
    fn detect(&self, source: &str) -> Vec<RuleMatch>;
}

pub fn rules_for(language: &ContractLanguage) -> Vec<Box<dyn DetectionRule>> {
    match language {
        ContractLanguage::Solidity => solidity_rules(),
        ContractLanguage::Rust => rust_solana_rules(),
        ContractLanguage::Move => move_rules(),
        ContractLanguage::Cairo => cairo_rules(),
        ContractLanguage::Aiken => aiken_rules(),
        ContractLanguage::Compact => compact_rules(),
        ContractLanguage::Quorlin => quorlin_rules(),
    }
}
```

```rust
// src/services/analyzer/engine.rs
impl AnalysisEngine {
    pub fn analyze(source: &str, language: &ContractLanguage) -> Vec<DetectedVulnerability> {
        let rule_set = rules::rules_for(language);
        let mut vulnerabilities = Vec::new();
        for rule in &rule_set {
            let matches = rule.detect(source);
            for m in matches {
                vulnerabilities.push(Self::match_to_vulnerability(m, source));
            }
        }
        vulnerabilities.sort_by(|a, b| {
            severity_ordinal(&a.severity).cmp(&severity_ordinal(&b.severity))
        });
        vulnerabilities
    }
}
```

### Data model

```
tenants (id PK, name UNIQUE, api_key_hash, created_at)
   │ 1──∞ contracts (id PK, tenant_id FK⤷CASCADE, name, source_hash,
   │                 source_code, language DEFAULT 'solidity', uploaded_at)
   │ 1──∞ audits (id PK, tenant_id, contract_id, status DEFAULT 'queued',
   │              report JSONB, error_message, created_at, completed_at)
   │              ├──∞ findings (id PK, audit_id FK⤷CASCADE, tenant_id, vuln_class,
   │              │              severity, description, affected_functions JSONB,
   │              │              causal_chain JSONB, historical_matches, plain_english,
   │              │              suggested_fix JSONB, attack_path JSONB,
   │              │              bounty_estimate_usd, confidence)
   │              └──∞ audit_badges (id PK, audit_id FK⤷CASCADE, tenant_id,
                                     contract_name, certificate_hash UNIQUE,
                                     grade, vulnerability_count, high_severity_count,
                                     chain DEFAULT 'solidity', issued_at, metadata_json)
```

### Technology stack

- **Framework**: Axum 0.7 on Tokio (multipart, SSE, typed headers)
- **Database**: PostgreSQL 14+ (Supabase-ready) via SQLx 0.8 (compile-time checked queries, migrations run on boot)
- **Auth**: JWT (HS256, 24h) + Argon2id-hashed API keys; `tower_governor` rate limiting
- **Analysis**: native Rust rule engine (`services/analyzer`) — no external binaries
- **LLM**: OpenRouter-compatible chat API (`google/gemini-2.5-flash`, 1024 tokens, temp 0.3)
- **Middleware**: Tower HTTP (Brotli compression, CORS, trace, timeout, request IDs), `DashMap` broadcast registry for SSE

---

## Detection Rules

Languages are parsed case-insensitively with chain aliases (`src/models/contract.rs`):

| Language | Aliases | Rules |
|---|---|---|
| Solidity (default) | `sol` | 15 |
| Rust / Solana | `rs`, `solana`, `anchor` | 9 |
| Move | `aptos`, `sui` | 6 |
| Cairo | `starknet` | 6 |
| Aiken | `cardano` | 6 |
| Compact | `midnight` | 4 |
| Quorlin | `kortana` | 11 |

Full check-name catalog (`rule.detect()` → `RuleMatch.check_name`):

| Language | Check names |
|---|---|
| Solidity | `reentrancy-eth`, `unchecked-return`, `tx-origin`, `access-control`, `arithmetic-overflow`, `timestamp-dependence`, `delegatecall-injection`, `flash-loan-manipulation`, `price-oracle-manipulation`, `unprotected-mint`, `signature-replay`, `signature-malleability`, `cross-chain-replay`, `erc4626-share-inflation`, `unbounded-loop-dos` |
| Rust / Solana | `missing-signer-check`, `pda-seed-collision`, `rust-arithmetic-overflow`, `missing-owner-check`, `unchecked-account-owner`, `missing-rent-exemption`, `unchecked-account-type`, `unvalidated-remaining-accounts`, `non-canonical-bump` |
| Move | `move-arithmetic`, `move-missing-acquires`, `move-unprotected-entry`, `move-unconstrained-shared-object`, `move-missing-access-check`, `move-public-mutator` |
| Cairo | `felt-overflow`, `cairo-reentrancy`, `cairo-unprotected-storage-write`, `cairo-missing-event`, `cairo-unprotected-upgrade`, `cairo-unsafe-unwrap` |
| Aiken | `validator-bypass`, `aiken-datum-hijack`, `aiken-double-satisfaction`, `aiken-missing-boundary-validation`, `aiken-missing-signatory`, `aiken-unchecked-time-range` |
| Compact | `compact-state-leak`, `compact-private-state-leak`, `compact-witness-exposure`, `compact-underconstrained-action` |
| Quorlin | `quorlin-permission`, `QL-AC-01`, `QL-AC-02`, `QL-AC-03`, `QL-AC-04`, `QL-IV-01`, `QL-IV-03`, `QL-RE-01`, `QL-RE-03`, `QL-EV-01`, `QL-WA-01` |

Example — a rule is a pure function over source text (`src/services/analyzer/rules.rs`):

```rust
struct TxOriginRule;

impl DetectionRule for TxOriginRule {
    fn check_name(&self) -> &str { "tx-origin" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("tx.origin") { continue; }
            let in_condition = line.contains("require(")
                || line.contains("if (") || line.contains("if(")
                || line.contains("assert(");
            if !in_condition { continue; }
            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());
            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::TxOriginAuth,
                severity: FindingSeverity::High,
                description: format!(
                    "Use of `tx.origin` for authorization in `{}`. \
                     A phishing contract can relay calls and pass the tx.origin check.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.95,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "require(msg.sender == owner, \"Not authorized\");".into(),
                    explanation: "Replace tx.origin with msg.sender for authorization checks.".into(),
                }),
            });
        }
        matches
    }
}
```

### Bounty estimation

Deterministic per-severity table (`src/services/bounty_estimator.rs`):

```rust
// High: $50,000 · Medium: $10,000 · Low: $1,000 · Informational: $0
BountyEstimator::default().estimate(&vulnerabilities) // -> u64 total USD
```

### Badge issuance

```rust
// src/services/pipeline.rs — badge failure is non-fatal (.ok()), the report
// is persisted with badge_id: None instead
let badge_id = BadgeIssuer::issue(
    &pool,
    BadgeIssueParams {
        audit_id,
        tenant_id,
        contract_name: &job.contract_name,
        chain: &chain,                 // ContractLanguage::to_string()
        report_json: &report_json,
        vulnerability_count: total as i32,
        high_severity_count: high as i32,
        medium_severity_count: medium as i32,
    },
)
.await
.ok();
```

Grade comes from `AuditGrade::from_counts(high, medium)`; `certificate_hash = sha256(audit_id ‖ report_json)`; metadata is NFT-style JSON (`name`, `description`, `attributes`, `external_url: https://wyrmkeep.io/verify/{hash}`).

---

## Quick Start

### Prerequisites

- Rust 1.75+
- PostgreSQL 14+ (or Supabase account)

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

3. **Configure the database:**

   Get your connection string from Supabase:
   - Dashboard → Settings → Database → Connection String (URI)
   - Add to `.env` as `DATABASE_URL`

4. **Run the server (migrations run automatically on boot):**
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

### End-to-end audit in 4 calls

```bash
TOKEN=...  # JWT from tenant creation, or use X-API-Key: <tenant_id>.<raw_key>

# 1. Upload
CID=$(curl -s -X POST http://localhost:8000/v1/contracts \
  -H "Authorization: Bearer $TOKEN" \
  -F "name=MyToken" -F "file=@contracts/MyToken.sol" -F "language=solidity" \
  | jq -r .data.id)

# 2. Queue audit (202 Accepted)
AID=$(curl -s -X POST http://localhost:8000/v1/audits \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"contract_id\":\"$CID\"}" | jq -r .audit_id)

# 3. Stream progress (SSE) until report_ready
curl -N http://localhost:8000/v1/audits/$AID/stream \
  -H "Authorization: Bearer $TOKEN"

# 4. Fetch report, findings, call graph, badge
curl http://localhost:8000/v1/audits/$AID/report -H "Authorization: Bearer $TOKEN"
curl "http://localhost:8000/v1/findings?limit=20" -H "Authorization: Bearer $TOKEN"
curl http://localhost:8000/v1/audits/$AID/call-graph -H "Authorization: Bearer $TOKEN"
```

---

## API Documentation

### Base URL

```
http://localhost:8000/v1
```

All endpoints return JSON and include a `request_id` field for tracing. All `/v1/*` routes except badge verification require auth.

### Authentication

Two authentication methods are supported:

**1. JWT Bearer Token:**
```bash
Authorization: Bearer <jwt_token>
```

**2. API Key:**
```bash
X-API-Key: <tenant_id>.<raw_api_key>
```

Rate limiting: 1 req/s, burst 10 per tenant (API-key prefix, else JWT prefix, else IP). Creating tenants additionally requires `role == Admin`.

### Route table

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | none | Liveness probe |
| `POST` | `/v1/tenants` | admin | Create tenant, returns API key + JWT |
| `GET` | `/v1/tenants/me` | tenant | Current tenant info |
| `POST` | `/v1/contracts` | tenant | Upload contract (multipart) |
| `GET` | `/v1/contracts?limit&after` | tenant | List contracts (cursor pagination) |
| `GET` | `/v1/contracts/:id` | tenant | Get one contract |
| `POST` | `/v1/audits` | tenant | Queue audit → `202 Accepted` + `audit_id` |
| `GET` | `/v1/audits?limit&after` | tenant | List audits |
| `GET` | `/v1/audits/:id/stream` | tenant | SSE progress stream |
| `GET` | `/v1/audits/:id/report` | tenant | Final audit report |
| `GET` | `/v1/audits/:id/call-graph` | tenant | Nodes, edges, attack paths |
| `GET` | `/v1/findings?limit&after` | tenant | List findings |
| `GET` | `/v1/findings/:id/chain` | tenant | Causal chain for a finding |
| `GET` | `/v1/badges?limit&after` | tenant | List badges |
| `GET` | `/v1/badges/:id` | tenant | Get badge by id **or** audit id |
| `GET` | `/v1/badges/verify/:certificate_hash` | none | Public badge verification |

---

## Authentication Endpoints

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

## Tenant Management

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
    "created_at": "2026-07-03T12:00:00.000Z"
  },
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

## Contract Management

### Upload Contract

```http
POST /v1/contracts
Content-Type: multipart/form-data
```

Upload a smart contract for auditing.

**Form Fields:**
- `name` (required): Contract name
- `file` or `source_code` (required): Contract source code
- `language` (optional): Programming language (default: "solidity"; see language table for aliases)

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

## Audit Management

### Create Audit

```http
POST /v1/audits
```

Start a new security audit for a contract. Returns `202 Accepted` and enqueues an `AuditJob` on the background worker.

**Request Body:**
```json
{
  "contract_id": "650e8400-e29b-41d4-a716-446655440000",
  "vuln_class_tags": ["all"]
}
```

(`vuln_class_tags` defaults to `["all"]` when omitted.)

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

Real-time Server-Sent Events stream backed by a per-audit broadcast channel (buffer 100, 15s keep-alive). If the audit is already `complete`/`failed`, the stream replays the terminal event immediately; otherwise it sends a `status_update{running}` greeting and tails live events.

**Event types** (`src/routes/audits.rs` — `AuditEvent`, `snake_case` tagged):

| `type` | Payload | Meaning |
|---|---|---|
| `status_update` | `stage`, `message` | Lifecycle marker (`starting`, `running`, greeting) |
| `analysis_started` | `language` | Detection engine started |
| `analysis_complete` | `vulnerability_count`, `elapsed_ms` | Native analysis finished |
| `pattern_extracted` | `node_count`, `edge_count` | Call-graph counts |
| `enrichment_started` | `finding_index`, `total` | LLM enrichment of finding N began |
| `enrichment_complete` | `finding_index` | Finding N persisted |
| `call_graph_ready` | `node_count`, `edge_count` | Graph materialized |
| `report_ready` | `audit_id` | Report persisted, stream terminal |
| `error` | `message` | Terminal failure |

Consume it (browsers can't set `Authorization` on native `EventSource`, so stream via `fetch`):

```js
// Same-origin proxy or backend route forwards the Authorization header.
const res = await fetch(`/v1/audits/${auditId}/stream`, {
  headers: { Authorization: `Bearer ${token}` },
});
const reader = res.body.getReader();
const decoder = new TextDecoder();
let buf = "";
for (;;) {
  const { done, value } = await reader.read();
  if (done) break;
  buf += decoder.decode(value, { stream: true });
  for (const chunk of buf.split("\n\n")) {
    const line = chunk.split("\n").find((l) => l.startsWith("data:"));
    if (!line) continue;
    const evt = JSON.parse(line.slice(5));
    if (evt.type === "report_ready") {
      reader.cancel();
      fetchReport(evt.audit_id);
    }
  }
  buf = buf.slice(buf.lastIndexOf("\n\n") + 2);
}
```

### Get Audit Report

```http
GET /v1/audits/:id/report
```

Retrieve the final audit report (vulnerability counts, severity breakdown, call graph, bounty total, badge id).

### Get Call Graph

```http
GET /v1/audits/:id/call-graph
```

Nodes, edges, and attack paths extracted from the stored report.

**Response:**
```json
{
  "nodes": [...],
  "edges": [...],
  "attack_paths": [...],
  "request_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

---

## Findings

### List Findings

```http
GET /v1/findings?limit=20&after=<cursor>
```

List vulnerability findings with pagination. Each row carries the detector output plus enrichment: `plain_english`, `suggested_fix`, `attack_path`, `bounty_estimate_usd`, and `confidence`.

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

## Badges

Audits mint a badge row (`audit_badges`) with an NFT-style `metadata_json` and a unique `certificate_hash`. Verification is public — no auth required.

### List Badges

```http
GET /v1/badges?limit=20&after=<cursor>
```

### Get Badge

```http
GET /v1/badges/:id
```

Matches by badge `id` **or** `audit_id`.

### Verify Badge (public)

```http
GET /v1/badges/verify/:certificate_hash
```

```bash
curl http://localhost:8000/v1/badges/verify/<certificate_hash>
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Database Configuration
DATABASE_URL=postgresql://postgres:[password]@db.xxx.supabase.co:5432/postgres

# Server Configuration
PORT=8000

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-min-32-chars

# LLM Configuration (OpenRouter-compatible)
LLM_API_KEY=your-llm-api-key
LLM_BASE_URL=https://openrouter.ai/api/v1
```

### Configuration Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `DATABASE_URL` | Yes | PostgreSQL connection string | `postgresql://user:pass@host:5432/db` |
| `PORT` | No | Server port (default: 8000) | `8000` |
| `JWT_SECRET` | Yes | Secret for JWT signing (32+ chars) | `your-secret-key-here` |
| `LLM_API_KEY` | Yes | Bearer key for the chat-completions API | `sk-...` |
| `LLM_BASE_URL` | No | Chat API base URL (default: OpenRouter) | `https://openrouter.ai/api/v1` |

`AppConfig` (`src/config.rs`) only owns the last three; `DATABASE_URL`/`PORT` are read in `main.rs`. Pool defaults: 10 max connections, 10s acquire timeout, migrations via `sqlx::migrate!` on boot.

### Error model

`AppError` (`src/error.rs`) maps to `{code, message}` JSON: `DATABASE_ERROR`/`ANALYSIS_ERROR`/`INTERNAL_ERROR` → 500 (generic message, detail logged), `LLM_ERROR` → 502, `NOT_FOUND` → 404, `UNAUTHORIZED` → 401, `FORBIDDEN` → 403, `VALIDATION_ERROR` → 400, `CONFLICT` → 409.

---

## Development

### Project Structure

```
wyrmkeep/
├── src/
│   ├── auth/              # JWT claims/keys, Argon2 API-key middleware, AuthUser extractor
│   ├── models/            # audit, badge, contract (ContractLanguage), finding,
│   │                      #   tenant, vuln_ontology (VulnClass, AttackStep, CodeDiff)
│   ├── routes/            # audits (+SSE), badges, call_graph, contracts,
│   │                      #   findings, health, tenants
│   ├── services/
│   │   ├── analyzer/      # engine.rs (AnalysisEngine) + rules.rs (57 DetectionRules)
│   │   ├── pipeline.rs    # AuditPipeline::run — the 9-stage orchestration
│   │   ├── job_queue.rs   # mpsc background worker
│   │   ├── llm_client.rs  # OpenRouter chat: explain_vulnerability, suggest_fix
│   │   ├── bounty_estimator.rs  # 50k/10k/1k/0 table
│   │   ├── badge_issuer.rs      # BadgeIssueParams → grade + sha256 certificate
│   │   └── pattern.rs     # Slither-check-name → VulnClass mapper (legacy helper)
│   ├── bin/migrate.rs     # Migration binary
│   ├── config.rs          # JWT_SECRET / LLM_API_KEY / LLM_BASE_URL
│   ├── db/mod.rs          # (stub — SQL is inline sqlx)
│   ├── error.rs           # AppError → status codes
│   ├── state.rs           # AppState: pool, config, LlmClient, job_tx, audit_events
│   ├── lib.rs
│   └── main.rs            # tracing, pool, migrations, worker, Axum serve
├── migrations/            # 7 SQL files: tenants, contracts, audits, findings
│                          #   (+enrichment), badges (+chain column)
├── examples/test_server.rs# Standalone SSE stub (:8001/test, unrelated to audits)
├── Dockerfile
└── README.md
```

### Running Tests

```bash
cargo test              # 21 analyzer unit tests (src/services/analyzer/rules.rs)
cargo test --lib services::analyzer
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint (must be warning-free: cargo clippy --lib --tests -- -D warnings)
cargo clippy

# Check compilation
cargo check
```

### Database Migrations

Migrations run automatically on boot (`sqlx::migrate!("./migrations")`). Manual runs:

```bash
cargo sqlx migrate add <migration_name>
cargo sqlx migrate run
```

Note: `audits.slither_raw`, `audits.abstract_pattern`, and `audits.memory_matches` are unused legacy columns; tenant `cognee_dataset_*` columns were dropped (`20240102000001`).

---

## API Design Principles

1. **RESTful**: Standard HTTP methods and status codes
2. **Versioned**: All endpoints under `/v1` for future compatibility
3. **Idempotent**: Safe retries for GET, PUT, DELETE
4. **Paginated**: Cursor-based pagination for all list endpoints
5. **Traced**: Unique request IDs for debugging
6. **Documented**: Comprehensive error messages
7. **Secure**: JWT + API key authentication

## Acknowledgments

- [Axum](https://github.com/tokio-rs/axum) - Web framework
- [SQLx](https://github.com/launchbadge/sqlx) - Database toolkit
- [Tower](https://github.com/tower-rs/tower) - Middleware
- [Tokio](https://tokio.rs) - Async runtime (SSE broadcast, job queue)

---

<div align="center">

**Shipped in Rust**

</div>
