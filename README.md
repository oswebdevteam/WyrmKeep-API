# WyrmKeep API

A smart contract audit platform leveraging memory-augmented pattern recognition for vulnerability detection.

## Quick Start

### 1. Set up PostgreSQL

```bash
# Using Docker
docker run -d \
  --name wyrmkeep-db \
  -e POSTGRES_USER=wyrmkeep \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=wyrmkeep \
  -p 5432:5432 \
  postgres:16
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your configuration
```

### 3. Run Locally

```bash
cargo run
```

Server starts on `http://localhost:8000`

## Deployment

This application can deploy to **Railway**, **Fly.io**, **Render**, or any Docker-compatible platform.

See [DEPLOYMENT.md](DEPLOYMENT.md) for detailed deployment guides for each platform.

**Quick Deploy to Railway:**
```bash
npm install -g @railway/cli
railway login
railway init
railway add --plugin postgres
railway up
```

## Features

### 🔍 Smart Contract Analysis
- Automated vulnerability detection using Slither
- Pattern extraction and abstraction
- Memory-augmented recall for historical vulnerability matching

### 🔐 Multi-Tenant Architecture
- JWT-based authentication
- API key support with tenant isolation
- Secure data segregation

### 📊 Advanced Endpoints

#### Contracts
- Upload and manage smart contracts
- Cursor-based pagination
- Source code hashing for deduplication

#### Audits
- Create audit jobs with custom vulnerability tags
- Real-time SSE event streaming
- Comprehensive audit reports

#### Findings
- **NEW**: Paginated findings list
- Causal chain analysis
- Severity classification

#### Memory
- **NEW**: Dataset-scoped recall (shared, private, session)
- **NEW**: Real statistics per dataset
- **NEW**: Complete memory cleanup (GDPR compliant)
- Pattern matching and similarity search

## Recent Updates

See [CHANGELOG.md](CHANGELOG.md) for detailed changes.

### Production Implementations (2026-07-02)

✅ **Findings Pagination** - Efficient cursor-based pagination  
✅ **Memory Dataset Selection** - Query different dataset scopes  
✅ **Complete Session Cleanup** - Full GDPR compliance  
✅ **Real Memory Statistics** - Actual node/edge counts  
✅ **Dynamic Vulnerability Tags** - Customizable audit scoping  
✅ **Advanced Edge Inference** - Vulnerability-specific relationships  

## API Examples

### Create Audit with Custom Tags
```bash
POST /audits
{
  "contract_id": "uuid",
  "vuln_class_tags": ["reentrancy", "access-control"]
}
```

### Query Private Memory
```bash
POST /memory/recall
{
  "query": "reentrancy pattern",
  "top_k": 10,
  "scope": "private"
}
```

### Paginated Findings
```bash
GET /findings?limit=50&after=<cursor-uuid>
```

### Memory Statistics
```bash
GET /memory/stats
```

## Architecture

### Technology Stack
- **Framework**: Axum + Shuttle.rs
- **Database**: PostgreSQL with SQLx
- **Authentication**: JWT + API Keys (Argon2)
- **Memory System**: Cognee (graph-based knowledge storage)
- **Analysis**: Slither + Custom Pattern Extraction

### Key Components

```
┌─────────────┐
│   Clients   │
└──────┬──────┘
       │
┌──────▼──────────────────────────────┐
│  API Layer (Axum)                   │
│  - Routes                           │
│  - Auth Middleware                  │
│  - Request Validation               │
└──────┬──────────────────────────────┘
       │
┌──────▼──────────────────────────────┐
│  Business Logic                     │
│  - Audit Pipeline                   │
│  - Pattern Abstraction              │
│  - Memory Integration               │
└──────┬──────────────────────────────┘
       │
┌──────▼──────────┬──────────────────┐
│   PostgreSQL    │  Cognee Memory   │
│   (SQLx)        │  (Graph Store)   │
└─────────────────┴──────────────────┘
```

## Database Schema

### Tenants
- Multi-tenant isolation
- API key hashing with Argon2
- Cognee dataset associations

### Contracts
- Source code storage
- SHA-256 hashing
- Language detection

### Audits
- Job queue management
- Status tracking (queued, running, complete, failed)
- Slither raw output and abstract patterns
- Memory matches and final reports

### Findings
- Vulnerability classification
- Severity levels
- Causal chain analysis
- Historical match tracking

## Development

### Prerequisites
- Rust 1.70+
- CMake (for lance-encoding)
- Ninja build system
- Protocol Buffers compiler (protoc)

### Local Development
```bash
# Run with Shuttle local environment
cargo shuttle run

# View logs
cargo shuttle logs

# Check status
cargo shuttle status
```

### Configuration

Secrets are managed via `Secrets.toml` (production) and `Secrets.dev.toml` (development):

```toml
JWT_SECRET = "your-jwt-secret"
COGNEE_SIDECAR_URL = "http://localhost:8000"
COGNEE_SIDECAR_TOKEN = "your-token"
LLM_API_KEY = "your-llm-key"
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

(Add your license here)

## Support

For issues and questions:
- GitHub Issues: (your repo URL)
- Documentation: [DEPLOYMENT.md](DEPLOYMENT.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
