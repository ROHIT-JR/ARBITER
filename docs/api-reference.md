# API Reference

ARBITER provides a FastAPI server with endpoints for quantum simulations, attack detection, and audit ledger inspection.

## Base URL

```
http://localhost:8000/api/v1
```

## Endpoints

### Health Check

```http
GET /health
```

**Response:**

```json
{
  "status": "healthy",
  "version": "0.1.0"
}
```

---

### Simulate a QDS Session

```http
POST /api/v1/simulate
Content-Type: application/json
```

**Request Body:**

```json
{
  "rounds": 100,
  "visibility": 0.92,
  "hypothesis": "legitimate",
  "noise_preset": "trapped_ion_2024"
}
```

**Parameters:**

- `rounds` (int): Number of QDS rounds. Default: 1200
- `visibility` (float): Bell measurement visibility. Range: [0, 1]
- `hypothesis` (str): Attack scenario
  - `"legitimate"`, `"forgery"`, `"impersonation"`, `"replay"`, `"channel"`
- `noise_preset` (str, optional): Predefined noise model
  - `"trapped_ion_2024"`, `"idealized"`, `"depolarizing"`

---

### Detect Attacks

```http
POST /api/v1/detect
Content-Type: application/json
```

**Request Body:**

```json
{
  "transcript": [...]
}
```

**Response:**

```json
{
  "decision": "accept",
  "attack_type": "legitimate",
  "confidence": 0.999,
  "rounds_analyzed": 100
}
```

---

### Get Audit Ledger

```http
GET /api/v1/ledger
```

**Query Parameters:**

- `offset` (int, optional): Start from entry N. Default: 0
- `limit` (int, optional): Return at most N entries. Default: 100

---

## Interactive Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI Schema:** http://localhost:8000/openapi.json

## Example Workflow

```bash
# 1. Simulate a session
curl -X POST http://localhost:8000/api/v1/simulate \
  -H "Content-Type: application/json" \
  -d '{"rounds": 100, "visibility": 0.92, "hypothesis": "legitimate"}' \
  > transcript.json

# 2. Detect attacks
curl -X POST http://localhost:8000/api/v1/detect \
  -H "Content-Type: application/json" \
  -d @transcript.json

# 3. Check the ledger
curl http://localhost:8000/api/v1/ledger
```

See [Architecture](architecture.md) for more details on the detection algorithm.
