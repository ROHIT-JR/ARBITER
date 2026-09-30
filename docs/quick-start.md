# Quick Start

## 1. Installation

```bash
pip install arbiter-qds
```

## 2. Run the Demo

```bash
arbiter demo
```

## 3. Run the API Server

```bash
uvicorn arbiter.api.server:app --reload
```

Open your browser to `http://localhost:8000`:
- **Dashboard:** Interactive simulation interface
- **/docs:** Swagger UI with all API endpoints
- **/health:** Server health check

## 4. Docker Deployment

```bash
docker compose up
```

Visit `http://localhost:8000` for the interactive dashboard.

## 5. Python API

```python
from arbiter.qds_simulation import simulate_session, SessionConfig, Hypothesis
from arbiter.noise import PRESETS
from arbiter.pipeline import Arbiter

config = SessionConfig(rounds=100, visibility=0.92, hypothesis=Hypothesis.LEGITIMATE)

noise = PRESETS["trapped_ion_2024"]
result = simulate_session(config, noise=noise)

detector = Arbiter()
verdict = detector.detect(result.transcript)

print(f"Verdict: {verdict.decision}")
print(f"Attack: {verdict.attack_type}")
print(f"Confidence: {verdict.confidence:.3f}")
```

## 6. Run Tests

```bash
pip install "arbiter-qds[dev]"
pytest
pytest --cov=arbiter
```

## Next Steps

- [Architecture](architecture.md) - System components and design
- [Threat Model](threat-model.md) - Attack scenarios in detail
- [API Reference](api-reference.md) - Full endpoint documentation
