# Installation

## System Requirements

- **Python:** 3.10, 3.11, 3.12, or 3.13
- **OS:** Linux, macOS, or Windows (WSL2 recommended)
- **Memory:** 2 GB RAM minimum; 8 GB recommended for Qiskit circuits
- **Docker:** (optional) Docker 20.10+ for containerized deployment

## Quick Install (pip)

```bash
pip install arbiter-qds
```

Verify the installation:

```bash
python -c "import arbiter; print(arbiter.__version__)"
arbiter --help
```

## Docker Setup

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/ROHIT-JR/ARBITER.git
cd ARBITER
docker compose up
```

Access the dashboard at `http://localhost:8000`.

### Using Docker CLI

```bash
docker build -t arbiter-qds:latest .
docker run -p 8000:8000 -v arbiter-data:/data arbiter-qds:latest
```

## Development Install

```bash
git clone https://github.com/ROHIT-JR/ARBITER.git
cd ARBITER

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

pip install -e ".[dev]"
pytest
```

## Next Steps

- [Quick Start](quick-start.md) - Run your first simulation
- [API Reference](api-reference.md) - Explore endpoints
- [Contributing](../CONTRIBUTING.md) - Join the team
