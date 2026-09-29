# ARBITER: Optimal attack attribution for quantum digital signatures
# Multi-stage Docker build: frontend (Node) + backend (Python 3.12)

# ============================================================================
# Stage 1: Frontend Build (Node.js)
# ============================================================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app/frontend

# Copy frontend source
COPY frontend/package*.json ./
COPY frontend/tsconfig.json ./
COPY frontend/vite.config.ts ./
COPY frontend/index.html ./
COPY frontend/src ./src

# Install dependencies and build
RUN npm ci && npm run build

# ============================================================================
# Stage 2: Python Backend (Final)
# ============================================================================
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ARBITER_DATA_DIR=/data \
    PORT=8000

# Create non-root user
RUN groupadd -r arbiter && useradd -r -g arbiter arbiter

# Install system dependencies (for scientific computing and cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python package
COPY . .

# Copy built frontend from builder stage
COPY --from=frontend-builder /app/frontend/dist ./src/arbiter/dashboard

# Install Python package in editable mode with all dependencies
RUN pip install --no-cache-dir -e .[api,pki,sdp]

# Create data directory with proper permissions
RUN mkdir -p /data && chown -R arbiter:arbiter /data /app

# Switch to non-root user
USER arbiter

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:${PORT}/health', timeout=2)" || exit 1

# Expose port
EXPOSE ${PORT}

# Default command: run API server with dashboard
CMD ["python", "-m", "uvicorn", "arbiter.api.server:app", "--host", "0.0.0.0", "--port", "8000"]
