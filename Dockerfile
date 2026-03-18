FROM python:3.12-slim

WORKDIR /app

# System deps — Node.js from Debian Bookworm official repos (avoids curl-pipe-bash fragility)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs \
    npm \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Verify Node.js install
RUN node --version && npm --version

# Python deps — explicit list avoids editable-install fragility with large packages
RUN pip install --no-cache-dir \
    "fastapi>=0.115.0" \
    "uvicorn[standard]>=0.30.0" \
    "pydantic>=2.0.0" \
    "RestrictedPython>=7.1" \
    "click>=8.0.0" \
    "httpx>=0.27.0" \
    "numpy>=1.26" \
    "pandas>=2.2"

# App source
COPY auth.py app.py ./
COPY help ./help

# Data dir for SQLite auth DB
RUN mkdir -p /app/data
ENV AUTH_DB_PATH=/app/data/auth.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=15s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Single worker required: in-memory sessions are worker-local.
# Concurrency is handled by the thread pool inside the process.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
