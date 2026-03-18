FROM python:3.12-slim

WORKDIR /app

# System deps + Node.js 22.x (for JavaScript execution sandbox)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Verify Node.js install
RUN node --version && npm --version

# Python deps
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# App source
COPY auth.py app.py ./

# Data dir for SQLite auth DB
RUN mkdir -p /app/data
ENV AUTH_DB_PATH=/app/data/auth.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=15s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
