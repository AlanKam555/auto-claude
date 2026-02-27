# SecureClaw Production Dockerfile
# Multi-stage build for minimal image size

FROM python:3.11-slim AS base

# Security: create non-root user
RUN groupadd --gid 1000 secureclaw && \
    useradd --uid 1000 --gid secureclaw --shell /bin/bash --create-home secureclaw

WORKDIR /app

# Install dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=secureclaw:secureclaw . .

# Create config directory with correct permissions
RUN mkdir -p /app/config && chown secureclaw:secureclaw /app/config

# Switch to non-root user
USER secureclaw

# Expose the default port
EXPOSE 8000

# Health check for container orchestration
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; r = httpx.get('http://localhost:8000/health'); assert r.status_code == 200"

# Run the application
CMD ["python", "main.py", "--host", "0.0.0.0", "--port", "8000"]
