FROM python:3.11-slim

LABEL org.opencontainers.image.title="CNSL"
LABEL org.opencontainers.image.description="Correlated Network Security Layer v3.4.13"
LABEL org.opencontainers.image.version="3.4.13"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/rahadbhuiya/cnsl"

# System deps: tcpdump (live capture), iptables/ipset (blocking), curl (healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iptables \
    ipset \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Install with all optional deps. asyncpg/PyYAML aren't in the "full" extra
# (full = the batteries-included single-node default: sqlite + notify +
# auth + 2fa + ml + reports) since they're only needed for optional
# PostgreSQL backend/migration (--migrate-db) and YAML config files
# respectively -- installed explicitly here so the image supports both
# out of the box.
RUN pip install --no-cache-dir -e ".[full]" && \
    pip install --no-cache-dir aiohttp aiosqlite aiokafka pyotp bcrypt asyncpg pyyaml

# Data directories
RUN mkdir -p /var/lib/cnsl /var/log/cnsl /etc/cnsl

# Volumes
VOLUME ["/var/log", "/etc/cnsl", "/var/lib/cnsl"]

# Dashboard port
EXPOSE 8765

# Healthcheck -- /api/health is unauthenticated by design, specifically
# for load balancers/container orchestrators (see cnsl/dashboard.py).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8765/api/health || exit 1

# Run in dry-run by default; pass --execute to enable real blocking.
# Container needs: --cap-add NET_ADMIN --cap-add NET_RAW
ENTRYPOINT ["python", "-m", "cnsl"]
CMD ["--config", "/etc/cnsl/config.json", "--dashboard"]