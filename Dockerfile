FROM python:3.11-slim

LABEL org.opencontainers.image.title="CNSL"
LABEL org.opencontainers.image.description="Correlated Network Security Layer v2.0.0"
LABEL org.opencontainers.image.version="2.0.0"
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

# Install with all optional deps
RUN pip install --no-cache-dir -e ".[full]" && \
    pip install --no-cache-dir aiohttp aiosqlite aiokafka pyotp bcrypt

# Data directories
RUN mkdir -p /var/lib/cnsl /var/log/cnsl /etc/cnsl

# Volumes
VOLUME ["/var/log", "/etc/cnsl", "/var/lib/cnsl"]

# Dashboard port
EXPOSE 8765

# Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:8765/api/stats || exit 1

# Run in dry-run by default; pass --execute to enable real blocking.
# Container needs: --cap-add NET_ADMIN --cap-add NET_RAW
ENTRYPOINT ["python", "-m", "cnsl"]
CMD ["--config", "/etc/cnsl/config.json", "--dashboard"]