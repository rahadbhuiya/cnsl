FROM python:3.11-slim

LABEL org.opencontainers.image.title="CNSL Guard"
LABEL org.opencontainers.image.description="Cyber Network Security Layer — SSH brute-force detection"
LABEL org.opencontainers.image.licenses="MIT"

# Install tcpdump and iptables (needed for live capture and blocking)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iptables \
    ipset \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install --no-cache-dir -e ".[all]"

# Mount your auth.log and config here:
VOLUME ["/var/log", "/etc/cnsl"]

# Run in dry-run mode by default; pass --execute to enable blocking.
# NOTE: container needs --cap-add NET_ADMIN NET_RAW for tcpdump + iptables.
ENTRYPOINT ["python", "-m", "cnsl"]
CMD ["--config", "/etc/cnsl/config.json"]