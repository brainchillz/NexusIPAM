FROM debian:bookworm-slim

# iputils-ping supplies the ICMP prober (setuid/cap_net_raw, so the app itself
# needs no privileges); iproute2 gives `ip neigh` for MAC discovery; openssl
# generates the self-signed cert on first run.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv iputils-ping iproute2 openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /opt/nexus-ipam/requirements.txt
RUN python3 -m venv /opt/nexus-ipam/venv \
    && /opt/nexus-ipam/venv/bin/pip install --no-cache-dir -r /opt/nexus-ipam/requirements.txt

COPY nexus-ipam.py /opt/nexus-ipam/nexus-ipam.py
COPY nexusipam /opt/nexus-ipam/nexusipam
COPY templates /opt/nexus-ipam/templates
COPY static /opt/nexus-ipam/static
COPY docker/entrypoint.sh /opt/nexus-ipam/entrypoint.sh
RUN chmod +x /opt/nexus-ipam/entrypoint.sh

# /data holds everything mutable: auth.json, certs, ipam.db.
ENV NEXUSIPAM_DATA_DIR=/data \
    NEXUSIPAM_NO_SUDO=1

EXPOSE 8444/tcp
VOLUME /data
WORKDIR /opt/nexus-ipam

ENTRYPOINT ["/opt/nexus-ipam/entrypoint.sh"]
