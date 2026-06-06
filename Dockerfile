FROM nousresearch/hermes-agent:latest

# Build this Railway wrapper as a thin derivative of the official Hermes image.
# Docker Hub's `latest` tag is resolved whenever Railway performs an uncached
# image build. The upstream image already contains the hermes CLI, dashboard
# assets, TUI bundle, Node/npm, Chromium tooling, and s6-overlay PID 1.
USER root

COPY requirements.txt /app/requirements.txt
RUN uv pip install \
      --python /opt/hermes/.venv/bin/python \
      --no-cache \
      -r /app/requirements.txt

RUN mkdir -p /data/.hermes

COPY server.py /app/server.py
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh && \
    chown -R hermes:hermes /app /data /opt/hermes/.venv

# Keep this template's existing Railway volume contract: users mount a Railway
# volume at /data, while Hermes itself reads/writes /data/.hermes.
ENV HOME=/data
ENV HERMES_HOME=/data/.hermes

# This app starts and protects the native dashboard itself via server.py. Leave
# upstream's optional s6 dashboard service disabled to avoid a port collision.
ENV HERMES_DASHBOARD=0

# Inherit the official image entrypoint:
#   ["/init", "/opt/hermes/docker/main-wrapper.sh"]
# The wrapper sees /app/start.sh as an executable and runs it directly as the
# hermes user under s6 supervision.
CMD ["/app/start.sh"]
