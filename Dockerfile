# VulNova Observatory — production container image.
# Works on any container host (Render, Railway, Fly.io, Koyeb, a VPS, …).
FROM python:3.12-slim

# Keep Python lean and unbuffered for clean container logs.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    # App data (SQLite cache, ExploitDB CSV, Metasploit index) lives under
    # $HOME/.vulnova. Point HOME at /data so it can be backed by a volume.
    HOME=/data \
    # Proactively refresh all sources every 6 hours (0 disables).
    VULNOVA_REFRESH_HOURS=6

WORKDIR /app

# Install the package first (leverages layer caching for deps).
COPY pyproject.toml README.md ./
COPY vulnova ./vulnova
RUN pip install --upgrade pip && pip install .

# Writable data dir (mount a persistent volume here to keep the cache warm).
RUN mkdir -p /data && chmod 777 /data
VOLUME ["/data"]

# The platform provides $PORT; default to 8000 for local runs.
ENV PORT=8000
EXPOSE 8000

# Single worker + threads: I/O-bound workload, and exactly one background
# refresh scheduler. Long timeout because a forced refresh downloads multi-MB
# OSV dumps. Uses the app factory.
CMD gunicorn "vulnova.web.app:create_app()" \
    --bind "0.0.0.0:${PORT}" \
    --workers 1 --threads 8 --timeout 120 \
    --access-logfile - --error-logfile -
