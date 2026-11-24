FROM python:3.13-slim

# tzdata: log times and Lite windows are computed in the configured TZ
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sgb \
    && mkdir /data && chown sgb:sgb /data

WORKDIR /app
# Standard library only: no pip install, no PyPI access needed at build time
COPY sgb_sync.py .

USER sgb
ENV SGB_BASE_DIR=/data PYTHONUNBUFFERED=1
VOLUME ["/data"]

# "unhealthy" if the last successful sync (status.json) is older than HEALTH_MAX_AGE_MINUTES.
# The first full scan takes ~10-30 min, hence the 60 min grace period at start.
HEALTHCHECK --interval=5m --timeout=10s --start-period=60m --retries=1 \
    CMD python -c "import os,sys,time; p='/data/status.json'; m=int(os.environ.get('HEALTH_MAX_AGE_MINUTES','150')); sys.exit(0 if os.path.exists(p) and time.time()-os.path.getmtime(p) < m*60 else 1)"

CMD ["python", "sgb_sync.py"]
