FROM python:3.13-slim

# Standard library only; no extra packages
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sgb \
    && mkdir -p /var/log/sgb /control && chown sgb:sgb /var/log/sgb /control

WORKDIR /app
COPY sgb_ui.py .

USER sgb
ENV SGB_BASE_DIR=/data SGB_CONTROL_DIR=/control UI_HOST=0.0.0.0 UI_PORT=8080 BEHIND_PROXY=1 \
    UI_LOG_FILE=/var/log/sgb/sgb_ui.log PYTHONUNBUFFERED=1
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3).status == 200 else 1)"

CMD ["python", "sgb_ui.py"]
