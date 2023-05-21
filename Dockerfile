FROM python:3.11.3-alpine3.18

ENV PIP_DEFAULT_TIMEOUT=100 \
    # Allow statements and log messages to immediately appear
    PYTHONUNBUFFERED=1 \
    # disable a pip version check to reduce run-time & log-spam
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # cache is useless in docker image, so disable to reduce image size
    PIP_NO_CACHE_DIR=1

# Set WORKDIR
WORKDIR /app

RUN set -ex \
    # Create a non-root user
    && addgroup --system --gid 1001 appgroup \
    && adduser --system --uid 1001 -G appgroup --no-create-home appuser \
    # Install dependencies
    && pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir "aiohttp==3.8.3" "jsonrpcserver==5.0.9" "uvloop==0.17.0" "eth-abi==4.0.0" "eth-account==0.8.0"

RUN chown -R appuser:appgroup /app

USER appuser

COPY . /app
ENTRYPOINT [ "python", "main.py" ]