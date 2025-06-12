FROM python:3.13.4-alpine3.22 AS builder

ENV PIP_DEFAULT_TIMEOUT=100 \
    # Allow statements and log messages to immediately appear
    PYTHONUNBUFFERED=1 \
    # disable a pip version check to reduce run-time & log-spam
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # cache is useless in docker image, so disable to reduce image size
    PIP_NO_CACHE_DIR=1

# Set WORKDIR
WORKDIR /app

COPY ./requirements.txt .

RUN set -ex \
    # Create a non-root user
    && addgroup --system --gid 1001 appgroup \
    && adduser --system --uid 1001 -G appgroup --no-create-home appuser \
    # Upgrade pip
    && pip install --no-cache-dir --upgrade pip \
    # Build wheels from requirements
    && pip wheel --no-cache-dir --wheel-dir=/wheels -r requirements.txt

COPY . .

RUN set -ex \
    # Install dependencies
    && pip install --no-cache /wheels/* \
    && rm -rf /wheels \
    && pip install . --no-dependencies

RUN chown -R appuser:appgroup /app 
RUN mkdir -p /app/cache
RUN chmod a+w /app/cache

ENTRYPOINT [ "python", "-m", "voltaire_bundler" ]
