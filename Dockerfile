FROM python:3.11.2-alpine3.17
# Configure Poetry
ENV POETRY_VERSION=1.3.1
ENV POETRY_HOME=/opt/poetry
ENV POETRY_VENV=/opt/poetry-venv
ENV POETRY_CACHE_DIR=/opt/.cache

# Install poetry separated from system interpreter
RUN python3 -m venv $POETRY_VENV \
    && $POETRY_VENV/bin/pip install -U pip setuptools \
    && $POETRY_VENV/bin/pip install poetry==${POETRY_VERSION}

# Add `poetry` to PATH
ENV PATH="${PATH}:${POETRY_VENV}/bin"

# Set WORKDIR
WORKDIR /app

# Install dependencies
RUN apk add python3-dev libc-dev gcc
COPY poetry.lock pyproject.toml ./
RUN poetry install

# Run your app
COPY . /app
ENTRYPOINT [ "poetry", "run", "python", "main.py" ]