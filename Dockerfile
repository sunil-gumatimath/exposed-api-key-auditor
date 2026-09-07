FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /opt/auditor

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# Install dependencies first (layer caching) — single pip install from pyproject
COPY pyproject.toml README.md ./
COPY auditor/ ./auditor/
RUN python -m pip install .

RUN addgroup --system app && adduser --system --ingroup app app

RUN mkdir -p /work \
    && chown -R app:app /opt/auditor /work

USER app
WORKDIR /work

ENTRYPOINT ["python", "-m", "auditor"]
CMD ["--help"]
