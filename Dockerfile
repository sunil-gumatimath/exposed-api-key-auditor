FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/auditor

RUN addgroup --system app && adduser --system --ingroup app app

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY auditor.py README.md ./

RUN mkdir -p /work \
    && chown -R app:app /opt/auditor /work
USER app
WORKDIR /work

ENTRYPOINT ["python", "/opt/auditor/auditor.py"]
CMD ["--help"]
