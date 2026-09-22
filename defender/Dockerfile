FROM python:3.9-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/tmp/app"

RUN python -m venv /opt/venv
COPY docker-requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY defender /tmp/app/defender
COPY convert_model.py /tmp/app/convert_model.py
RUN python /tmp/app/convert_model.py \
      --input /tmp/app/defender/models/NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl.gz \
      --output /tmp/app/defender/models/compact \
    && rm /tmp/app/defender/models/NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl.gz


FROM python:3.9-slim

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/opt/defender" \
    PYTHONUNBUFFERED=1 \
    DF_MODEL_DIR="/opt/defender/defender/models/compact" \
    DF_MODEL_THRESH="0.75" \
    DF_MAX_SAMPLE_BYTES="16777216" \
    PORT="8080"

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system defender \
    && useradd --system --gid defender --no-create-home defender

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder --chown=defender:defender /tmp/app/defender /opt/defender/defender

USER defender
WORKDIR /opt/defender
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=2s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=1)" || exit 1

CMD ["python", "-m", "defender"]
