FROM python:3.9-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/tmp/app"

RUN python -m venv /opt/venv
COPY docker-requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
# oscrypto 1.3.0 assumes one-digit OpenSSL version components. Debian's
# current libcrypto reports multi-digit patch versions, so widen only that
# parser before Signify is imported. See wbond/oscrypto issue #78.
RUN python -c 'from pathlib import Path; root=Path("/opt/venv/lib/python3.9/site-packages/oscrypto/_openssl"); old=r"(\\d\\.\\d\\.\\d[a-z]*)"; new=r"(\\d+\\.\\d+\\.\\d+[a-z]*)"; files=list(root.glob("_libcrypto_*.py")); assert files and all(old in p.read_text() for p in files); [p.write_text(p.read_text().replace(old, new)) for p in files]'

COPY defender /tmp/app/defender
# The v4 reviewer model is stored as compressed/base64 chunks so it can be
# versioned through the repository connector. Reconstruct and validate the
# exact JSON artifact during the image build.
RUN python -c 'from pathlib import Path; import base64,gzip,json; p=Path("/tmp/app/defender/models/boundary_reviewer_v4_candidate"); parts=sorted(p.glob("model.json.pygzip.b64.part-*")); assert len(parts)==5, "expected 5 reviewer v4 payload parts"; raw=gzip.decompress(base64.b64decode("".join(x.read_text() for x in parts))); obj=json.loads(raw); assert len(obj["estimators"])==192, "unexpected reviewer v4 tree count"; (p/"model.json").write_bytes(raw)'
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
    DF_MODEL_THRESH="0.510001" \
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
