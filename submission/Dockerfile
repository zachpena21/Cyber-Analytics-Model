FROM python:3.11-slim

ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/defender \
    OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1 \
    DF_ENABLE_SCORE_ENDPOINT=0 DF_MAX_SAMPLE_BYTES=16777216 PORT=8080

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
RUN python -c 'from pathlib import Path; import sysconfig; root=Path(sysconfig.get_paths()["purelib"])/"oscrypto"/"_openssl"; old=r"(\d\.\d\.\d[a-z]*)"; new=r"(\d+\.\d+\.\d+[a-z]*)"; files=list(root.glob("_libcrypto_*.py")); assert files; [p.write_text(p.read_text().replace(old,new)) for p in files]'
RUN groupadd --system defender && useradd --system --gid defender --no-create-home defender
COPY app/defender /opt/defender/defender
USER defender
WORKDIR /opt/defender
EXPOSE 8080
CMD ["python", "-m", "defender.submission_main"]
