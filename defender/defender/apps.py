"""HTTP interface required by the black-box defense challenge."""

import logging
import os
import time

import pandas as pd
from flask import Flask, jsonify, request

from defender.models.attribute_extractor import PEAttributeExtractor


LOGGER = logging.getLogger(__name__)
MAX_SAMPLE_BYTES = int(os.getenv("DF_MAX_SAMPLE_BYTES", str(16 * 1024 * 1024)))


def create_app(model, threshold: float) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MODEL=model,
        MODEL_THRESHOLD=threshold,
        MAX_CONTENT_LENGTH=MAX_SAMPLE_BYTES,
    )

    @app.errorhandler(413)
    def too_large(_error):
        return jsonify(error="sample exceeds configured size limit"), 413

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    @app.get("/model")
    def model_info():
        model = app.config["MODEL"]
        classifier = getattr(model, "classifier", None)
        return jsonify(
            name="NFS_21_ALL_hash_50000_WITH_MLSEC20",
            classifier=getattr(
                model,
                "classifier_name",
                type(classifier).__name__ if classifier is not None else "unknown",
            ),
            threshold=app.config["MODEL_THRESHOLD"],
            max_sample_bytes=MAX_SAMPLE_BYTES,
        ), 200

    @app.post("/")
    def predict():
        started = time.perf_counter()
        if request.mimetype != "application/octet-stream":
            return jsonify(error="expecting application/octet-stream"), 400

        bytez = request.get_data(cache=False)
        if not bytez:
            return jsonify(error="empty request body"), 400

        try:
            attributes = PEAttributeExtractor(bytez).extract()
            frame = pd.DataFrame([attributes])
            result = app.config["MODEL"].predict_threshold(
                frame, app.config["MODEL_THRESHOLD"]
            )[0]
            result = int(result)
            if result not in (0, 1):
                raise ValueError(f"model returned invalid label {result!r}")
        except Exception:
            # Malformed PE files and extractor failures fail closed. This avoids
            # treating parser-crash evasions as benign and still returns quickly.
            LOGGER.exception("classification failed; returning malicious verdict")
            result = 1

        LOGGER.info(
            "classified bytes=%d result=%d elapsed_ms=%.1f",
            len(bytez),
            result,
            (time.perf_counter() - started) * 1000,
        )
        return jsonify(result=result), 200

    return app
