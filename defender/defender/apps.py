"""HTTP interface required by the black-box defense challenge."""

import logging
import os
import time

import pandas as pd
from flask import Flask, jsonify, request

from defender.models.attribute_extractor import PEAttributeExtractor
from defender.signature_policy import has_verified_microsoft_signature


LOGGER = logging.getLogger(__name__)
MAX_SAMPLE_BYTES = int(os.getenv("DF_MAX_SAMPLE_BYTES", str(16 * 1024 * 1024)))
MICROSOFT_OVERRIDE_ENABLED = os.getenv(
    "DF_MICROSOFT_OVERRIDE", "1"
).strip().casefold() not in {"0", "false", "no", "off"}
MICROSOFT_OVERRIDE_SCORE = float(os.getenv("DF_MICROSOFT_OVERRIDE_SCORE", "0.51"))
MICROSOFT_OVERRIDE_TOLERANCE = float(
    os.getenv("DF_MICROSOFT_OVERRIDE_TOLERANCE", "0.000000001")
)


def create_app(model, threshold: float) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MODEL=model,
        MODEL_THRESHOLD=threshold,
        MAX_CONTENT_LENGTH=MAX_SAMPLE_BYTES,
        MICROSOFT_OVERRIDE_ENABLED=MICROSOFT_OVERRIDE_ENABLED,
        MICROSOFT_OVERRIDE_SCORE=MICROSOFT_OVERRIDE_SCORE,
        MICROSOFT_OVERRIDE_TOLERANCE=MICROSOFT_OVERRIDE_TOLERANCE,
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
        details = dict(
            name="NFS_21_ALL_hash_50000_WITH_MLSEC20",
            classifier=getattr(
                model,
                "classifier_name",
                type(classifier).__name__ if classifier is not None else "unknown",
            ),
            threshold=app.config["MODEL_THRESHOLD"],
            max_sample_bytes=MAX_SAMPLE_BYTES,
            microsoft_override=app.config["MICROSOFT_OVERRIDE_ENABLED"],
            microsoft_override_score=app.config["MICROSOFT_OVERRIDE_SCORE"],
            modern_adapter=hasattr(model, "predict_components"),
        )
        if hasattr(model, "adapter_threshold"):
            details["adapter_threshold"] = model.adapter_threshold
        return jsonify(**details), 200

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
            model = app.config["MODEL"]
            adapter_triggered = False
            if hasattr(model, "extract_base_components") and hasattr(
                model, "score_adapter"
            ):
                benign_values, features = model.extract_base_components(frame)
                benign_probability = float(benign_values[0])
                base_trigger = (
                    benign_probability < app.config["MODEL_THRESHOLD"]
                )
                if (
                    base_trigger
                    and app.config["MICROSOFT_OVERRIDE_ENABLED"]
                    and abs(
                        benign_probability
                        - app.config["MICROSOFT_OVERRIDE_SCORE"]
                    )
                    <= app.config["MICROSOFT_OVERRIDE_TOLERANCE"]
                    and has_verified_microsoft_signature(bytez)
                ):
                    LOGGER.info(
                        "trusted Microsoft legacy-feature override "
                        "benign_probability=%.9f",
                        benign_probability,
                    )
                    base_trigger = False
                adapter_probability = float(
                    model.score_adapter(features, [base_trigger])[0]
                )
                adapter_triggered = (
                    adapter_probability >= model.adapter_threshold
                )
                result = int(adapter_triggered)
            elif hasattr(model, "predict_components"):
                benign_values, adapter_values = model.predict_components(frame)
                benign_probability = float(benign_values[0])
                adapter_probability = float(adapter_values[0])
                adapter_triggered = (
                    adapter_probability >= model.adapter_threshold
                )
                result = int(adapter_triggered)
            else:
                benign_probability = float(model.predict_proba(frame)[0][0])
                result = int(
                    benign_probability < app.config["MODEL_THRESHOLD"]
                )

            if (
                result == 1
                and not adapter_triggered
                and app.config["MICROSOFT_OVERRIDE_ENABLED"]
                and abs(
                    benign_probability - app.config["MICROSOFT_OVERRIDE_SCORE"]
                )
                <= app.config["MICROSOFT_OVERRIDE_TOLERANCE"]
                and has_verified_microsoft_signature(bytez)
            ):
                LOGGER.info(
                    "trusted Microsoft borderline override benign_probability=%.9f",
                    benign_probability,
                )
                result = 0

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
