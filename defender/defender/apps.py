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
SCORE_ENDPOINT_ENABLED = os.getenv(
    "DF_ENABLE_SCORE_ENDPOINT", "0"
).strip().casefold() in {"1", "true", "yes", "on"}


def create_app(model, threshold: float) -> Flask:
    app = Flask(__name__)
    app.config.update(
        MODEL=model,
        MODEL_THRESHOLD=threshold,
        MAX_CONTENT_LENGTH=MAX_SAMPLE_BYTES,
        MICROSOFT_OVERRIDE_ENABLED=MICROSOFT_OVERRIDE_ENABLED,
        MICROSOFT_OVERRIDE_SCORE=MICROSOFT_OVERRIDE_SCORE,
        MICROSOFT_OVERRIDE_TOLERANCE=MICROSOFT_OVERRIDE_TOLERANCE,
        SCORE_ENDPOINT_ENABLED=SCORE_ENDPOINT_ENABLED,
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
            score_endpoint_enabled=app.config["SCORE_ENDPOINT_ENABLED"],
        )
        if hasattr(model, "adapter_threshold"):
            details["adapter_threshold"] = model.adapter_threshold
        return jsonify(**details), 200

    def score_sample(bytez):
        attributes = PEAttributeExtractor(bytez).extract()
        frame = pd.DataFrame([attributes])
        model = app.config["MODEL"]
        adapter_triggered = False
        adapter_probability = None
        signature_checked = False
        signature_verified = None

        if hasattr(model, "extract_base_components") and hasattr(
            model, "score_adapter"
        ):
            benign_values, features = model.extract_base_components(frame)
            benign_probability = float(benign_values[0])
            raw_base_trigger = (
                benign_probability < app.config["MODEL_THRESHOLD"]
            )
            adjusted_base_trigger = raw_base_trigger
            if (
                raw_base_trigger
                and app.config["MICROSOFT_OVERRIDE_ENABLED"]
                and abs(
                    benign_probability
                    - app.config["MICROSOFT_OVERRIDE_SCORE"]
                )
                <= app.config["MICROSOFT_OVERRIDE_TOLERANCE"]
            ):
                signature_checked = True
                signature_verified = bool(
                    has_verified_microsoft_signature(bytez)
                )
                if signature_verified:
                    LOGGER.info(
                        "trusted Microsoft legacy-feature override "
                        "benign_probability=%.9f",
                        benign_probability,
                    )
                    adjusted_base_trigger = False
            adapter_probability = float(
                model.score_adapter(features, [adjusted_base_trigger])[0]
            )
            adapter_triggered = (
                adapter_probability >= model.adapter_threshold
            )
            result = int(adapter_triggered)
        elif hasattr(model, "predict_components"):
            benign_values, adapter_values = model.predict_components(frame)
            benign_probability = float(benign_values[0])
            adapter_probability = float(adapter_values[0])
            raw_base_trigger = (
                benign_probability < app.config["MODEL_THRESHOLD"]
            )
            adjusted_base_trigger = raw_base_trigger
            adapter_triggered = (
                adapter_probability >= model.adapter_threshold
            )
            result = int(adapter_triggered)
        else:
            benign_probability = float(model.predict_proba(frame)[0][0])
            raw_base_trigger = (
                benign_probability < app.config["MODEL_THRESHOLD"]
            )
            adjusted_base_trigger = raw_base_trigger
            result = int(raw_base_trigger)

        if (
            result == 1
            and not adapter_triggered
            and app.config["MICROSOFT_OVERRIDE_ENABLED"]
            and abs(
                benign_probability - app.config["MICROSOFT_OVERRIDE_SCORE"]
            )
            <= app.config["MICROSOFT_OVERRIDE_TOLERANCE"]
        ):
            signature_checked = True
            signature_verified = bool(
                has_verified_microsoft_signature(bytez)
            )
            if signature_verified:
                LOGGER.info(
                    "trusted Microsoft borderline override "
                    "benign_probability=%.9f",
                    benign_probability,
                )
                result = 0
                adjusted_base_trigger = False

        if result not in (0, 1):
            raise ValueError(f"model returned invalid label {result!r}")
        return {
            "result": result,
            "benign_probability": benign_probability,
            "adapter_probability": adapter_probability,
            "adapter_threshold": getattr(model, "adapter_threshold", None),
            "base_trigger_raw": int(raw_base_trigger),
            "base_trigger_adjusted": int(adjusted_base_trigger),
            "signature_checked": signature_checked,
            "signature_verified": signature_verified,
        }

    def classify_request(include_scores):
        started = time.perf_counter()
        if request.mimetype != "application/octet-stream":
            return jsonify(error="expecting application/octet-stream"), 400

        bytez = request.get_data(cache=False)
        if not bytez:
            return jsonify(error="empty request body"), 400

        try:
            details = score_sample(bytez)
        except Exception:
            # Malformed PE files and extractor failures fail closed. This avoids
            # treating parser-crash evasions as benign and still returns quickly.
            LOGGER.exception("classification failed; returning malicious verdict")
            details = {"result": 1, "error": "classification_failed"}

        LOGGER.info(
            "classified bytes=%d result=%d elapsed_ms=%.1f",
            len(bytez),
            details["result"],
            (time.perf_counter() - started) * 1000,
        )
        if include_scores:
            return jsonify(**details), 200
        return jsonify(result=details["result"]), 200

    @app.post("/")
    def predict():
        return classify_request(include_scores=False)

    @app.post("/diagnostics/score")
    def diagnostic_score():
        if not app.config["SCORE_ENDPOINT_ENABLED"]:
            return jsonify(error="not found"), 404
        return classify_request(include_scores=True)

    return app
