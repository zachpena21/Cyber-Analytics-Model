"""Entrypoint for the black-box malware defense service."""

import logging
import os
from pathlib import Path

from gevent.pywsgi import WSGIServer

from defender.apps import create_app
from defender.models.compact_model import CompactNeedForSpeedModel
from defender.models.modern_adapter import ModernAdapterModel


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOGGER = logging.getLogger(__name__)


def main() -> None:
    model_dir = Path(
        os.getenv(
            "DF_MODEL_DIR",
            Path(__file__).parent / "models" / "compact",
        )
    ).resolve()
    adapter_dir = Path(
        os.getenv(
            "DF_ADAPTER_DIR",
            Path(__file__).parent / "models" / "modern_adapter",
        )
    ).resolve()
    threshold = float(os.getenv("DF_MODEL_THRESH", "0.510001"))
    port = int(os.getenv("PORT", "8080"))

    if not 0.0 <= threshold <= 1.0:
        raise ValueError("DF_MODEL_THRESH must be between 0 and 1")
    if not model_dir.is_dir():
        raise FileNotFoundError(
            f"Compact model not found at {model_dir}. Build it from the verified course model."
        )

    if (adapter_dir / "metadata.json").is_file():
        LOGGER.info(
            "Loading compact model from %s with modern adapter from %s",
            model_dir,
            adapter_dir,
        )
        model = ModernAdapterModel(model_dir, adapter_dir)
        trained_threshold = float(
            model.adapter_metadata["base_benign_threshold"]
        )
        if abs(threshold - trained_threshold) > 1e-12:
            raise ValueError(
                "DF_MODEL_THRESH does not match the threshold used to "
                f"calibrate the adapter ({trained_threshold})"
            )
    else:
        LOGGER.info("Loading compact model from %s (no modern adapter)", model_dir)
        model = CompactNeedForSpeedModel(model_dir)
    app = create_app(model=model, threshold=threshold)
    LOGGER.info("Listening on 0.0.0.0:%d with threshold %.6f", port, threshold)
    WSGIServer(("0.0.0.0", port), app, log=None).serve_forever()


if __name__ == "__main__":
    main()
