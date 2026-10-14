#!/usr/bin/env python3
"""Run only the fixed threshold candidate using the tested v8 image's runtime."""
import argparse
import json
from pathlib import Path

from prepare_reviewer_v8_whitebox import candidate_from_bytes


def checked_candidate(baseline_bytes, candidate_bytes):
    _, expected = candidate_from_bytes(baseline_bytes)
    actual = json.loads(candidate_bytes)
    if actual != expected:
        raise ValueError('Candidate differs from frozen v8 beyond reviewer threshold 0.60')
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    args = parser.parse_args()
    root = Path('/opt/defender/defender/models')
    baseline = root/'boundary_reviewer_v8_final/model.json'
    checked_candidate(baseline.read_bytes(), args.model.read_bytes())
    # Imports use the tested image, including its LIEF compatibility layer.
    from gevent.pywsgi import WSGIServer
    from defender.apps import create_app
    from defender.models.boundary_reviewer import BoundaryReviewer
    from defender.models.portable_model import PortableModernAdapter
    from defender.models.submission_extractor import install
    model = PortableModernAdapter(root/'compact', root/'modern_adapter')
    if model.adapter_threshold != .7 or model.adapter_metadata['base_benign_threshold'] != .510001:
        raise ValueError('Image upstream policy differs from submitted v8')
    model.boundary_reviewer = BoundaryReviewer(args.model)
    install()
    WSGIServer(('0.0.0.0', 8080), create_app(model, threshold=.510001), log=None).serve_forever()


if __name__ == '__main__':
    main()
