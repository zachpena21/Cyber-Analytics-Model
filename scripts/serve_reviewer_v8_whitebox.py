#!/usr/bin/env python3
"""Run only the fixed threshold candidate using the tested v8 image's runtime."""
import argparse
import hashlib
import json
from pathlib import Path

from prepare_reviewer_v8_whitebox import candidate_from_bytes


def checked_candidate(baseline_bytes, candidate_bytes):
    _, expected = candidate_from_bytes(baseline_bytes)
    actual = json.loads(candidate_bytes)
    if actual != expected:
        raise ValueError('Candidate differs from frozen v8 beyond reviewer threshold 0.60')
    return actual


def checked_rescue_proof(raw):
    from evaluate_reviewer_v8_rescue import CACHE_SHA, POLICY
    canonical = raw.replace(b'\r\n', b'\n')
    if hashlib.sha256(canonical).hexdigest() != 'c036f674c2c55583217d2927eaf9e79533f7454231d65245edc25a39c149aae0':
        raise ValueError('Expected verified full-pool rescue proof')
    proof = json.loads(canonical)
    if (proof['policy'] != POLICY or proof['cache_sha256'] != CACHE_SHA
            or not proof['ready_for_runtime_test']
            or proof['full_development_pool']['new_false_positives'] != 0):
        raise ValueError('Rescue policy lacks passing full-pool evidence')
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--model', type=Path, required=True)
    parser.add_argument('--agreement-rescue', action='store_true')
    parser.add_argument('--rescue-proof', type=Path)
    args = parser.parse_args()
    root = Path('/opt/defender/defender/models')
    baseline = root/'boundary_reviewer_v8_final/model.json'
    checked_candidate(baseline.read_bytes(), args.model.read_bytes())
    if args.agreement_rescue:
        if args.rescue_proof is None:
            raise ValueError('Expected verified full-pool rescue proof')
        checked_rescue_proof(args.rescue_proof.read_bytes())
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
    if args.agreement_rescue:
        model.reviewer_agreement_rescue = True
    install()
    WSGIServer(('0.0.0.0', 8080), create_app(model, threshold=.510001), log=None).serve_forever()


if __name__ == '__main__':
    main()
