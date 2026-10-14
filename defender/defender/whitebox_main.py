"""Standalone frozen whitebox entrypoint: t060 plus agreement rescue."""
import hashlib
import json
from pathlib import Path

MODEL_SHA = 'a9e350a04f77ff912486d45f9813b04dd686d5cae6661debd6eed316838d06e5'
EXPECTED_POLICY = dict(name='v8-t060-agreement-rescue-research', reviewer_threshold=.60,
    route_min=.15, adapter_min=.99, base_benign_max=.20, reviewer_min=.30,
    require_adjusted_base_trigger=True, exclude_verified_signatures=True)


def verify_reviewer(raw):
    if hashlib.sha256(raw).hexdigest() != MODEL_SHA:
        raise ValueError('Whitebox reviewer identity differs from the verified candidate')
    payload = json.loads(raw)
    if payload['reviewer_threshold'] != .60 or payload['route_min'] != .15:
        raise ValueError('Whitebox reviewer cascade differs')
    return payload


def main():
    from gevent.pywsgi import WSGIServer
    from defender.apps import create_app
    from defender.models.boundary_reviewer import BoundaryReviewer
    from defender.models.portable_model import PortableModernAdapter
    from defender.models.submission_extractor import install
    from defender.reviewer_rescue import POLICY
    root = Path(__file__).resolve().parent/'models'
    reviewer_path = root/'boundary_reviewer_v8_whitebox_t060/model.json'
    verify_reviewer(reviewer_path.read_bytes())
    if POLICY != EXPECTED_POLICY:
        raise ValueError('Whitebox rescue rule differs from the verified policy')
    model = PortableModernAdapter(root/'compact', root/'modern_adapter')
    if model.adapter_threshold != .7 or model.adapter_metadata['base_benign_threshold'] != .510001:
        raise ValueError('Whitebox upstream policy differs')
    model.boundary_reviewer = BoundaryReviewer(reviewer_path)
    model.reviewer_agreement_rescue = True
    install()
    WSGIServer(('0.0.0.0', 8080), create_app(model, threshold=.510001), log=None).serve_forever()


if __name__ == '__main__':
    main()
