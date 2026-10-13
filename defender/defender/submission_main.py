"""Final v8 entrypoint, retaining the established HTTP and routing policy."""
import hashlib
import logging
import os
from pathlib import Path
from gevent.pywsgi import WSGIServer
from defender.apps import create_app
from defender.models.boundary_reviewer import BoundaryReviewer
from defender.models.portable_model import PortableModernAdapter
from defender.models.submission_extractor import install as install_extractor


def main():
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    root=Path('/opt/defender/defender/models')
    reviewer_path=root/'boundary_reviewer_v8_final/model.json'
    if hashlib.sha256(reviewer_path.read_bytes()).hexdigest()!='6dbe19e2f0962b4797ee5f58e17a37511b16dae94385253394e8f1add1df78be':
        raise ValueError('Final reviewer weights changed')
    model=PortableModernAdapter(root/'compact',root/'modern_adapter')
    if model.adapter_threshold!=.7 or model.adapter_metadata['base_benign_threshold']!=.510001:
        raise ValueError('Final upstream policy changed')
    model.boundary_reviewer=BoundaryReviewer(reviewer_path)
    install_extractor()
    app=create_app(model,threshold=.510001)
    WSGIServer(('0.0.0.0',8080),app,log=None).serve_forever()


if __name__=='__main__':main()
