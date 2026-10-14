"""Exercise actual cascade handlers with lightweight HTTP/parser test doubles."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'defender'))


class App:
    def __init__(self, name):
        self.config, self.routes = {}, {}

    def route(self, path):
        def decorate(fn):
            self.routes[path] = fn
            return fn
        return decorate

    get = post = errorhandler = route


class Reviewer:
    threshold, route_min, feature_names = .6, .15, ()
    def score(self, *args, **kwargs):
        return .3368946435253518


class Model:
    adapter_threshold, reviewer_agreement_rescue = .7, True
    def __init__(self, benign=.17, adapter=.995939):
        self.benign, self.adapter = benign, adapter
        self.boundary_reviewer = Reviewer()
    def extract_base_components(self, frame):
        return [self.benign], None
    def score_adapter(self, features, triggers):
        return [self.adapter]


class RuntimeTests(unittest.TestCase):
    def test_proof_accepts_windows_newlines_and_rejects_modified_evidence(self):
        from serve_reviewer_v8_whitebox import checked_rescue_proof
        raw = (Path(__file__).resolve().parents[1]/'docs/evidence/phorpiex-rescue-full-pool.json').read_bytes()
        self.assertTrue(checked_rescue_proof(raw.replace(b'\n', b'\r\n'))['ready_for_runtime_test'])
        with self.assertRaises(ValueError):
            checked_rescue_proof(raw + b' ')

    def handlers(self, model, signature=False):
        extractor = types.SimpleNamespace(PEAttributeExtractor=lambda raw: types.SimpleNamespace(extract=lambda: {}))
        flask = types.SimpleNamespace(Flask=App, jsonify=lambda **kw: kw,
            request=types.SimpleNamespace(mimetype='application/octet-stream', args={}, get_data=lambda **kw: b'MZtest'))
        modules = {'flask': flask, 'defender.models.attribute_extractor': extractor,
                   'defender.signature_policy': types.SimpleNamespace(has_verified_microsoft_signature=lambda raw: signature)}
        source = Path(__file__).resolve().parents[1]/'defender/defender/apps.py'
        with patch.dict(sys.modules, modules):
            spec = importlib.util.spec_from_file_location('_rescue_test_apps', source)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            module.SCORE_ENDPOINT_ENABLED = True
            return module.create_app(model, .510001)

    def test_rescue_changes_public_decision_and_preserves_raw_score(self):
        app = self.handlers(Model())
        details, status = app.routes['/diagnostics/score']()
        self.assertEqual(status, 200)
        self.assertEqual(details['result'], 1)
        self.assertTrue(details['reviewer_agreement_rescue_applied'])
        self.assertEqual(details['reviewer_probability'], .3368946435253518)
        self.assertEqual(app.routes['/']()[0], dict(result=1))
        self.assertIn('reviewer_agreement_rescue', app.routes['/model']()[0])

    def test_disabled_policy_preserves_original_response(self):
        model = Model(); model.reviewer_agreement_rescue = False
        app = self.handlers(model)
        details, _ = app.routes['/diagnostics/score']()
        self.assertEqual(details['result'], 0)
        self.assertNotIn('reviewer_agreement_rescue_applied', details)
        self.assertNotIn('reviewer_agreement_rescue', app.routes['/model']()[0])

    def test_benign_and_verified_signature_are_not_rescued(self):
        for model, signature in ((Model(benign=.8), False), (Model(benign=.51), True),
                                 (Model(adapter=.98), False), (Model(adapter=.1), False)):
            details, _ = self.handlers(model, signature).routes['/diagnostics/score']()
            self.assertEqual(details['result'], 0)
            self.assertFalse(details['reviewer_agreement_rescue_applied'])

    def test_wrong_reviewer_policy_is_rejected_at_startup(self):
        model = Model(); model.boundary_reviewer.threshold = .5
        with self.assertRaises(ValueError):
            self.handlers(model)


if __name__ == '__main__':
    unittest.main()
