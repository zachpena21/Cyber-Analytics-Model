import unittest
import evaluate_reviewer_v8_rescue as rescue


class RescueTests(unittest.TestCase):
    def row(self, **kwargs):
        return dict(adapter_probability=.99, benign_probability=.2,
                    base_trigger_adjusted=1, signature_verified=False, **kwargs)

    def test_rescue_requires_all_conditions(self):
        row = self.row()
        self.assertEqual(rescue.predict(row, .3), (0, 1, True))
        for field, value in [('adapter_probability', .9899), ('benign_probability', .2001),
                             ('base_trigger_adjusted', 0), ('signature_verified', True)]:
            changed = dict(row); changed[field] = value
            self.assertEqual(rescue.predict(changed, .3), (0, 0, False))
        self.assertEqual(rescue.predict(row, .2999), (0, 0, False))

    def test_never_reverses_a_detection(self):
        for adapter in (0., .1499, .15, .7, .99, 1.):
            for score in (0., .2999, .3, .5999, .6, 1.):
                r = self.row(); r['adapter_probability'] = adapter
                before, after, _ = rescue.predict(r, score)
                self.assertGreaterEqual(after, before)

    def test_benign_rescue_is_recorded_as_regression(self):
        row = self.row(sha256='a', label=0, score=.4)
        result = rescue.summarize([row])
        self.assertFalse(result['no_new_false_positives'])
        self.assertEqual(result['new_false_positives'], 1)

    def test_nonfinite_and_invalid_probabilities_rejected(self):
        with self.assertRaises(ValueError):
            rescue.predict(self.row(), float('nan'))
        row = self.row(); row['adapter_probability'] = 2
        with self.assertRaises(ValueError):
            rescue.gates(row)


if __name__ == '__main__':
    unittest.main()
