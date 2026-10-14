"""Fixed agreement rescue for the isolated whitebox candidate."""
import math

POLICY = dict(name='v8-t060-agreement-rescue-research', reviewer_threshold=.60,
              route_min=.15, adapter_min=.99, base_benign_max=.20,
              reviewer_min=.30, require_adjusted_base_trigger=True,
              exclude_verified_signatures=True)


def number(value):
    if value in (None, '', False, 'False', 'false'):
        return 0.
    if value in (True, 'True', 'true'):
        return 1.
    value = float(value)
    if not math.isfinite(value):
        raise ValueError('Non-finite numeric input')
    return value


def gates(row):
    adapter, benign = number(row['adapter_probability']), number(row['benign_probability'])
    if not 0 <= adapter <= 1 or not 0 <= benign <= 1:
        raise ValueError('Upstream probability out of range')
    return (adapter >= POLICY['adapter_min'] and benign <= POLICY['base_benign_max']
            and number(row['base_trigger_adjusted']) == 1
            and number(row['signature_verified']) == 0)


def predict(row, score):
    score = number(score)
    if not 0 <= score <= 1:
        raise ValueError('Reviewer score out of range')
    routed = number(row['adapter_probability']) >= POLICY['route_min']
    baseline = int(score >= POLICY['reviewer_threshold']) if routed else int(number(row['adapter_probability']) >= .7)
    rescued = bool(baseline == 0 and routed and score >= POLICY['reviewer_min'] and gates(row))
    return baseline, int(baseline == 1 or rescued), rescued
