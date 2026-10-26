import copy

import pytest

from aibom_guardian.ci_summary import render


def report():
    return {'packages': [{'package': 'demo', 'version': '1.0', 'ecosystem': 'PyPI',
                         'verdict': 'WARNING', 'license_status': 'UNKNOWN',
                         'vulnerabilities': None, 'osv_unverified': True}],
            'unscanned': ['dependency conflict'], 'metadata': {}}


def test_unknown_is_not_zero_or_resolved():
    old = report()
    old['packages'][0].update(vulnerabilities=[{'id': 'GHSA-demo'}], osv_unverified=False)
    new = report()
    text = render(new, old)
    assert 'Unverified vulnerability lookups: 1' in text
    assert '| demo | 1.0 | WARNING | unverified | UNKNOWN |' in text
    assert '| demo | unverified |  |  |' in text
    assert 'GHSA-demo' not in text


def test_renderer_escapes_report_content_and_does_not_mutate():
    data = report()
    data['packages'][0]['package'] = '<script>|[link](url)\n# injected'
    original = copy.deepcopy(data)
    text = render(data)
    assert '<script>' not in text and '\n# injected' not in text
    assert '&#124;' in text and '&#91;' in text
    assert data == original


def test_verified_comparison_and_model_scope():
    old = report()
    old['unscanned'] = []
    old['packages'][0].update(vulnerabilities=[{'id': 'OLD'}], osv_unverified=False)
    new = copy.deepcopy(old)
    new['packages'][0]['vulnerabilities'] = [{'id': 'NEW'}]
    new['models'] = [{'model_id': 'example/model'}]
    text = render(new, old)
    assert '| demo | compared | NEW | OLD |' in text
    assert 'table above covers packages only' in text


@pytest.mark.parametrize('data', [{}, {'packages': [None]}, {'packages': [], 'metadata': []}])
def test_invalid_report_is_rejected(data):
    with pytest.raises(ValueError):
        render(data)
