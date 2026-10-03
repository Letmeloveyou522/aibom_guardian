"""Repository CLI exit policy with synthetic results; live evidence is separate."""
import json

import pytest

from aibom_guardian.repository_checker import _cli


@pytest.mark.parametrize('verdict,errors,policy,expected', [
    ('ALLOW', [], 'warning', 0),
    ('WARNING', [], 'warning', 3),
    ('BLOCK', [], 'warning', 2),
    ('ALLOW', [{'code': 'lookup_failed'}], 'warning', 3),
    ('WARNING', [{'code': 'not_found'}], 'warning', 3),
    ('WARNING', [], 'block', 0),
    ('BLOCK', [], 'block', 2),
    ('BLOCK', [], 'never', 0),
    ('WARNING', [{'code': 'not_found'}], 'never', 0),
])
def test_exit_policy_preserves_report(monkeypatch, capsys, verdict, errors, policy, expected):
    report = {'verdict': verdict, 'errors': errors, 'trust_score': 50}
    monkeypatch.setattr(_cli, 'check_repository', lambda *a, **k: report)
    assert _cli.main(['https://github.com/pallets/flask', '--json', '--fail-on', policy]) == expected
    assert json.loads(capsys.readouterr().out) == report


def test_default_rejects_warning(monkeypatch, capsys):
    monkeypatch.setattr(_cli, 'check_repository', lambda *a, **k: {'verdict': 'WARNING'})
    assert _cli.main(['https://github.com/pallets/flask', '--json']) == 3
    assert json.loads(capsys.readouterr().out)['verdict'] == 'WARNING'
