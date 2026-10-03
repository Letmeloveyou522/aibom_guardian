"""Synthetic GitHub responses for revision verification and score propagation."""
from types import SimpleNamespace

import pytest

from aibom_guardian.repository_checker import RepositoryChecker


@pytest.mark.parametrize('revision,status,sha,verified,pinned', [
    ('a' * 40, 200, 'a' * 40, True, True),
    ('A' * 40, 200, 'a' * 40, True, True),
    ('a' * 40, 422, None, False, False),
    ('a' * 40, 404, None, False, False),
    ('a' * 40, 200, 'b' * 40, False, False),
    ('a' * 40, 200, 'short', False, False),
    ('main', 200, 'a' * 40, True, False),
    ('feature/test', 200, 'a' * 40, True, False),
])
def test_resolved_commit_controls_pin(monkeypatch, revision, status, sha, verified, pinned):
    checker = RepositoryChecker()
    monkeypatch.setattr(checker, '_resolve_maintainers', lambda *a: (None, 'unknown', []))
    monkeypatch.setattr(checker, 'check_openssf_scorecard', lambda *a: {'available': False})
    urls = []

    def get(url, **kwargs):
        urls.append(url)
        if '/commits/' in url:
            return {'sha': sha}, SimpleNamespace(status_code=status), None
        return {}, SimpleNamespace(status_code=200), None

    monkeypatch.setattr(checker.http, 'get_json', get)
    result = checker.check('https://github.com/o/r', revision=revision)
    detail = result['provenance_detail']
    assert detail['revision_verified'] is verified
    assert detail['revision_pinned'] is pinned
    assert detail['resolved_revision'] == (sha if verified else None)
    assert bool(result['errors']) is not verified
    if '/' in revision:
        assert any('/commits/feature%2Ftest' in u for u in urls)


def test_transport_failure_cannot_grant_pin(monkeypatch):
    checker = RepositoryChecker()
    monkeypatch.setattr(checker.http, 'get_json', lambda *a, **k: (
        None, None, {'code': 'network', 'detail': 'synthetic failure', 'retryable': True}))
    result = checker.check('https://github.com/o/r', revision='a' * 40)
    assert result['errors']
    assert result['provenance_detail']['revision_pinned'] is False
    assert result['provenance_detail']['resolved_revision'] is None
