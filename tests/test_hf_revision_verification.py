"""Mocked Hub responses; real dataset evidence is stored separately."""
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import quote

import pytest

from aibom_guardian.repository_checker import RepositoryChecker


@pytest.mark.parametrize('kind', ['hf_model', 'hf_dataset'])
@pytest.mark.parametrize('revision,returned,status,verified,pinned', [
    ('a' * 40, 'a' * 40, 200, True, True),
    ('main', 'a' * 40, 200, True, False),
    ('refs/pr/1', 'a' * 40, 200, True, False),
    ('0' * 40, None, 404, False, False),
    ('a' * 40, 'b' * 40, 200, False, False),
    ('a' * 40, 'short', 200, False, False),
])
def test_hf_revision_evidence_survives_provenance_merge(monkeypatch, kind, revision, returned, status, verified, pinned):
    checker = RepositoryChecker()
    get = Mock(return_value=({'sha': returned, 'cardData': {'license': 'mit'}, 'siblings': []},
                             SimpleNamespace(status_code=status), None))
    read = Mock(return_value=('# Dataset card\n', SimpleNamespace(status_code=200), None))
    monkeypatch.setattr(checker.http, 'get_json', get)
    monkeypatch.setattr(checker.http, 'get_text', read)
    result = checker.check('org/repo', target_type=kind, revision=revision)
    url = get.call_args.args[0]
    assert url.endswith('/revision/' + quote(revision, safe=''))
    assert 'params' not in get.call_args.kwargs
    provenance = result['provenance_detail']
    assert provenance['revision_verified'] is verified
    assert provenance['revision_pinned'] is pinned
    assert provenance['resolved_revision'] == (returned if verified else None)
    assert bool(result['errors']) is not verified
    if verified:
        assert '/raw/' + returned + '/README.md' in read.call_args.args[0]
    if status == 404:
        read.assert_not_called()
