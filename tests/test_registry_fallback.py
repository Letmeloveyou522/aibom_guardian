"""Fault-injection regression tests, separate from live user-flow evidence."""
import json
import os
from unittest.mock import Mock

import pytest
import requests

from aibom_guardian import license_checker as lc


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(lc, '_cache_dir', lambda: tmp_path)
    monkeypatch.setattr(lc, '_OFFLINE', False)
    return tmp_path


@pytest.mark.parametrize('failure', ['connection', 'http', 'json'])
def test_fallback_download_is_cached_and_reusable_offline(cache, monkeypatch, failure):
    payload = {'licenseListVersion': 'test', 'licenses': []}
    primary = Mock()
    if failure == 'http':
        primary.raise_for_status.side_effect = requests.HTTPError('503')
    else:
        primary.json.side_effect = ValueError('invalid JSON')
    mirror = Mock()
    mirror.json.return_value = payload
    get = Mock(side_effect=[requests.ConnectionError('reset')
                           if failure == 'connection' else primary, mirror])
    monkeypatch.setattr(requests, 'get', get)
    args = ('spdx-licenses.json', lc._SPDX_URL)
    assert lc._fetch_registry(*args, fallback_urls=(lc._SPDX_FALLBACK_URL,)) == (
        payload, 'download')
    assert [c.args[0] for c in get.call_args_list] == [lc._SPDX_URL, lc._SPDX_FALLBACK_URL]
    assert json.loads((cache / args[0]).read_text()) == payload
    monkeypatch.setattr(lc, '_OFFLINE', True)
    get.reset_mock()
    assert lc._fetch_registry(*args, fallback_urls=(lc._SPDX_FALLBACK_URL,)) == (
        payload, 'cache')
    get.assert_not_called()


@pytest.mark.parametrize('has_cache', [False, True])
def test_all_origins_fail_without_inventing_registry(cache, monkeypatch, has_cache):
    payload = {'licenses': []}
    if has_cache:
        path = cache / 'spdx-licenses.json'
        path.write_text(json.dumps(payload))
        os.utime(path, (0, 0))
    get = Mock(side_effect=requests.ConnectionError('unreachable'))
    monkeypatch.setattr(requests, 'get', get)
    result = lc._fetch_registry('spdx-licenses.json', lc._SPDX_URL,
                               fallback_urls=(lc._SPDX_FALLBACK_URL,))
    assert result == ((payload, 'stale cache') if has_cache else (None, None))
    assert get.call_count == 2
