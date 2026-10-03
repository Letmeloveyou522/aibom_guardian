"""Synthetic transport failures, separate from public-model live evidence."""
from unittest.mock import Mock

import httpx
import pytest
import requests

from aibom_guardian import model_checker as model


@pytest.mark.parametrize('failure', [ConnectionResetError('reset'), httpx.ConnectError('reset'),
                                   requests.ConnectionError('reset'), TimeoutError('timeout')])
def test_transport_failure_retries_same_reference(monkeypatch, failure):
    monkeypatch.setattr(model.time, 'sleep', lambda delay: None)
    api = Mock()
    api.model_info.side_effect = [failure, {'sha': 'result'}]
    assert model._model_info_with_retry(api, 'org/model', 'revision') == {'sha': 'result'}
    assert api.model_info.call_count == 2
    assert api.model_info.call_args_list[0] == api.model_info.call_args_list[1]


def test_transport_failure_stops_after_three_attempts(monkeypatch):
    monkeypatch.setattr(model.time, 'sleep', lambda delay: None)
    api = Mock()
    api.model_info.side_effect = ConnectionResetError('reset')
    with pytest.raises(ConnectionResetError):
        model._model_info_with_retry(api, 'org/model', None)
    assert api.model_info.call_count == 3


@pytest.mark.parametrize('status', [401, 403, 404])
def test_http_errors_are_not_retried(status):
    api = Mock()
    response = httpx.Response(status, request=httpx.Request('GET', 'https://example.com'))
    api.model_info.side_effect = httpx.HTTPStatusError('failure', request=response.request, response=response)
    with pytest.raises(httpx.HTTPStatusError):
        model._model_info_with_retry(api, 'org/model', None)
    assert api.model_info.call_count == 1
