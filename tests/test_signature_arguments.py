from unittest.mock import patch
from types import SimpleNamespace

import pytest

from aibom_guardian.repository_checker import RepositoryChecker


@pytest.mark.parametrize('key,identity,issuer,expected', [
    ('public.pem', None, None, ['--key', 'public.pem']),
    (None, 'reviewer@example.test', 'https://issuer.example.test',
     ['--certificate-identity', 'reviewer@example.test', '--certificate-oidc-issuer', 'https://issuer.example.test']),
])
def test_bundle_keeps_requested_verification_constraints(key, identity, issuer, expected):
    with patch('aibom_guardian.repository_checker.shutil.which', return_value='cosign'):
        with patch('aibom_guardian.repository_checker.subprocess.run',
                   return_value=SimpleNamespace(returncode=0, stdout='Verified OK', stderr='')) as call:
            result = RepositoryChecker()._verify_cosign(
                local_file='artifact.bin', signature_file=None, signature_bundle='bundle.json',
                signature_key=key, certificate_identity=identity, certificate_oidc_issuer=issuer)
    assert result[0] is True
    assert call.call_args.args[0] == ['cosign', 'verify-blob', 'artifact.bin', '--bundle', 'bundle.json', *expected]
