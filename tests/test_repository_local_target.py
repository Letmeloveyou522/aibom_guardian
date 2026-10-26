import hashlib

from aibom_guardian.repository_checker import check_repository


def test_local_target_is_hashed_without_duplicate_local_file_argument(tmp_path):
    path = tmp_path / 'payload.bin'
    path.write_bytes(b'local verification fixture')
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    matched = check_repository(str(path), target_type='local', expected_sha256=expected)
    assert matched['provenance_detail']['hash_verified'] is True
    mismatched = check_repository(str(path), target_type='local', expected_sha256='0' * 64)
    assert mismatched['provenance_detail']['hash_verified'] is False
    assert mismatched['verdict'] == 'BLOCK'


def test_explicit_local_file_takes_precedence(tmp_path):
    path = tmp_path / 'payload.bin'
    path.write_bytes(b'explicit file')
    result = check_repository('display label', target_type='local', local_file=str(path),
                              expected_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    assert result['provenance_detail']['hash_verified'] is True
