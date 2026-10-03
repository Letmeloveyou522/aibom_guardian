"""Range-resolution regression checks with explicitly mocked registry I/O."""
import json

import pytest

from aibom_guardian import npm_checker as npm
from aibom_guardian import scanner


@pytest.mark.parametrize('spec,expected', [
    ('^1.0.0', '1.9.0'), ('~1.0.0', '1.0.5'), ('1', '1.9.0'),
    ('1.0', '1.0.5'), ('1.0.0', '1.0.0'), ('>=1.0.0', None),
    ('<1.0.0', None), ('1.0.0 invalid', None),
])
def test_direct_versions_are_resolved_or_explicitly_unscanned(tmp_path, monkeypatch, spec, expected):
    path = tmp_path / 'package.json'
    path.write_text(json.dumps({'dependencies': {'pkg': spec}}))
    monkeypatch.setattr(npm, '_npm_versions', lambda name: ['1.0.0', '1.0.5', '1.9.0', '2.0.0'])
    entries, _ = npm.parse_package_json(str(path))
    resolved, unscanned = npm.resolve_direct_versions(entries)
    if expected is None:
        assert not resolved
        assert len(unscanned) == 1
    else:
        assert resolved[0].version == expected
        assert resolved[0].spec == spec
        assert resolved[0].resolution_source == ('exact' if spec == '1.0.0' else 'registry-range')
        assert not unscanned


def test_offline_ranges_write_evidence_without_scanning_base(tmp_path, monkeypatch):
    path = tmp_path / 'package.json'
    path.write_text(json.dumps({'dependencies': {'pkg': '^1.0.0'}}))
    report = tmp_path / 'report.json'
    monkeypatch.setattr(npm, '_npm_versions', lambda *a: pytest.fail('offline network call'))
    monkeypatch.setattr(npm, '_scan_one_package', lambda *a, **k: pytest.fail('base scanned'))
    assert scanner.main(['--npm', str(path), '--offline', '--no-explain', '--json', str(report)]) == 1
    data = json.loads(report.read_text())
    assert data['packages'] == []
    assert 'offline' in data['unscanned'][0]


def test_failed_lookup_never_scans_the_range_base(tmp_path, monkeypatch):
    path = tmp_path / 'package.json'
    path.write_text(json.dumps({'dependencies': {'pkg': '^1.0.0'}}))
    report = tmp_path / 'report.json'
    monkeypatch.setattr(npm, '_npm_versions', lambda name: [])
    monkeypatch.setattr(npm, '_scan_one_package', lambda *a, **k: pytest.fail('base scanned'))
    assert scanner.main(['--npm', str(path), '--no-explain', '--json', str(report)]) == 1
    assert 'lookup failed' in json.loads(report.read_text())['unscanned'][0]


@pytest.mark.parametrize('spec,version,expected', [
    ('^1.0.0', '1.1.0-beta.1', False),
    ('~1.0.0', '1.0.1-beta.1', False),
    ('^1.0.0-beta.1', '1.0.0-beta.2', True),
    ('^1.0.0-beta.1', '1.1.0-beta.1', False),
    ('^1.0.0-beta.1', '1.1.0', True),
    ('^1.0.0 || ^2.0.0-beta.1', '1.1.0-beta.1', False),
])
def test_prerelease_opt_in_is_specific_to_version_tuple(spec, version, expected):
    assert npm._npm_spec_matches(spec, version) is expected


def test_stable_range_does_not_fall_back_to_prerelease(monkeypatch):
    monkeypatch.setattr(npm, '_npm_versions', lambda name: ['1.1.0-beta.1'])
    assert npm._resolve_npm_range('pkg', '^1.0.0') is None
