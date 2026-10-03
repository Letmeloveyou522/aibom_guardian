"""Synthetic lock fixtures for parser regression; live evidence is separate."""
import json

import pytest

from aibom_guardian._npm_lockfile import load_lockfile
from aibom_guardian import npm_checker as npm


def write_lock(tmp_path, version=3):
    manifest = {'dependencies': {'a': '^1.0.0', 'ms': '0.7.1'},
                'devDependencies': {'@scope/b': '2.0.0'}}
    entries = {
        '': manifest,
        'node_modules/a': {'version': '1.0.0', 'dependencies': {'ms': '2.1.2'}},
        'node_modules/ms': {'version': '0.7.1'},
        'node_modules/a/node_modules/ms': {'version': '2.1.2'},
        'node_modules/@scope/b': {'version': '2.0.0', 'dev': True,
                                 'dependencies': {'ms': '0.7.1'}},
    }
    path = tmp_path / 'package.json'
    path.write_text(json.dumps(manifest))
    lock = {'lockfileVersion': version, 'packages': entries}
    (tmp_path / 'package-lock.json').write_text(json.dumps(lock))
    return path, lock


def save(tmp_path, lock):
    (tmp_path / 'package-lock.json').write_text(json.dumps(lock))


@pytest.mark.parametrize('version', [2, 3])
def test_locked_versions_paths_and_hoisted_edges(tmp_path, version):
    path, _ = write_lock(tmp_path, version)
    rows, missing, source = load_lockfile(path)
    assert not missing
    assert source['lockfile_version'] == version
    by_path = {r.installation_path: r for r in rows}
    assert len(rows) == 4
    assert by_path['node_modules/a'].version == '1.0.0'
    assert by_path['node_modules/a'].spec == '^1.0.0'
    assert by_path['node_modules/a/node_modules/ms'].required_by_paths == ('node_modules/a',)
    assert by_path['node_modules/ms'].required_by_paths == ('node_modules/@scope/b',)
    assert by_path['node_modules/@scope/b'].section == 'devDependencies'
    assert all(r.resolution_source == 'lockfile' for r in rows)


def test_same_version_different_paths_kept(tmp_path):
    path, lock = write_lock(tmp_path)
    lock['packages']['node_modules/a/node_modules/ms']['version'] = '0.7.1'
    save(tmp_path, lock)
    rows, _, _ = load_lockfile(path)
    assert len([r for r in rows if r.name == 'ms' and r.version == '0.7.1']) == 2


def test_direct_only(tmp_path):
    path, _ = write_lock(tmp_path)
    rows, missing, _ = load_lockfile(path, direct_only=True)
    assert len(rows) == 3 and all(r.direct for r in rows)
    assert not missing


@pytest.mark.parametrize('version', [1, 4, True, '3'])
def test_unsupported_format_never_falls_back(tmp_path, version):
    path, _ = write_lock(tmp_path, version)
    with pytest.raises(ValueError, match='lockfileVersion'):
        load_lockfile(path)


def test_stale_manifest_rejected(tmp_path):
    path, _ = write_lock(tmp_path)
    path.write_text(json.dumps({'dependencies': {'a': '^2.0.0'}}))
    with pytest.raises(ValueError, match='differ'):
        load_lockfile(path)


@pytest.mark.parametrize('record', [
    {'link': True, 'resolved': '../workspace'},
    {'name': 'another-package', 'version': '1.0.0'},
    {'version': '1.0.0', 'resolved': 'https://private.example/a.tgz'},
    {'version': '1.0'},
])
def test_unsupported_sources_explicitly_unscanned(tmp_path, record):
    path, lock = write_lock(tmp_path)
    lock['packages']['node_modules/a'] = record
    save(tmp_path, lock)
    rows, missing, _ = load_lockfile(path)
    assert all(r.name != 'a' for r in rows)
    assert any('unsupported' in m for m in missing)


def test_missing_required_and_absent_optional(tmp_path):
    path, lock = write_lock(tmp_path)
    a = lock['packages']['node_modules/a']
    a['dependencies']['required'] = '*'
    a['optionalDependencies'] = {'optional': '*'}
    a['peerDependencies'] = {'optional-peer': '*'}
    a['peerDependenciesMeta'] = {'optional-peer': {'optional': True}}
    save(tmp_path, lock)
    _, missing, _ = load_lockfile(path)
    assert len(missing) == 1 and 'required' in missing[0]


def test_shrinkwrap_precedence(tmp_path):
    path, _ = write_lock(tmp_path)
    (tmp_path / 'npm-shrinkwrap.json').write_text('{}')
    with pytest.raises(ValueError, match='takes precedence'):
        load_lockfile(path)


def test_absent_lock_uses_existing_flow(tmp_path):
    assert load_lockfile(tmp_path / 'package.json') is None


def test_offline_scan_uses_lock_without_registry_resolution(tmp_path, monkeypatch):
    path, _ = write_lock(tmp_path)
    for method in ('_npm_versions', '_npm_dependencies'):
        monkeypatch.setattr(npm, method, lambda *a: pytest.fail('lock must not re-resolve'))
    report = tmp_path / 'report.json'
    rows = npm.run_npm_scan(str(path), offline=True, report_path=str(report))
    assert len(rows) == 4
    assert all(r['vulnerabilities'] is None for r in rows)
    data = json.loads(report.read_text())
    assert data['dependency_source']['kind'] == 'package-lock'
    assert data['packages'][0]['installation_path'] == 'node_modules/a'
