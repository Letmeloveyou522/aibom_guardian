"""Read npm lockfile v2/v3 inventories without resolving registry versions."""
from collections import deque
import json
from pathlib import Path
from urllib.parse import urlsplit

SECTIONS = ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')


def _dependencies(entry, section):
    value = entry.get(section, {})
    if not isinstance(value, dict) or any(
        not isinstance(k, str) or not k or not isinstance(v, str)
        for k, v in value.items()
    ):
        raise ValueError(f'Invalid lockfile/manifest {section}')
    return value


def _path_name(path):
    if not isinstance(path, str) or not path.startswith('node_modules/'):
        return None
    names = path[len('node_modules/'):].split('/node_modules/')
    for name in names:
        parts = name.split('/')
        if any(p in ('', '.', '..') or '\\' in p for p in parts):
            return None
        if not (len(parts) == 1 and not name.startswith('@') or
                len(parts) == 2 and parts[0].startswith('@') and len(parts[0]) > 1):
            return None
    return names[-1]


def _find_child(packages, parent, name):
    if _path_name(f'node_modules/{name}') != name:
        raise ValueError(f'Invalid dependency name: {name}')
    current = parent
    while True:
        candidate = f'{current}/node_modules/{name}' if current else f'node_modules/{name}'
        if candidate in packages:
            return candidate
        if not current:
            return None
        current = current.rsplit('/node_modules/', 1)[0] if '/node_modules/' in current else ''


def load_lockfile(manifest_path, *, direct_only=False):
    """Return (packages, unscanned, source) or None when no sibling lock exists.

    Never silently fall back to registry resolution for a present invalid lock.
    Local links, aliases and non-public-registry sources remain unscanned.
    """
    from .npm_checker import NpmPackage, _parse_semver

    manifest_path = Path(manifest_path)
    if (manifest_path.parent / 'npm-shrinkwrap.json').exists():
        raise ValueError('npm-shrinkwrap.json takes precedence; this format is not supported yet')
    path = manifest_path.parent / 'package-lock.json'
    if not path.exists():
        return None
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    lock = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        raise ValueError('package.json and package-lock.json must be objects')
    if type(lock.get('lockfileVersion')) is not int or lock['lockfileVersion'] not in (2, 3):
        raise ValueError('Only package-lock.json lockfileVersion 2 and 3 are supported')
    entries = lock.get('packages')
    if not isinstance(entries, dict) or not isinstance(entries.get(''), dict):
        raise ValueError('Lockfile packages must contain the root entry ""')
    root = entries['']
    for section in SECTIONS:
        if _dependencies(manifest, section) != _dependencies(root, section):
            raise ValueError(f'package.json and package-lock.json differ in {section}; update the lockfile')

    unscanned, valid = [], {}
    for install_path, record in entries.items():
        if install_path == '':
            continue
        name = _path_name(install_path)
        if not isinstance(record, dict):
            raise ValueError(f'Invalid lockfile entry: {install_path}')
        version = record.get('version')
        parsed = _parse_semver(version) if isinstance(version, str) else None
        resolved = record.get('resolved', '')
        source_ok = isinstance(resolved, str) and (
            not resolved or (urlsplit(resolved).scheme == 'https' and
                             urlsplit(resolved).hostname == 'registry.npmjs.org'))
        if (not name or record.get('link') or not parsed or parsed.precision != 3
                or record.get('name', name) != name or not source_ok):
            unscanned.append(f'{install_path}: unsupported lockfile path, version, link, alias or source')
            continue
        valid[install_path] = (name, record)

    parents = {p: [] for p in valid}
    children = {p: [] for p in valid}
    depths, roots, root_specs = {}, {}, {}
    for parent_path, record in [('', root), *[(p, r) for p, (_, r) in valid.items()]]:
        sections = SECTIONS if not parent_path else ('dependencies', 'optionalDependencies', 'peerDependencies')
        deps = {}
        for section in sections:
            for name, spec in _dependencies(record, section).items():
                if name not in deps or section == 'optionalDependencies':
                    deps[name] = (spec, section)
        for name, (spec, section) in deps.items():
            search_parent = parent_path
            if section == 'peerDependencies' and parent_path:
                search_parent = (parent_path.rsplit('/node_modules/', 1)[0]
                                 if '/node_modules/' in parent_path else '')
            target = _find_child(entries, search_parent, name)
            peer_meta = record.get('peerDependenciesMeta', {})
            optional_peer = (isinstance(peer_meta, dict) and isinstance(peer_meta.get(name), dict)
                             and peer_meta[name].get('optional'))
            if target is None:
                if section != 'optionalDependencies' and not (section == 'peerDependencies' and optional_peer):
                    unscanned.append(f'{parent_path or "<root>"}: locked dependency {name} is missing')
                continue
            if target not in valid:
                continue
            if not parent_path:
                depths[target] = 0
                roots[target] = section
                root_specs[target] = spec
            else:
                if parent_path not in parents[target]:
                    parents[target].append(parent_path)
                children[parent_path].append(target)
    queue = deque(depths)
    while queue:
        parent = queue.popleft()
        for child in children[parent]:
            if child not in depths:
                depths[child] = depths[parent] + 1
                queue.append(child)

    packages = []
    for install_path, (name, record) in valid.items():
        direct = install_path in roots
        if direct_only and not direct:
            continue
        if install_path not in depths:
            unscanned.append(f'{install_path}: not reachable from declared root dependencies')
        packages.append(NpmPackage(
            name, record['version'], root_specs.get(install_path, record['version']),
            roots.get(install_path, 'devDependencies' if record.get('dev') else 'dependencies'),
            True, direct=direct, depth=depths.get(install_path, -1),
            required_by=tuple(f'{valid[p][0]}@{valid[p][1]["version"]}' for p in parents[install_path]),
            resolution_source='lockfile', installation_path=install_path,
            required_by_paths=tuple(parents[install_path]),
            dependency_paths=tuple(children[install_path]),
        ))
    return packages, unscanned, {'kind': 'package-lock', 'path': str(path),
                                 'lockfile_version': lock['lockfileVersion']}
