"""
Packaging metadata tests.

The dependency list exists twice - `[project].dependencies` for installs and
requirements.txt for clones - so drift between them is a test failure here
rather than something a reader is trusted to notice.
"""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
REQUIREMENTS = ROOT / "requirements.txt"

# tomllib is 3.11+ and the project supports 3.10. Skipping beats adding a
# tomli dependency; CI runs the whole matrix, so drift is still caught.
tomllib = pytest.importorskip("tomllib", reason="tomllib is 3.11+; CI covers this there")


def normalize(requirement: str) -> str:
    """PEP 503 name normalization, so huggingface_hub == huggingface-hub."""
    for separator in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if separator in requirement:
            name, _, rest = requirement.partition(separator)
            return f"{name.strip().lower().replace('_', '-')}{separator}{rest.strip()}"
    return requirement.strip().lower().replace("_", "-")


def read_requirements() -> list[str]:
    entries = []
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(normalize(line))
    return entries


def read_pyproject() -> dict:
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)


def test_runtime_dependencies_match_requirements_txt():
    project = read_pyproject()["project"]
    declared = {normalize(d) for d in project["dependencies"]}
    dev = {normalize(d) for d in project["optional-dependencies"]["dev"]}
    listed = set(read_requirements())

    assert listed == declared | dev, (
        "pyproject.toml and requirements.txt disagree.\n"
        f"  only in requirements.txt: {sorted(listed - (declared | dev))}\n"
        f"  only in pyproject.toml:   {sorted((declared | dev) - listed)}"
    )


def test_mcp_stays_pinned():
    """
    mcp 2.x removed mcp.server.fastmcp, which mcp_server.py imports, so an
    unpinned install produces a server that cannot start. If someone relaxes
    this, they need to have ported the server first.
    """
    dependencies = read_pyproject()["project"]["dependencies"]
    assert "mcp==1.28.1" in dependencies


def test_console_scripts_point_at_real_callables():
    """A typo'd entry point only surfaces after install, which is too late."""
    scripts = read_pyproject()["project"]["scripts"]
    assert scripts["aibom-guardian"] == "aibom_guardian.scanner:main"
    assert scripts["aibom-guardian-mcp"] == "aibom_guardian.mcp_server:main"

    from aibom_guardian import scanner
    from aibom_guardian import mcp_server

    assert callable(scanner.main)
    assert callable(mcp_server.main)


def test_version_is_single_sourced():
    """
    pyproject reads the version from aibom_guardian.__version__. If someone adds
    a static `version =` back, the two can disagree and the wheel ships a lie.
    """
    project = read_pyproject()["project"]
    assert "version" not in project, "version must stay dynamic, not hardcoded"
    assert "version" in project["dynamic"]

    import aibom_guardian

    assert aibom_guardian.__version__.count(".") >= 2


def test_sbom_reports_the_real_tool_version():
    """
    metadata.tools states which tool produced the document, so a hardcoded
    version there would make every SBOM misstate its own provenance.
    """
    import aibom_guardian
    from aibom_guardian import sbom_generator

    assert sbom_generator.AIBOM_GUARDIAN_VERSION == aibom_guardian.__version__

    sbom = sbom_generator.ensure_cyclonedx_metadata({})
    entries = sbom["metadata"]["tools"]["components"]
    ours = [c for c in entries if c["name"] == sbom_generator.AIBOM_GUARDIAN_TOOL_NAME]
    assert ours, "AIBOM-Guardian is missing from metadata.tools"
    assert ours[0]["version"] == aibom_guardian.__version__
