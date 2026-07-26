"""
mcp_server.py
-----------------------------------
Exposes AIBOM-Guard's scanning logic as an MCP (Model Context Protocol)
server, so AI agents/clients (e.g. Claude Desktop, Cursor) can call it
directly - for example, asking "is package X version Y safe to use?"
and getting back a real answer backed by OSV + license checks.

This file doesn't reimplement anything - it just wraps the functions
we already built in license_checker.py and osv_client.py as MCP tools.

Run it directly to start the server:
    python3 mcp_server.py
"""

from mcp.server.fastmcp import FastMCP

from osv_client import query_vulnerabilities
from license_checker import classify_license
from score_engine import calculate_trust_score
from importlib.metadata import metadata, PackageNotFoundError


def _vulns_to_issues(vulns: list) -> list:
    """OSV 취약점 목록을 score_engine이 기대하는 issues 형식으로 변환."""
    issues = []
    for v in vulns:
        sev = str(v.get("severity", "unknown")).lower()
        if sev not in ("critical", "high", "medium", "low"):
            sev = "unknown"
        issues.append({
            "type": "cve",
            "id": v.get("id"),
            "severity": sev,
            "summary": v.get("summary"),
        })
    return issues


def _build_check_result(license_status: str, vulns: list) -> dict:
    """score_engine.calculate_trust_score() 입력 스키마에 맞게 조립."""
    return {
        "type": "library",
        "license_status": license_status,
        "issues": _vulns_to_issues(vulns),
        "model_info": None,
        "repository_info": None,
    }

# "aibom-guard" is the name the MCP client will show for this server
mcp = FastMCP("aibom-guard")


@mcp.tool()
def check_package(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    Check whether a package (given its name and version) is safe to use.

    Looks up known vulnerabilities via the OSV database and checks the
    license of the installed package against an allowed-license list.
    Returns a Trust Score (0-100) and a verdict: ALLOW, WARNING, or BLOCK.

    Args:
        name: Package name, e.g. "requests"
        version: Package version, e.g. "2.28.0"
        ecosystem: Package ecosystem, e.g. "PyPI" or "npm" (default: PyPI)
    """
    vulns = query_vulnerabilities(name, version, ecosystem)

    try:
        meta = metadata(name)
        lic_raw = meta.get("License", "") or "UNKNOWN"
    except PackageNotFoundError:
        lic_raw = "NOT_INSTALLED"

    lic_status = classify_license(lic_raw)
    score_result = calculate_trust_score(_build_check_result(lic_status, vulns))

    return {
        "package": name,
        "version": version,
        "license_status": lic_status,
        "license_raw": lic_raw,
        "vulnerabilities": vulns,
        "trust_score": score_result["trust_score"],
        "verdict": score_result["verdict"],
        "hard_block": score_result["hard_block"],
        "hard_block_reasons": score_result["hard_block_reasons"],
        "score_breakdown": score_result["breakdown"],
    }


@mcp.tool()
def check_license(license_string: str) -> str:
    """
    Classify a license string as ALLOWED, REVIEW, BLOCKED, or UNKNOWN,
    based on the competition's open-source license policy (only
    OSI-approved, non-restrictive licenses are ALLOWED).

    Args:
        license_string: A license name, e.g. "MIT" or "GPL-3.0"
    """
    return classify_license(license_string)


if __name__ == "__main__":
    # This starts the MCP server using stdio transport, which is what
    # Claude Desktop / Cursor expect for locally-run MCP servers.
    mcp.run()