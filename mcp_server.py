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
from importlib.metadata import metadata, PackageNotFoundError

# "aibom-guard" is the name the MCP client will show for this server
mcp = FastMCP("aibom-guard")


@mcp.tool()
def check_package(name: str, version: str, ecosystem: str = "PyPI") -> dict:
    """
    Check whether a package (given its name and version) is safe to use.

    Looks up known vulnerabilities via the OSV database and checks the
    license of the installed package against an allowed-license list.
    Returns a Trust Score (0-100) and a verdict: ALLOW, CONDITIONAL, or BLOCK.

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

    score = 100
    if lic_status == "BLOCKED":
        score -= 60
    elif lic_status == "REVIEW":
        score -= 20
    elif lic_status == "UNKNOWN":
        score -= 15

    critical_count = sum(1 for v in vulns if str(v.get("severity", "")).upper() in ("CRITICAL", "HIGH"))
    other_count = len(vulns) - critical_count
    score -= critical_count * 30
    score -= other_count * 10
    score = max(score, 0)

    if score >= 80:
        verdict = "ALLOW"
    elif score >= 50:
        verdict = "CONDITIONAL"
    else:
        verdict = "BLOCK"

    return {
        "package": name,
        "version": version,
        "license_status": lic_status,
        "license_raw": lic_raw,
        "vulnerabilities": vulns,
        "trust_score": score,
        "verdict": verdict,
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