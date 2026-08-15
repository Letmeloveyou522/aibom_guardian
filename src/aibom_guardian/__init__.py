"""
AIBOM-Guardian - security, license and supply-chain scanner for Python packages
and Hugging Face models, with CycloneDX SBOM / ML-BOM output.

Entry points
------------
    aibom-guardian <requirements.txt>      CLI            (aibom_guardian.scanner)
    aibom-guardian-mcp                     MCP server     (aibom_guardian.mcp_server)
    python -m aibom_guardian <req.txt>     same as the CLI

Library use
-----------
    from aibom_guardian import calculate_trust_score, classify_license_detailed

Re-exports resolve lazily. An eager import here would break
``python -m aibom_guardian.license_checker``: runpy imports the parent package
first, so the submodule would already be in sys.modules and runpy would then
run a second copy of it as __main__.
"""

__version__ = "0.1.0"

_LAZY = {
    "calculate_trust_score": "score_engine",
    "classify_license": "license_checker",
    "classify_license_detailed": "license_checker",
    "query_vulnerabilities": "osv_client",
}

__all__ = ["__version__", *sorted(_LAZY)]


def __getattr__(name: str):
    """PEP 562 lazy attribute lookup."""
    module_name = _LAZY.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib

    module = importlib.import_module(f".{module_name}", __name__)
    value = getattr(module, name)
    globals()[name] = value  # later lookups bypass __getattr__
    return value


def __dir__():
    return sorted([*globals(), *_LAZY])
