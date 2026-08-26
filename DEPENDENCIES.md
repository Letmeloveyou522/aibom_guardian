# Dependencies

This document lists the runtime and development dependencies used by
AIBOM-Guardian. `pyproject.toml` is the source of truth for installation.
`requirements.txt` contains the same dependencies for development from a
source checkout.

## Runtime dependencies

| Package | Version | Purpose | Used by | License |
|---|---|---|---|---|
| [requests](https://github.com/psf/requests) | >=2.32 | HTTP requests to package registries and external APIs | Package and repository collectors | Apache-2.0 |
| [prettytable](https://github.com/prettytable/prettytable) | >=3.0 | Terminal result tables | `_cli_report.py` | BSD-3-Clause |
| [cyclonedx-bom](https://github.com/CycloneDX/cyclonedx-python) | >=4.0 | CycloneDX SBOM generation | `sbom_generator.py` | Apache-2.0 |
| [mcp](https://github.com/modelcontextprotocol/python-sdk) | 1.28.1 | MCP server implementation | `mcp_server.py` | MIT |
| [huggingface_hub](https://github.com/huggingface/huggingface_hub) | >=0.24,<2.0 | Hugging Face metadata and model files | `model_checker.py` | Apache-2.0 |
| [picklescan](https://github.com/mmaitre314/picklescan) | >=0.0.21 | Static inspection of pickle files | `model_checker.py` | MIT |

`mcp` is pinned to 1.28.1 because the current server imports
`mcp.server.fastmcp`, which is not available in mcp 2.x.

## Development dependencies

| Package | Version | Purpose | License |
|---|---|---|---|
| [pytest](https://github.com/pytest-dev/pytest) | >=8.0 | Test execution | MIT |
| [pyflakes](https://github.com/PyCQA/pyflakes) | >=3.0 | Static checks in CI | MIT |

## External services

| Service | Purpose | Authentication |
|---|---|---|
| OSV | Vulnerability lookup | Not required |
| PyPI | Python package metadata | Not required |
| npm Registry | npm package metadata | Not required |
| GitHub API | Repository information | `GITHUB_TOKEN` optional |
| OpenSSF Scorecard | Repository security signals | Not required |
| Hugging Face Hub | Model metadata and files | `HF_TOKEN` required for gated models |
| Ollama | Optional local result explanation | Local service |
| SPDX License List | License identification data | Not required |
| Blue Oak Council | License classification data | Not required |

SPDX and Blue Oak data are downloaded when needed and cached locally. Set
`AIBOM_GUARDIAN_CACHE` to change the cache directory.

Model Card PII detection in `security_classifiers.py` uses only the Python
standard library and does not add a runtime dependency.

When adding or changing a dependency, update `pyproject.toml`,
`requirements.txt`, and this document together.
