# Open Source Libraries Used

This document lists the external open source libraries used in the
AIBOM-Guardian project, along with their licenses. (For Article 8 compliance)

Every entry below is actually imported or invoked by the code. The canonical
install list is `[project].dependencies` in `pyproject.toml`;
`requirements.txt` mirrors it for installs from a clone, and
`tests/test_packaging.py` fails if the two drift apart.

The "Used by" column names modules under `src/aibom_guardian/`.

## Runtime

| Library | Purpose | Used by | GitHub | License |
|---|---|---|---|---|
| requests | HTTP calls to the OSV, PyPI, npm registry and GitHub APIs | `osv_client.py`, `repository_checker.py`, `recommendation.py`, `npm_checker.py`, `ai_explainer.py` | https://github.com/psf/requests | Apache-2.0 |
| prettytable | Print result tables in the terminal | `scanner.py` | https://github.com/prettytable/prettytable | BSD-3-Clause |
| cyclonedx-bom / cyclonedx-python-lib | Generate the base CycloneDX SBOM (`cyclonedx-py` CLI) | `sbom_generator.py` | https://github.com/CycloneDX/cyclonedx-python | Apache-2.0 |
| mcp (pinned `==1.28.1`) | Expose tools to Claude Desktop / Cursor via Model Context Protocol | `mcp_server.py` | https://github.com/modelcontextprotocol/python-sdk | MIT |
| huggingface_hub | Read Hugging Face model metadata and download model files | `model_checker.py` | https://github.com/huggingface/huggingface_hub | Apache-2.0 |
| picklescan | Detect dangerous opcodes / globals inside pickle weight files | `model_checker.py` | https://github.com/mmaitre314/picklescan | MIT |

> `mcp` is pinned to 1.28.1 on purpose: mcp 2.x removed `mcp.server.fastmcp`,
> which `mcp_server.py` imports, so an unpinned install breaks the server.

## Development only

| Library | Purpose | GitHub | License |
|---|---|---|---|
| pytest | Unit test runner | https://github.com/pytest-dev/pytest | MIT |
| pyflakes | CI lint: reports names that do not resolve | https://github.com/PyCQA/pyflakes | MIT |

## External APIs (not libraries, for reference)

| Service | Purpose | Terms |
|---|---|---|
| OSV API (api.osv.dev) | Known vulnerabilities (CVE/GHSA/PYSEC) | Run by Google, free public API, no key required |
| PyPI JSON API (pypi.org) | Package existence, yanked releases, latest version | Free public API, no key required |
| npm registry (registry.npmjs.org) | npm package versions, dependencies, license fields | Free public API, no key required |
| GitHub REST API (api.github.com) | Repository activity, maintainers, releases | Free; `GITHUB_TOKEN` recommended to avoid rate limits |
| OpenSSF Scorecard API (api.securityscorecards.dev) | Repository security posture score | Run by OpenSSF, free public API |
| Hugging Face Hub API (huggingface.co/api) | Model metadata, file lists, model files | Free public API; gated repos need `HF_TOKEN` and license acceptance |
| Ollama (localhost:11434) | Optional local LLM explanation | Runs on the user's own machine; no data leaves it |
| SPDX License List (spdx.org/licenses/licenses.json) | License identification | Free public file; downloaded on first use and cached locally |
| Blue Oak Council License List (blueoakcouncil.org/list.json) | Permissiveness ratings for licenses OSI never reviewed | Free public file; their terms permit automating access to it |

> Neither list is vendored into this repository. Blue Oak's terms allow
> automating *access* to the JSON files but say nothing about redistributing
> them, and neither SPDX data repository declares a license for the list
> itself. Both are fetched on first use and cached under
> `~/.cache/aibom-guardian/registries` (`%LOCALAPPDATA%` on Windows).

> Model-card PII detection (`security_classifiers.py`) uses only the Python
> standard library (`re`); it adds no extra runtime dependency.

> Whenever you add a new library, add its name / purpose / GitHub link /
> license to the tables above and to `requirements.txt`.

## Removed

`pip-licenses` was listed here previously but no module imports it - license
classification is done in `license_checker.py` against
`importlib.metadata`. It was removed rather than left in an Article 8
declaration that the code does not match.
