# Open Source Libraries Used

This document lists the external open source libraries used in the
AIBOM-Guard project, along with their licenses. (For Article 8 compliance)

| Library | Purpose | GitHub | License |
|---|---|---|---|
| cyclonedx-bom / cyclonedx-python-lib | Generate CycloneDX-format SBOM | https://github.com/CycloneDX/cyclonedx-python | Apache-2.0 |
| pip-licenses | Check licenses of installed packages | https://github.com/raimon49/pip-licenses | MIT |
| requests | HTTP calls to OSV / GitHub / OpenSSF / Hugging Face APIs | https://github.com/psf/requests | Apache-2.0 |
| prettytable | Print result tables in the terminal | https://github.com/prettytable/prettytable | BSD-3-Clause |

## External APIs (not a library, for reference)
| Service | Purpose | License / Terms |
|---|---|---|
| OSV API (api.osv.dev) | Query known vulnerabilities (CVEs, etc.) | Run by Google, free public API, Apache-2.0 (per osv-scanner) |
| GitHub REST API (api.github.com) | Repository trust signals (stars, commits, releases, contributors) | Free public API; authenticated requests recommended (GITHUB_TOKEN) |
| OpenSSF Scorecard API (api.securityscorecards.dev) | Security scorecard for GitHub repositories | CDLA Permissive 2.0 |
| PyPI JSON API (pypi.org/pypi) | Resolve package project URLs / published digests / signature hints | Free public API |
| Hugging Face Hub API (huggingface.co/api/datasets) | Dataset license / source / collection metadata | Free public API |

> Whenever you add a new library, add its name / GitHub link / license to this table.
