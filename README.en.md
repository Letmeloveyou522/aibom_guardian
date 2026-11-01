# AIBOM Guardian

[![CI](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

## Inspect package and AI model supply-chain risks together

AIBOM Guardian checks **Python/npm dependencies and Hugging Face models** for known
vulnerabilities, license issues and model-file risk signals. It preserves evidence and
unverified states, supports CLI/CI/MCP workflows, produces CycloneDX 1.6 SBOM/ML-BOM output,
and tracks changes in a registered inventory with optional Slack notifications.

[Demo](#demo) · [Validation](#validation) · [Quick start](#quick-start) · [Detailed usage](docs/usage.en.md) · [Monitoring](docs/monitoring.en.md) · [한국어](README.md)

## Problem and contribution

Adopting an AI application requires reviewing software dependencies alongside model licenses,
weight formats, remote-code settings and provenance. Evidence from different checks needs to
be assembled, incomplete lookups kept visible, and newly reported risks followed over time.

Guardian connects **pre-adoption checks → evidence-based review → BOM records → change monitoring**.
`ALLOW`, `WARNING` and `BLOCK` support review and CI policy; they do not certify safety.

| Project implementation | Result for the developer | Code |
|---|---|---|
| Dependency parsing and collection | Python transitive dependencies/extras, npm lockfile versions/paths, explicit unscanned inputs | [`_requirements.py`](src/aibom_guardian/_requirements.py), [`npm_checker.py`](src/aibom_guardian/npm_checker.py) |
| Shared policy engine | Consistent scoring rules across CLI and MCP, with evidence confidence separate from risk | [`_adapters.py`](src/aibom_guardian/_adapters.py), [`score_engine.py`](src/aibom_guardian/score_engine.py) |
| Package and model BOM records | Model commits, formats, licenses and available base-model/dataset references alongside findings | [`model_checker.py`](src/aibom_guardian/model_checker.py), [`sbom_generator.py`](src/aibom_guardian/sbom_generator.py) |
| Persistent monitoring | Fixed-version rechecks, change events, SQLite history and a Slack retry queue | [`monitoring.py`](src/aibom_guardian/monitoring.py), [`notifications.py`](src/aibom_guardian/notifications.py) |

External sources and tools include **OSV, PyPI, npm, Hugging Face, SPDX, Blue Oak, picklescan,
OpenSSF Scorecard and cosign**. Guardian implements the collection, normalization, policy
decisions and workflow integration around that evidence. [Dependencies and licenses](DEPENDENCIES.md)

## Demo

<p align="center">
  <img width="413" height="244" alt="Python package scan" src="https://github.com/user-attachments/assets/04687cd8-a9d0-4e9a-ab9d-227aa1933746" />
  <img width="410" height="295" alt="AI model scan" src="https://github.com/user-attachments/assets/bb46e442-a08f-4857-99f2-758f0134d9b0" />
</p>

<p align="center">
  <sub>Example Python package and AI model results</sub>
</p>


Screenshots are example runs. Live advisory counts and verdicts can change with upstream data.

| Input | Inspect | Next action |
|---|---|---|
| [`sample-requirements.txt`](examples/sample-requirements.txt) | Deliberately old versions, transitive findings and license evidence | Recheck candidate versions and test the application |
| Same input plus `--model sshleifer/tiny-gpt2` | Package/model results, file formats, license and resolved commit | Review unverified evidence; enable pickle content scanning when needed |
| A registered scan report | New advisory observations, metadata changes and lookup failures/recovery | Review Slack summaries and saved history |

After installation:

```bash
aibom-guardian examples/sample-requirements.txt --model sshleifer/tiny-gpt2 --no-explain
```

Output is displayed in the terminal and saved as `scan_report.json` and `sbom.json`.
[Example JSON](examples/scan_report.sample.json) · [Example BOM](examples/sbom.sample.json)

For an offline policy demonstration, run `python examples/demo_scenarios.py --compact`.
Its default mode uses **synthetic model reports and mocked PyPI responses**, not live malware experiments.

## Validation

Verification snapshot: **2026-11-01, working tree based on `4fec520` with the demo import fix and regression test**.
See the [validation record](docs/validation.md) for commands, environment and limits.

| Check | Observed result | Evidence |
|---|---|---|
| Automated tests | 1,052 passed, including 44 monitoring/Slack tests | [Summary](docs/evidence/verification-2026-11-01.json), [tests](tests/) |
| Live Slack integration | One synthetic change delivered through a real webhook; success response, history and no repeat delivery on the next check verified | [Integration record](docs/evidence/verification-2026-11-01.json) |
| Windows scheduled check | Seven packages and one model rechecked successfully; no lookup failures; last task exit code 0 | [Validation scope](docs/validation.md#실제-연동-확인) |
| CI configuration | Python 3.10–3.13 tests, static checks, packaging and an offline CLI smoke test configured | [Workflow](.github/workflows/ci.yml), [runs](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml) |

Passing tests establish implementation behavior, **not real-world detection accuracy or external score validity**.
Reboot recovery, long-running operation and evaluation against independently labelled data remain unverified.

## Quick start

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian
python -m venv .venv
```

Activate the environment with the command for your shell:

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# macOS / Linux
source .venv/bin/activate
# Windows cmd: .venv\Scripts\activate.bat
```

Install the tool and scan the included example. Repeat installation after updating the checkout.

```bash
python -m pip install .
aibom-guardian examples/sample-requirements.txt --no-explain
```

You do not need to install the scanned dependencies. Demo inputs contain deliberately vulnerable
versions; use them as scanner input, not production dependencies. Exit **2 (BLOCK) or 3 (WARNING)**
can be an expected scan result. Exit 1 indicates invalid input or arguments.
`--no-explain` skips only the optional Ollama explanation; findings and saved reports remain available.
The basic scan needs neither Ollama nor GitHub/Hugging Face tokens.

```bash
aibom-guardian --npm examples/npm-live-before.json --no-explain
aibom-guardian ../my-project/requirements.txt --no-explain
aibom-guardian --npm ../my-project/package.json --no-explain
```

## Scoring and verification states

Trust Score is a **project-defined policy score**, starting at 100. Its weights are not prescribed
or certified by an international standard. Confidence represents available evidence, not a probability of safety.

| Category | Maximum category deduction |
|---|---:|
| Malicious code | 28 |
| Vulnerabilities | 25 |
| License | 15 |
| Typosquatting | 12 |
| Nonexistent package or model | 10 |
| Provenance | 10 |

Decision priority:

1. A hard-block policy condition produces `BLOCK`.
2. Without a hard block, confidence below 0.5 produces `WARNING`.
3. Otherwise, a score below 50 produces `BLOCK`.
4. A score of at least 80, confidence of at least 0.7, and no confirmed High or suspicious finding produces `ALLOW`.
5. All other cases produce `WARNING`.

A completed vulnerability lookup with no findings is `vulnerabilities: []`; an unverified lookup is `null`.
License and Model Card checks also preserve unverified states. CLI and MCP use the same scoring engine,
but different collection scopes can produce different results.
[Methodology, policy and evaluation](docs/trust_score_methodology.md)

## Usage and documentation

| Goal | Capability | Guide |
|---|---|---|
| Pre-adoption review | Python/npm/model checks and JSON/BOM output | [Coverage and CLI](docs/usage.en.md) |
| CI policy | Exit codes, SARIF and report summaries | [Output and integration](docs/usage.en.md#output-files-and-exit-codes) |
| AI clients | Eight MCP tools for checks, project scanning, version comparison and monitoring | [MCP setup](docs/usage.en.md#mcp-server) |
| Ongoing monitoring | Fixed-version rechecks, Slack and Windows scheduling | [Monitoring guide](docs/monitoring.en.md) |

After generating a report:

```bash
python -m aibom_guardian.monitoring init scan_report.json --db .aibom-guardian/monitor.db
python -m aibom_guardian.monitoring check --db .aibom-guardian/monitor.db --interval 3600
```

Events are local JSON by default; Slack delivery requires webhook configuration.
Registered versions stay fixed and do not automatically follow the installed environment.

## Architecture

```text
requirements / package.json (+ lockfile) / model reference
    -> parse and collect evidence
    -> shared adapter -> policy score, confidence and verdict
    -> terminal / JSON / CycloneDX / SARIF / CI exit code

saved report -> fixed inventory -> periodic recheck -> SQLite history / Slack
```

## Known limitations

- Checks cover known vulnerabilities and available evidence, not model behavior, backdoors or all malicious code.
- Pickle content scanning is opt-in and limited to known dangerous patterns.
- Model Card PII inspection is static text analysis, not runtime masking.
- Registry-resolved versions do not prove installation success or application compatibility.
- MCP `check_package` supports PyPI; use the CLI for npm. Collection scope affects results.
- Gated models need accepted terms and `HF_TOKEN`; signature verification requires local `cosign`.
- Windows scheduled checks require an awake PC and the configured user to be logged in. Lost Slack responses can cause duplicate delivery on retry.

## Development and license

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m pyflakes src/aibom_guardian tests examples
```

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md) · [Dependencies](DEPENDENCIES.md)

Released under [Apache License 2.0](LICENSE).
