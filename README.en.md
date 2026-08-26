# AIBOM-Guardian

[![CI](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guardian/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

## Scan packages and AI models in one workflow

AIBOM-Guardian scans Python and npm dependencies, checks optional Hugging Face
models, and records the results in a CycloneDX 1.6 SBOM or ML-BOM. It can run
locally, in CI, or as an MCP server.

Each component receives a Trust Score and an `ALLOW`, `WARNING`, or `BLOCK`
verdict based on vulnerabilities, license terms, risk signals, and available
provenance. A failed lookup remains unverified instead of being reported as a
clean result.

[한국어 README](README.md) | [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md) | [Changelog](CHANGELOG.md)

## Quick start

Python 3.10 or newer is required.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guardian.git
cd aibom_guardian
python -m venv .venv
```

Activate the environment and install the project:

```bash
# Windows
.venv\Scripts\activate

# macOS or Linux
source .venv/bin/activate

pip install -e .
```

Run a scan:

```bash
aibom-guardian requirements.txt
aibom-guardian --npm package.json
aibom-guardian requirements.txt --model CompVis/stable-diffusion-v1-4
```

The files under [`examples/`](examples/) contain deliberately vulnerable
versions for demonstration. Do not install them in production.

## Scan coverage

### Python packages

- Direct and indirect dependencies from `requirements.txt`
- Known vulnerabilities from OSV, with duplicate aliases merged
- License classification and obligations using SPDX and Blue Oak data
- Nonexistent names, typosquatting signals, yanked releases, and release age
- Optional repository, signature, and OpenSSF checks

Ranges such as `>=` and `~=` are resolved against PyPI. Extras and environment
markers are supported. Includes, URLs, VCS requirements, and unresolved lines
are reported under `unscanned`.

### npm packages

The npm path reads `dependencies` and `devDependencies` from `package.json`,
resolves indirect dependencies through the npm registry, and checks licenses
and known vulnerabilities.

### AI models

- Hugging Face metadata, revision, license, and gated status
- Pickle and safetensors weight formats
- Dangerous pickle patterns when file scanning is enabled
- Remote-code settings such as `trust_remote_code` and `auto_map`
- Model Card completeness and static PII signals
- Base-model and training-dataset references when available

Model files are pinned to a commit revision during inspection. Pickle content
scanning is off by default to avoid downloading large files. Enable it with
`--model-pickle-scan MB`.

## Example output

```text
[INFO] 3 direct + 4 transitive = 7 packages to scan.

+----------+---------+----------------+-------+-------------+---------+
| Package  | Version | License Status | Vulns | Trust Score | Verdict |
+----------+---------+----------------+-------+-------------+---------+
| requests |  2.28.0 |    ALLOWED     |   4   |      75     | WARNING |
| numpy    |  1.24.0 |    ALLOWED     |   0   |     100     | ALLOW   |
| pyyaml   |  5.3.1  |    ALLOWED     |   1   |      49     | BLOCK   |
+----------+---------+----------------+-------+-------------+---------+

- pyyaml==5.3.1 (BLOCK, score 49)
    [HARD BLOCK] Critical severity cve finding: GHSA-8q59-q68h-6hv4
    -> suggested: PyYAML==6.0.3 (confirmed) - Upgrade to latest safe release
```

Indirect dependencies remain marked as indirect in the JSON report and SBOM.
Detailed findings include severity, evidence, and a recommended action when
one can be confirmed.

## Trust Score

The score starts at 100 and applies deductions across six categories.

| Category | Weight |
|---|---:|
| Malicious code | 28 |
| Vulnerabilities | 25 |
| License | 15 |
| Typosquatting | 12 |
| Hallucinated package or model | 10 |
| Provenance | 10 |

- `BLOCK`: a hard-block condition or a score below 50
- `ALLOW`: a score of at least 80, confidence of at least 0.7, and no high-severity finding
- `WARNING`: all other cases, including incomplete verification

A blocked license, confirmed malicious code, or critical finding causes a hard
block regardless of score. The CLI and MCP interfaces use the same scoring
engine.

### Verification states

| Field | Check completed, no finding | Unverified |
|---|---|---|
| `vulnerabilities` | `[]` | `null` |
| `license_unverified` | `false` | `true` |
| `pii_scan_unverified` | `false` | `true` |

Unverified evidence lowers confidence and normally produces `WARNING`. A
network or metadata failure cannot appear as a successful check.

## Main options

| Option | Description |
|---|---|
| `--npm PATH` | Scan an npm `package.json` file |
| `--model REF` | Add a Hugging Face model; repeatable |
| `--direct-only` | Skip indirect dependency resolution |
| `--min-release-age DAYS` | Warn about newer releases; off by default |
| `--supply-chain` | Enable repository and provenance checks |
| `--model-pickle-scan MB` | Inspect pickle files up to the given size |
| `--sarif PATH` | Write a SARIF 2.1.0 report |
| `--json PATH` | Set the JSON path; default `scan_report.json` |
| `--sbom PATH` | Set the SBOM path; default `sbom.json` |
| `-j`, `--jobs N` | Concurrent package workers; default 8 |
| `--offline` | Disable network access |
| `--no-explain` | Skip the optional Ollama explanation |
| `--verbose` | Print all vulnerability details |
| `--fail-on POLICY` | Choose `warning`, `block`, or `never` |
| `--version` | Print the installed version |

Packages are processed concurrently. Checks within one package run in sequence
so later analysis can use earlier results. Report order follows input order.

## Output files and exit codes

| File | Contents |
|---|---|
| `scan_report.json` | Results, findings, confidence, and score breakdown |
| `sbom.json` | CycloneDX 1.6 SBOM or ML-BOM |
| Optional `.sarif` file | SARIF 2.1.0 findings for code scanning |

Reference outputs are available at
[`examples/scan_report.sample.json`](examples/scan_report.sample.json) and
[`examples/sbom.sample.json`](examples/sbom.sample.json).

| Code | Meaning |
|---:|---|
| `0` | All results are `ALLOW` and nothing is unscanned |
| `1` | Invalid input or arguments |
| `2` | At least one result is `BLOCK` |
| `3` | Warning or unscanned input, with no block |

Use `--fail-on block` to gate only on blocked results or `--fail-on never` to
record findings without failing the build.

## GitHub Actions

```yaml
- uses: Letmeloveyou522/aibom_guardian@v1
  with:
    requirements: requirements.txt
    min-release-age: 1

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aibom-guardian.sarif
```

See [`action.yml`](action.yml) for the supported inputs.

## Optional integrations

| Item | Purpose |
|---|---|
| `GITHUB_TOKEN` | Higher GitHub API limits for supply-chain checks |
| `HF_TOKEN` | Access to gated models after license acceptance |
| Ollama | Local explanations using `qwen2.5:0.5b` |
| `cosign` | Signature verification |

The base package scan does not require these integrations.

## MCP server

`aibom-guardian-mcp` exposes four tools over stdio.

| Tool | Purpose |
|---|---|
| `check_package` | Check one PyPI package |
| `check_license` | Classify a license and return its obligations |
| `check_model` | Inspect one Hugging Face model |
| `check_repo_trust` | Check repository and provenance evidence |

The server returns one JSON response per target. Batch dependency scans,
report files, and Ollama explanations are handled by the CLI.

```json
{
  "mcpServers": {
    "aibom-guardian": {
      "command": "aibom-guardian-mcp",
      "env": { "GITHUB_TOKEN": "...", "HF_TOKEN": "..." }
    }
  }
}
```

Do not commit real tokens.

## Architecture

```text
requirements.txt / package.json / model reference
                         |
                         v
                  parse and resolve
                         |
                         v
 collect license, vulnerability, risk, and provenance evidence
                         |
                         v
             shared result adapter
                         |
                         v
                  score_engine
                         |
                         v
 terminal / JSON / CycloneDX / SARIF / exit code
```

Collectors gather evidence without assigning final verdicts. The CLI and MCP
server normalize findings through `_adapters.py` and pass them to
`score_engine.py`, keeping verdicts consistent across interfaces.

| Module | Responsibility |
|---|---|
| `scanner.py` | CLI orchestration |
| `_requirements.py` | Python requirement parsing and expansion |
| `npm_checker.py` | npm project scanning |
| `osv_client.py` | OSV and CVSS processing |
| `license_checker.py` | License classification and obligations |
| `model_checker.py` | Hugging Face model inspection |
| `repository_checker/` | Repository and provenance checks |
| `_adapters.py` | Shared scoring input |
| `score_engine.py` | Trust Score and verdict |
| `sbom_generator.py` | CycloneDX SBOM and ML-BOM |
| `mcp_server.py` | MCP tools |

## Known limitations

- MCP `check_package` supports PyPI only; use `--npm` for npm projects.
- Model Card PII checks inspect static text and do not provide runtime masking.
- Version ranges use current registry data and may differ from an earlier install.
- Pickle scanning is off by default and detects known dangerous patterns only.
- Gated models require an accepted license and a valid `HF_TOKEN`.
- Signature verification requires a local `cosign` binary.
- Network failures produce unverified findings, not verified clean results.

## Development and contribution

```bash
pytest
pyflakes src/aibom_guardian tests examples
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution process and
[`SECURITY.md`](SECURITY.md) for vulnerability reports. Runtime dependencies
and licenses are listed in [`DEPENDENCIES.md`](DEPENDENCIES.md).

## License

Released under the Apache License 2.0. See [`LICENSE`](LICENSE).
