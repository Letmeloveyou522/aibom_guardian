# Scan coverage and detailed usage

[Back to README](../README.en.md) · [한국어](usage.md)

## Scan coverage

### Python packages

- Direct and indirect dependencies from `requirements.txt`, including supported environment markers and extras
- Known OSV vulnerabilities, merged advisory aliases, and license classification
- Missing packages, typosquatting signals, yanked releases, and optional repository checks

Supported ranges are resolved using current PyPI metadata. Includes, URLs, VCS requirements,
conflicts and incomplete traversal are recorded as `unscanned`. This does not replace pip's resolver
or prove that the dependency set can be installed.

### npm packages

When a sibling `package-lock.json` v2/v3 is present, the scanner uses its exact versions and
installation paths. Mismatched root declarations, v1 locks and npm-shrinkwrap cause an error.
Local links, aliases and private registry entries are recorded as `unscanned`.
Without a lockfile, supported dependency ranges select matching registry versions and expand
indirect dependencies. The scanner does not inspect the installed `node_modules` tree.

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

The standalone `python -m aibom_guardian.repository_checker` also accepts
`--fail-on warning|block|never`. With the default `warning` policy, WARNING or
reported collection errors return 3, and BLOCK returns 2. Use `--fail-on never`
for the previous report-only behavior that returned 0 regardless of findings.

| File | Contents |
|---|---|
| `scan_report.json` | Results, findings, confidence, and score breakdown |
| `sbom.json` | CycloneDX 1.6 SBOM or ML-BOM |
| Optional `.sarif` file | SARIF 2.1.0 findings for code scanning |

Reference outputs are available at
[`examples/scan_report.sample.json`](../examples/scan_report.sample.json) and
[`examples/sbom.sample.json`](../examples/sbom.sample.json).

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

See [`action.yml`](../action.yml) for the supported inputs.

## Optional integrations

| Item | Purpose |
|---|---|
| `GITHUB_TOKEN` | Higher GitHub API limits for supply-chain checks |
| `HF_TOKEN` | Access to gated models after license acceptance |
| Ollama | Local explanations using `qwen2.5:0.5b` |
| `cosign` | Signature verification |

The base package scan does not require these integrations.

## MCP server

Generate Claude Desktop, Cursor, and VS Code configuration fragments with the installed environment's Python:
`python examples/mcp_setup.py --output mcp-client-configs --check`.
This probes each configured command with the MCP SDK; it does not modify client settings.
Use a new output directory. Merge the generated `aibom-guardian` entry into the existing configuration:

| Client | Generated file | Configuration destination |
|---|---|---|
| Claude Desktop | claude-desktop.json | Windows: `%APPDATA%\Claude\claude_desktop_config.json`, under `mcpServers` |
| Cursor | cursor.json | Project `.cursor/mcp.json`, under `mcpServers` |
| VS Code | vscode.json | Project `.vscode/mcp.json`, under `servers` |

Start the server, enable its tools in chat, and call `check_license` with MIT to check the connection.
Regenerate the configuration if you move the Python environment: it uses an absolute interpreter path.
The SDK check covers initialization, tool discovery, and calls; it does not validate client UI settings or permissions.

`aibom-guardian-mcp` exposes eight tools over stdio.

| Tool | Purpose |
|---|---|
| `check_package` | Check one PyPI package |
| `check_license` | Classify a license and return its obligations |
| `check_model` | Inspect one Hugging Face model |
| `check_repo_trust` | Check repository and provenance evidence |
| `scan_project` | Scan a Python requirements file within a configured project root |
| `compare_package_candidate` | Recheck two explicit PyPI versions; compatibility remains unverified |
| `monitor_history` | Read saved monitoring runs |
| `check_monitor` | Recheck registered versions and save changes |

The server returns JSON. Report files and Ollama explanations remain CLI features.
`check_package` checks vulnerabilities and licenses only. `scan_project` uses the
CLI collector, including recommendations and optional transitive dependencies.
Scores from different check scopes need not match.

Set `AIBOM_GUARDIAN_PROJECT_ROOT` in the MCP server's `env` to your project directory,
restart the server, then request `scan_project(requirements_path="requirements.txt", direct_only=false)`.
Absolute paths and files outside that root are rejected; input size is limited to 1 MiB.
This tool supports Python; use the CLI for npm. Online scans send package names and
versions to public registries. It does not install packages or write report files.
`offline=true` skips external lookups and returns unverified findings.

See the [monitoring guide](../docs/monitoring.en.md) for database and Slack configuration.

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
## Compare reports and deliver a BOM

Python and npm reports include scan time, tool/policy versions, options and input
SHA-256. npm lockfile scans also record the lockfile SHA-256.

```powershell
python -m aibom_guardian.reporting before.json after.json
python -m aibom_guardian.ci_summary after.json --before before.json
python -m aibom_guardian.bom_tools sbom.json
```

Comparison covers package versions and advisory IDs, not models or license changes.
Failed lookups and unscanned inputs cannot establish remediation. `no_longer_reported`
means an ID was absent from the subsequent lookup, not proven safety or compatibility.
Removed packages are listed separately. The summary command renders Markdown for CI.
The last command validates CycloneDX 1.6
JSON. Python/model BOM generation also validates before writing.

To upload explicitly, set `DEPENDENCY_TRACK_API_KEY` in your environment and use an
existing Dependency-Track project UUID:

```powershell
python -m aibom_guardian.bom_tools sbom.json --server https://dtrack.example.com --project <project-UUID>
```

This sends the BOM and replaces the project's component inventory. Choose a project
matching the full scan scope. HTTPS is required except for localhost.
`status=accepted` and `analysis_verified=false` mean upload acceptance only. Check
analysis and alerts in Dependency-Track; Guardian scores and custom model fields
are not guaranteed to affect its risk assessment.
[Dependency-Track integration documentation](https://docs.dependencytrack.org/usage/cicd/)

Package alternatives are unverified candidates (`candidate_verified=false`,
`compatibility_verified=false`). Rescan and test your application before adopting
one. Model `trust_score` is higher when fewer deductions apply; `risk_score` remains
an equal-valued compatibility alias. Suspicious pickle references require review
and are not automatically treated as confirmed malicious references.
