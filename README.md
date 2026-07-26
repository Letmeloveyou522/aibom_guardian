# AIBOM-Guard (Personal MVP)

A simple CLI tool that scans a Python project's dependencies
(`requirements.txt`) and checks whether they are **safe to use** -
both in terms of **known security vulnerabilities** and **license
compliance**.

## What problem does this solve?

Modern software is built on top of open source packages. Two things
can go wrong with those packages:

1. **Security vulnerabilities** - an older version of a package might
   have a known security hole (a CVE) that attackers can exploit.
2. **License issues** - some packages come with licenses that restrict
   commercial use, which can cause legal problems for a project that
   plans to use them commercially or submit them to a competition with
   open-source license requirements.

AIBOM-Guard checks both automatically and produces a standard-format
report (CycloneDX SBOM) that documents exactly what was found.

## What it does, step by step

1. Reads a `requirements.txt` file (list of packages + versions)
2. For each package:
   - Checks its license against a list of OSI-approved open source licenses
   - Queries the [OSV database](https://osv.dev) (Google's free, open
     vulnerability database) for known CVEs affecting that version
   - Calculates a simple 0-100 "Trust Score" and a verdict:
     `ALLOW` / `CONDITIONAL` / `BLOCK`
3. Prints a summary table in the terminal
4. Saves two files:
   - `scan_report.json` - the raw scan results
   - `sbom.json` - a standard **CycloneDX SBOM** (Software Bill of
     Materials) that also embeds our license/vulnerability findings,
     so it's both a standard SBOM *and* a security report in one file

## Project structure

```
aibom-guard/
├─ requirements.txt           # example input: packages to scan
├─ scanner.py                 # main CLI - runs the whole pipeline
├─ osv_client.py              # queries OSV API for known vulnerabilities
├─ license_checker.py         # classifies license as ALLOWED / REVIEW / BLOCKED
├─ sbom_generator.py          # builds the final CycloneDX SBOM file
├─ repository_checker.py      # GitHub / HF / PyPI supply-chain trust checks
├─ mcp_server.py              # MCP server entry point (Claude Desktop / Cursor)
├─ DEPENDENCIES.md            # list of open source libraries this project uses
├─ tests/                     # unit tests (mocked network)
└─ scan_report.json / sbom.json   # example output from a real run
```

## How to run it

```bash
# 1. install dependencies
pip install requests prettytable cyclonedx-bom --break-system-packages

# 2. make sure the cyclonedx-py CLI is on your PATH
export PATH="$HOME/.local/bin:$PATH"

# 3. run a scan
python3 scanner.py requirements.txt
```

Example output:

```
+----------+---------+----------------+-------+-------------+---------+
| Package  | Version | License Status | Vulns | Trust Score | Verdict |
+----------+---------+----------------+-------+-------------+---------+
| requests |  2.28.0 |    ALLOWED     |   8   |      20     |  BLOCK  |
|  numpy   |  1.24.0 |    ALLOWED     |   0   |     100     |  ALLOW  |
|  pyyaml  |  5.3.1  |    ALLOWED     |   2   |      80     |  ALLOW  |
+----------+---------+----------------+-------+-------------+---------+
```

## MCP server (Claude Desktop / Cursor)

`mcp_server.py` exposes AIBOM-Guard tools over stdio MCP.

### Tools

| Tool | Role |
|---|---|
| `check_package` | CVE/advisory lookup (OSV) + installed-package license status |
| `check_license` | Classify a license string (ALLOWED / REVIEW / BLOCKED / UNKNOWN) |
| `check_repo_trust` | Supply-chain trust: GitHub activity, OpenSSF Scorecard, revision pinning, SHA-256, signatures/provenance, HF dataset docs |

Use `check_package` when you only need vulnerabilities for a package version.
Use `check_repo_trust` for repository / provenance / integrity questions.

### Install the MCP SDK (once)

```bash
pip install mcp
```

Optional tokens (never commit real values):

```text
GITHUB_TOKEN
GITHUB_API_VERSION
HF_TOKEN
HUGGINGFACE_TOKEN
```

### Claude Desktop config example

Keep your existing `command` / `args` paths. Only add env vars if needed:

```json
{
  "mcpServers": {
    "aibom-guard": {
      "command": "python",
      "args": ["C:/path/to/aibom_guard/mcp_server.py"],
      "env": {
        "GITHUB_TOKEN": "<your-token>",
        "HF_TOKEN": "<your-token>"
      }
    }
  }
}
```

Start the server manually to confirm imports:

```bash
python mcp_server.py
```

stdio MCP servers wait for client input — that idle state is normal.

### Manual Claude Desktop prompts

```text
Flask GitHub 저장소의 신뢰도를 분석해줘.
OpenSSF 점수, 최근 커밋, revision 고정 여부,
서명과 provenance 상태를 함께 알려줘.
```

```text
requests==2.31.0의 공급망 신뢰도를 검사해줘.
CVE뿐 아니라 PyPI 공개 해시, GitHub 저장소,
OpenSSF 점수, 버전 고정 여부도 확인해줘.
```

```text
https://huggingface.co/datasets/namespace/name
데이터셋의 라이선스, 출처, 수집 방법 기재 여부를 검사해줘.
```

```text
target_type을 github로 지정해서 pallets/flask를 검사해줘.
```

`owner/repo` shorthand can mean either GitHub or Hugging Face.
Say the platform explicitly (or set `target_type`) so the tool is not ambiguous.

`local_file` paths are resolved on the machine running the MCP server,
not on a remote chat client's filesystem.

### Repository trust CLI (without MCP)

```bash
python repository_checker.py https://github.com/pallets/flask --json
python repository_checker.py requests==2.31.0
```

## Current status / limitations

This is an early-stage personal prototype. Known limitations:

- Only supports `package==version` pinned entries in `requirements.txt`
- License check reads the license of the *currently installed* version,
  which may not exactly match the version pinned in `requirements.txt`
- Package Trust Score in `scanner.py` / `check_package` is still a simple
  CVE+license placeholder; `check_repo_trust` uses a separate weighted model
- AI explanations via Ollama are optional and require a local model
- Cosign verification in `repository_checker.py` needs a local `cosign` binary

## Roadmap

- [x] Expose scanning as an MCP server (`mcp_server.py`)
- [x] Add repository / HF / PyPI supply-chain trust checks
- [ ] Add a locally-run AI model (Ollama) to explain results in plain language
- [ ] Support richer AI model scanning (AIBOM / ML-BOM)
- [ ] Align package CVE Trust Score with the repository trust model
