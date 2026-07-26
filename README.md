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
├─ requirements.txt      # example input: packages to scan
├─ scanner.py             # main CLI - runs the whole pipeline
├─ osv_client.py          # queries OSV API for known vulnerabilities
├─ license_checker.py     # classifies license as ALLOWED / REVIEW / BLOCKED
├─ repository_checker.py  # GitHub / OpenSSF / provenance / HF dataset trust
├─ sbom_generator.py      # builds the final CycloneDX SBOM file
├─ ai_explainer.py        # local Ollama explanation of risky findings
├─ mcp_server.py          # MCP tools for AI agents
├─ DEPENDENCIES.md        # list of open source libraries this project uses
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

## Current status / limitations

This is an early-stage personal prototype. Known limitations:

- Only supports `package==version` pinned entries in `requirements.txt`
- License check reads the license of the *currently installed* version,
  which may not exactly match the version pinned in `requirements.txt`
- Trust Score formula is a simple placeholder, not the full weighted
  scoring model
- No AI-generated explanations yet (planned: a locally-run open-weight
  model via Ollama, so the tool doesn't just call a closed AI API)
- Not yet exposed as an MCP server (planned next step)

## Roadmap

- [ ] Add a locally-run AI model (Ollama) to explain results in plain language
- [ ] Expose this as an MCP server so AI agents (e.g. Claude Desktop, Cursor)
      can call it directly
- [ ] Support AI model scanning (AIBOM / ML-BOM), not just regular packages
- [ ] Refine the Trust Score formula
