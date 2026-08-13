# AIBOM-Guard

[![CI](https://github.com/Letmeloveyou522/aibom_guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Letmeloveyou522/aibom_guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-brightgreen)](https://cyclonedx.org/)

## Builds the bill of materials for an AI project, and judges what is in it

One pass over your Python packages and Hugging Face models produces two
things:

- **What is in there** → a CycloneDX ML-BOM (`sbom.json`)
- **Whether you may use it** → `ALLOW` / `WARNING` / `BLOCK` (`scan_report.json`)

Existing SBOM tools see pip packages only. In an AI project the model is a
dependency too, yet it never reaches the bill of materials — and licences like
OpenRAIL have no SPDX identifier, so licence scanners walk straight past them.
That is the gap this fills.

한국어: [README.md](README.md) ·
Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) ·
Security: [SECURITY.md](SECURITY.md) ·
Changelog: [CHANGELOG.md](CHANGELOG.md)

---

## What it produces

```
$ aibom-guard requirements.txt

[INFO] 3 direct + 4 transitive = 7 packages to scan.

+--------------------+-----------+----------------+-------+-------------+---------+
|      Package       |  Version  | License Status | Vulns | Trust Score | Verdict |
+--------------------+-----------+----------------+-------+-------------+---------+
|      requests      |   2.28.0  |    ALLOWED     |   4   |      75     | WARNING |
|       numpy        |   1.24.0  |    ALLOWED     |   0   |     100     |  ALLOW  |
|       pyyaml       |   5.3.1   |    ALLOWED     |   1   |      49     |  BLOCK  |
| charset-normalizer |   2.0.12  |    ALLOWED     |   0   |     100     |  ALLOW  |
|        idna        |    3.18   |    ALLOWED     |   0   |     100     |  ALLOW  |
|      urllib3       |  1.26.20  |    ALLOWED     |   5   |      75     | WARNING |
|      certifi       | 2026.7.22 |     REVIEW     |   0   |      96     |  ALLOW  |
+--------------------+-----------+----------------+-------+-------------+---------+

- pyyaml==5.3.1 (BLOCK, score 49)
    [HARD BLOCK] Critical severity cve finding: GHSA-8q59-q68h-6hv4
    -> suggested: PyYAML==6.0.3 (confirmed) - Upgrade to latest safe release

[EXIT 2]
```

`urllib3` is not in the requirements file. `requests` pulled it in, and its
five vulnerabilities only show up because the scan follows that. `REVIEW`
means usable but with licence obligations, and the exit code is what fails
your build.

AI models go into the same table.

```
$ aibom-guard requirements.txt --model CompVis/stable-diffusion-v1-4

| Model                         | License               | Weights              | Verdict |
| CompVis/stable-diffusion-v1-4 | creativeml-openrail-m | safetensors + pickle | BLOCK   |
```

---

## Why it exists

Dependencies suggested by an LLM or copied from a tutorial bring three things
with them.

- **Packages that do not exist** — a name nobody registered on PyPI can be
  claimed by anyone, so the next person to make the same typo installs an
  attacker's code.
- **Licences you cannot use** — OpenRAIL and Llama-family licences restrict
  specific uses, which makes them not OSI open source. They have no SPDX
  identifier, so ordinary licence scanners skip them.
- **Model weights that execute** — a `.bin` file is a pickle and
  `torch.load()` runs the code inside it. Loading the model is arbitrary code
  execution.

And **a check that did not run is not a check that passed.** If the
vulnerability lookup fails the answer is "unknown", not "zero", and the
verdict is `WARNING`.

---

## Quick start

```bash
pip install -e .
aibom-guard requirements.txt
```

In CI:

```yaml
- uses: Letmeloveyou522/aibom_guard@v1
```

---

## How it differs

| | pip-audit | safety | syft · trivy | AIBOM-Guard |
|---|:---:|:---:|:---:|:---:|
| Vulnerabilities | ✅ | ✅ | ✅ | ✅ |
| Transitive dependencies | ✅ | ✅ | ✅ | ✅ |
| SBOM | ❌ | ❌ | ✅ | ✅ CycloneDX 1.6 |
| Licence obligations | ❌ | partial | identify only | ✅ per licence |
| **AI model licences** | ❌ | ❌ | ❌ | ✅ OpenRAIL, Llama |
| **Model weight safety** | ❌ | ❌ | ❌ | ✅ pickle vs safetensors |
| ML-BOM | ❌ | ❌ | partial | ✅ |
| Release cooldown | ❌ | ❌ | ❌ | ✅ |
| SARIF | ✅ | ✅ | ✅ | ✅ |
| **Unverified never passes** | ❌ | ❌ | ❌ | ✅ |
| Callable by an LLM agent | ❌ | ❌ | ❌ | ✅ 4 MCP tools |

If you only need package vulnerabilities, `pip-audit` is lighter. This tool
earns its place when **AI models have to be judged by the same standard and
land in the same SBOM.**

---

## Install

Requires Python 3.10 or newer.

```bash
git clone https://github.com/Letmeloveyou522/aibom_guard.git
cd aibom_guard

python -m venv .venv
.venv\Scripts\activate          # Windows
source .venv/bin/activate       # macOS / Linux

pip install -e .
```

`pip install -e .` installs the dependencies and registers the `aibom-guard`
command. Use `pip install .` if you do not intend to edit the source.

Verify:

```bash
pytest
```

Everything should pass. The suite uses no network, finishes in about three
seconds, and works without installing the package (`pyproject.toml` puts
`src/` on the path).

### Optional

| Item | When you need it |
|---|---|
| `GITHUB_TOKEN` | For `--supply-chain`. Without it you hit GitHub API rate limits |
| `HF_TOKEN` | For gated models such as Llama. You also need to accept the license on the Hub |
| Ollama | To have results explained by a local LLM. Without it you get a warning and the scan still completes |
| `cosign` | For signature verification |

---

## Usage

```bash
aibom-guard examples/sample-requirements.txt
```

`python -m aibom_guard` does the same thing.

`examples/sample-requirements.txt` is scan *input*, pinned to deliberately
vulnerable versions. It is not something to `pip install -r`. To scan your own
project, pass the path to its `requirements.txt`.

Include AI models:

```bash
aibom-guard examples/sample-requirements.txt \
    --model CompVis/stable-diffusion-v1-4
```

| Option | Description |
|---|---|
| `--model REF` | Include a Hugging Face model. Repeatable. Turns the SBOM into an ML-BOM |
| `--direct-only` | Scan only what the file lists. The default follows dependencies |
| `--min-release-age DAYS` | Warn about versions published fewer than DAYS ago. Default 0 (off) |
| `--sarif PATH` | Also write SARIF 2.1.0, for GitHub code scanning |
| `-j`, `--jobs N` | Concurrent lookups. Default 8; `1` scans one at a time |
| `--supply-chain` | Repository trust checks. Slow — several network round trips per package |
| `--model-pickle-scan MB` | Scan inside model pickle files. Default 0 (off) |
| `--offline` | No network. License checks only |
| `--no-explain` | Skip the Ollama explanation |
| `--json PATH` / `--sbom PATH` | Output paths |
| `--verbose` | Print every vulnerability. Default is the top 3 by severity per package |
| `--fail-on` | Exit-code policy: `warning` (default) / `block` / `never` |
| `--version` | Print the version |

### Input format

Not just `==` pins — `>=`, `~=`, `<`, extras and environment markers are all
parsed. A range is narrowed to **the version that would actually be
installed** from PyPI, and the report records whether the file chose that
version (`version_resolved: false`) or this tool did (`true`).

```
[INFO] Resolved requests>=2.32 -> requests==2.34.2
[Scanning] requests==2.34.2 ...  (resolved from >=2.32)
```

Lines that cannot be scanned — `-r` / `-c` includes, URL and VCS requirements
— are reported under `unscanned` rather than silently skipped. Under
`--offline` ranges cannot be narrowed, so those lines become `unscanned` too.

### Dependencies are followed

Not just what the file lists — **everything that will be installed**. The tree
is resolved from PyPI's `requires_dist` per pinned release, so nothing has to
be installed.

```
[INFO] 3 direct + 4 transitive = 7 packages to scan.
[Scanning] urllib3==1.26.20 ...  (resolved from urllib3 (<1.27,>=1.21.1))
```

One line of `requests==2.28.0` brings in `urllib3`, and that `urllib3` carries
five CVEs. The report and the SBOM both record whether a package was listed
(`direct`) or pulled in.

Optional extras are skipped, platform and `python_version` markers are
evaluated against the running interpreter, and the first occurrence of a name
wins so a pinned version is never replaced by a dependency's range.
Unresolvable dependencies are reported under `unscanned`. `--direct-only`
turns the whole thing off.

Lookups run concurrently — mostly network wait. For a 20-line file (53
packages with dependencies) `--jobs 1` takes 36s and the default 8 takes 8s.
The report is identical either way.

### Release cooldown

`--min-release-age DAYS` warns about versions published more recently.

```
[COOLDOWN] certifi==2026.7.22 published 22 day(s) ago (threshold 90).
```

Compromised releases are usually withdrawn within hours: the September 2025
npm attack on chalk and debug was gone in about 2.5 hours. Waiting a day
avoids most of that window, which is why pnpm 11 ships a 24-hour cooldown by
default and pip 26.0 added `--uploaded-prior-to`.

Off by default — a fresh release is not itself a defect.

### CI integration

SARIF makes GitHub annotate the pull request inline.

```yaml
- uses: Letmeloveyou522/aibom_guard@v1
  with:
    requirements: requirements.txt
    min-release-age: 1
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aibom-guard.sarif
```

Or directly:

```bash
aibom-guard requirements.txt --sarif aibom-guard.sarif
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything is ALLOW and every line was scanned |
| `1` | Bad input (missing file, bad arguments, nothing to scan) |
| `2` | At least one BLOCK |
| `3` | No hard block, but a WARNING or an unscanned line |

Argument errors also exit `1`. argparse defaults to `2`, which would leave CI
unable to distinguish a typo from a blocked dependency.

`3` exists for a reason. Previously only BLOCK counted as failure, so a failed
OSV lookup, a nonexistent package, an unreadable license and six unparsed
lines all exited `0`. A gate that reports success without having checked
anything is worse than no gate at all.

To gate on BLOCK alone, use `--fail-on block`.

---

## Reading the output

### Package summary

```
+----------+---------+----------------+-------+-------------+---------+
| Package  | Version | License Status | Vulns | Trust Score | Verdict |
+----------+---------+----------------+-------+-------------+---------+
| requests |  2.28.0 |    ALLOWED     |   4   |      75     | WARNING |
|  numpy   |  1.24.0 |    ALLOWED     |   0   |     100     |  ALLOW  |
|  pyyaml  |  5.3.1  |    ALLOWED     |   1   |      49     |  BLOCK  |
+----------+---------+----------------+-------+-------------+---------+
```

| Column | Meaning |
|---|---|
| License Status | `ALLOWED` permissive / `REVIEW` carries obligations / `BLOCKED` use restricted / `UNKNOWN` not identified |
| Vulns | OSV vulnerability count. GHSA / PYSEC / CVE aliases are merged into one |
| Trust Score | 0–100. Weighted deductions from 100 |
| Verdict | `ALLOW` / `WARNING` / `BLOCK` |

`UNKNOWN` means "we could not identify it", not "it is safe". It costs points.

### Detail

```
- requests==2.28.0 (WARNING, score 75)
    Vuln GHSA-9hjg-9r4m-mvj7 (severity medium, CVSS 5.3, aka PYSEC-2026-1872):
        Requests vulnerable to .netrc credentials leak via malicious URLs
    -> suggested: requests==2.34.2 (confirmed) - Upgrade to latest safe release

- pyyaml==5.3.1 (BLOCK, score 49)
    [HARD BLOCK] Critical severity cve finding: GHSA-8q59-q68h-6hv4
```

- `aka PYSEC-...` — the same vulnerability's ID in another database. Not
  double-counted.
- `-> suggested` — recommended action. `confirmed` means a definite fix
  (version bump, typo correction); `suggested` means an alternative worth
  reviewing.
- `[HARD BLOCK]` — blocked regardless of score. Three causes only: a critical
  vulnerability, confirmed malware, a blocked license.
- `[unverified]` — something that could not be checked: a pickle skipped for
  size, a network failure, a gated model we could not reach.

### AI models

```
| Model                         | License               | Family         | Weights              | Remote code | Card   | Score | Verdict |
| CompVis/stable-diffusion-v1-4 | creativeml-openrail-m | ai-behavioural | safetensors + pickle | no          | 60/100 | 49    | BLOCK   |
```

| Column | Meaning |
|---|---|
| Family | `permissive` OSI-approved / `copyleft` GPL family / `ai-community` conditional, e.g. Llama and Gemma / `ai-behavioural` use-restricted, e.g. OpenRAIL |
| Weights | `safetensors` safe / `safetensors + pickle` both present / `PICKLE ONLY` only pickle |
| Remote code | `YES` means loading the model executes Python from the repository |
| Card | Model Card completeness, 0–100 |

`ai-behavioural` licenses forbid specific uses, which makes them not OSI open
source; they are judged `BLOCKED`. `ai-community` licenses are usable but come
with conditions, so they are `REVIEW`.

`PICKLE ONLY` means there is no `.safetensors` alternative. `torch.load()`
executes code embedded in a pickle, so merely loading the model is arbitrary
code execution. When an alternative file exists in the same directory the
loader can be pointed at it, which lowers the risk.

### How the verdict is reached

The score is a weighted deduction across seven categories.

| Category | Weight | |
|---|---|---|
| malicious | 28 | Confirmed malicious code |
| cve | 25 | Published vulnerability |
| license | 15 | Legal grounds to block |
| typosquatting | 12 | Name-confusion attack |
| hallucination | 10 | Package or model that does not exist |
| provenance | 8 | Origin cannot be verified |
| pii | 2 | Sensitive data exposure |

80 and above is `ALLOW`, below 50 is `BLOCK`, everything else is `WARNING`.

**Anything that could not be checked is not treated as passing.** Thin
evidence lowers confidence, which yields `WARNING` rather than `ALLOW` or
`BLOCK`. What went unseen is recorded as `unverified` issues.

The weights and thresholds are agreed values, pinned by
`tests/test_score_engine.py`.

### Generated files

| File | Contents |
|---|---|
| `scan_report.json` | Full results, including `score_breakdown` and confidence |
| `sbom.json` | CycloneDX 1.6 SBOM. An ML-BOM when `--model` is used |

The SBOM carries resolved SPDX identifiers in the standard `licenses` field;
obligations and the reasoning behind each verdict are attached as
`aibom-guard:` properties. Model components additionally carry SHA-256
`hashes` of the weight files, derivation (`pedigree.ancestors`) and the last
modified date.

Against the G7 "SBOM for AI — Minimum Elements" list of 50 items, coverage is
**28**, with the Models cluster at 13/13. The rest — Datasets, KPI, System
Level — are values only the model's authors can know, so a scanner cannot fill
them in on principle.

Both files are regenerated on every run and are not tracked in git. Stable
copies live in
[examples/scan_report.sample.json](examples/scan_report.sample.json) and
[examples/sbom.sample.json](examples/sbom.sample.json).

---

## What gets checked

### Packages

| Check | Detail |
|---|---|
| Vulnerabilities | OSV lookup, CVSS vector parsing, alias de-duplication |
| License | SPDX identification plus obligations. See [License judgement](#license-judgement) |
| Typosquatting | Edit distance against well-known package names |
| Hallucinated packages | Names absent from PyPI. An unregistered name can be claimed by anyone |
| Deprecation | Yanked releases, long-unmaintained projects |
| Alternatives | Safe upgrade targets, typo corrections |

### AI models

| Check | Detail |
|---|---|
| Weight format | pickle vs safetensors, matched shard by shard against alternatives |
| Inside pickles | picklescan for dangerous globals |
| Remote code | `trust_remote_code`, `auto_map`. `owner/repo--module.Class` loads code from another repository |
| License | OpenRAIL family `BLOCKED`, Llama / Gemma and similar `REVIEW` |
| Model Card | Presence and completeness. Detects the HF default template (`[More Information Needed]`) |
| Provenance | Commit SHA, base model, training datasets, gated status |

Every model file is fetched pinned to a commit SHA. A branch can move while
the scan is running, and the report has to describe the same files that were
actually inspected.

---

## License judgement

Licenses are identified against two authoritative lists rather than guessed
from keywords, and the result says which list it came from.

| List | Used for |
|---|---|
| SPDX License List | 727 identifiers, `isOsiApproved` |
| Blue Oak Council License List | Permissiveness ratings for 225 licenses |

`isOsiApproved` alone is not enough. It is not a statement about whether a
license is restrictive — it is the procedural fact that someone applied to the
OSI and was approved. `CC0-1.0`, `BSD-Source-Code` and `MIT-Festival` are all
`false` and all permissive; nobody ever filed. Blocking on that flag alone
would block 161 licenses like them. Blue Oak fills that gap.

Order of judgement:

| Condition | Result |
|---|---|
| Documented use restriction (non-commercial, Commons Clause, BUSL, SSPL) | `BLOCKED` |
| OpenRAIL family / Llama, Gemma family | `BLOCKED` / `REVIEW` |
| Copyleft | `REVIEW` |
| Listed by Blue Oak or approved by OSI | `ALLOWED` |
| In SPDX but neither of the above | `REVIEW` |
| Nowhere at all | `UNKNOWN` |

The last two rows matter: absence of evidence is not grounds to block.

### The lists are downloaded and cached, not vendored

They are fetched on first run into `~/.cache/aibom-guard/registries`
(`%LOCALAPPDATA%\aibom-guard\registries` on Windows). After that the cache is
used; after 30 days a refresh is attempted, and if it fails the stale cache is
used anyway. `AIBOM_GUARD_CACHE` overrides the location.

They are deliberately not committed to this repository. Blue Oak's terms
permit automating *access* to the JSON files and say nothing about
redistributing them, and neither SPDX data repository declares a license for
the list itself. A tool that judges other people's licenses cannot ship files
whose terms it cannot state.

With `--offline` and no cache, only the built-in rules remain: use
restrictions and the copyleft families are still caught, everything else
becomes `UNKNOWN`. It degrades in that direction only — nothing becomes
`ALLOWED`.

### Obligations come with the verdict

The single word `REVIEW` does not tell you what to do, and AGPL and MPL do not
ask the same thing of you.

```
mysqlclient==2.2.4   REVIEW   GPL-2.0-only
  why : GNU General Public License v2.0 only (GPL-2.0-only) is a copyleft license.
  todo: Strong copyleft. Distributing a work that links or embeds this requires
        releasing the complete corresponding source of the whole work under the
        GPL. Internal use without distribution triggers nothing.
  ref : https://spdx.org/licenses/GPL-2.0-only.html
```

### Versions are never invented

`paramiko` declares only `"LGPL"`, but it is actually LGPL-2.1. Deciding it is
`LGPL-3.0-only` would mean advising the wrong obligations. A version-less
declaration reports the family and leaves the version unresolved.

```
LGPL     -> REVIEW  spdx=(unresolved)  "LGPL family, exact version undetermined"
LGPL-2.1 -> REVIEW  spdx=LGPL-2.1-only
```

### SPDX expressions

Follows the SPDX rule that `AND` binds tighter than `OR` and parentheses win.
`WITH` is not split apart — the exception has to be judged together with the
license on its left, otherwise `Apache-2.0 WITH Commons Clause` passes as
plain Apache.

### Which version's license gets read

Licenses change between releases. `chardet` 5.2.0 is LGPL-2.1; 7.5.1 is 0BSD.
Reading the installed copy would report terms belonging to a version nobody
pinned, and would miss copyleft obligations entirely.

So the pinned release on PyPI (`/pypi/<pkg>/<version>/json`) is the source of
truth. The installed copy is a fallback, and using the fallback is disclosed.

| `license_source` | Meaning |
|---|---|
| `pypi:license_expression` | PEP 639 SPDX expression |
| `pypi:license` / `pypi:classifier` | Metadata from the pinned release |
| `installed:*` | Installed copy. Sets `license_unverified: true` if the version differs |
| `none` | Could not be read anywhere |

When `license_unverified` is `true`, an `unverified` issue is recorded and
confidence drops — the same contract as an OSV failure. An installed copy
counts as verified only when its version matches the pin.

When several fields are present, the one that resolves to an SPDX identifier
wins rather than a fixed priority order. `psycopg2` puts
`"LGPL with exceptions"` in `license` and `"...v3 (LGPLv3)"` in its
classifiers; reading in a fixed order would discard the one that parses.

With `--offline`, PyPI is not queried and only the installed copy is used.

### Limits

Commons Clause is in neither the SPDX license list nor its 84 exceptions, and
model licenses such as OpenRAIL and Llama have no SPDX identifiers at all.
That territory is handled by a rule list, with the restriction spelled out per
entry.

---

## Architecture

```
model_checker ──────┐
repository_checker ─┼──> score_engine ──> sbom_generator / mcp_server
recommendation ─────┘
```

The collectors gather evidence and do not score. `score_engine` is the only
component that turns evidence into a number and a verdict, which is what makes
the CLI and the MCP server agree. Both front ends build that input through a
single shared adapter (`_adapters.py`), and a test asserts they are literally
the same function object.

```
src/aibom_guard/
    scanner.py              CLI entry point (aibom-guard)
    mcp_server.py           MCP entry point (aibom-guard-mcp)
    _adapters.py            front end -> score_engine input (single copy)
    score_engine.py         Trust Score / final verdict  <- the only scorer
    model_checker.py        Hugging Face model metadata
    osv_client.py           OSV CVE lookup + CVSS parsing
    recommendation.py       Risk detection + alternatives
    license_checker.py      License classification
    sbom_generator.py       CycloneDX SBOM / ML-BOM
    ai_explainer.py         Ollama local-model explanation
    repository_checker/     Supply-chain trust, split by target
        _constants.py         Allow-lists, API roots, thresholds
        _http.py              SSRF guard + the client enforcing it
        _targets.py           What the caller actually pointed at
        _evidence.py          Hashes, signatures, CODEOWNERS, GitHub URLs
        _datasets.py          Dataset card section coverage
        _scoring.py           Repository trust score
        _github.py            GitHub checks
        _huggingface.py       Hugging Face checks
        _pypi.py              PyPI checks
        _provenance.py        Local files, signatures, cosign
        _checker.py           RepositoryChecker, composing the above
        _api.py               check_repository()
examples/                   Sample input, demo, reference output
tests/                      Unit tests (no network)
```

`repository_checker` was one 2,828-line module. It is split by *target
ecosystem* rather than by layer, because that is how the work actually
divides: a change to how GitHub maintainers are counted has nothing to say to
the Hugging Face or PyPI paths. The import path from outside is unchanged.

Individual modules can be run on their own:

```bash
python -m aibom_guard.model_checker https://huggingface.co/google-bert/bert-base-uncased
python -m aibom_guard.repository_checker https://github.com/pallets/flask --json
python -m aibom_guard.license_checker
python -m aibom_guard.score_engine
python examples/demo_recommendation.py reqeusts==1.0.0
```

Run `model_checker` on its own and it **downloads and inspects** pickle files
up to 512 MB, which can take minutes depending on model size. Pass
`--max-pickle-size-mb 0` for metadata only. `aibom-guard --model` defaults the
other way — 0, enabled with `--model-pickle-scan MB`.

---

## MCP

`mcp_server` exposes **four** tools over stdio MCP. Unlike the CLI it does not
batch-scan a requirements.txt, does not write `scan_report.json` / `sbom.json`,
and does not run Ollama explanations. It answers one target at a time as JSON.

| Tool | Role | CLI equivalent |
|---|---|---|
| `check_package` | OSV CVEs + license + Trust Score. On OSV failure: `vulnerabilities: null`, `osv_unverified: true`, WARNING | A package row |
| `check_license` | Classify a license string (ALLOWED / REVIEW / BLOCKED / UNKNOWN) | `license_checker` |
| `check_repo_trust` | GitHub activity, OpenSSF, signatures, provenance, HF dataset documentation | `--supply-chain` |
| `check_model` | Hugging Face model scan. Returns the same schema as an entry in `scan_report.json`'s `models[]` | `--model REF` |

### CLI vs MCP scope

| | CLI (`aibom-guard`) | MCP (`aibom-guard-mcp`) |
|---|---|---|
| Input | `requirements.txt` + repeated `--model` | One target per tool |
| Output | Terminal + `scan_report.json` + CycloneDX / ML-BOM | Tool return JSON only |
| OSV failure | `vulnerabilities: null`, confidence down, WARNING | Same contract in `check_package` |
| Models | `--model` → `models[]` + SBOM `machine-learning-model` | `check_model` → identical `models[]` fields |

`scan_report.json` schema:

```json
{
  "packages": [ { "package", "version", "license_status", "vulnerabilities", "verdict", "..." } ],
  "models":   [ { "model_id", "license_status", "verdict", "risk_score", "issues", "model_card", "..." } ],
  "unscanned": [ "lines that are not == pins, e.g. name>=1.0" ]
}
```

Claude Desktop configuration:

```json
{
  "mcpServers": {
    "aibom-guard": {
      "command": "aibom-guard-mcp",
      "env": { "GITHUB_TOKEN": "...", "HF_TOKEN": "..." }
    }
  }
}
```

If `aibom-guard-mcp` is not on PATH — for example when it is installed only
inside a virtual environment — point at the interpreter directly:

```json
{
  "command": "C:/path/to/.venv/Scripts/python.exe",
  "args": ["-m", "aibom_guard.mcp_server"]
}
```

Passing the path to `mcp_server.py` no longer works. It is a module inside a
package and uses relative imports, so it has to be started with `-m`.

Both tokens are optional. Do not commit real values. Running the server
directly leaves it waiting on input, which is stdio MCP behaving correctly.

---

## Tests

```bash
pytest                            # everything
pytest tests/test_scanner.py -v   # one file, with test names
pytest -k license                 # filter by name
```

No network, about three seconds. `pyproject.toml` configures the path, so it
works from anywhere in the repository.

---

## Status

Implemented: package CVE / license / typosquatting / hallucination detection,
AI model scanning, supply-chain checks, Trust Score, SBOM and ML-BOM
generation, four MCP tools (`check_package`, `check_license`,
`check_repo_trust`, `check_model`), Ollama explanations.

Known limits:

- Licenses are read from the pinned release on PyPI. On lookup failure or
  offline it falls back to the installed copy and marks
  `license_unverified`.
- A version range is narrowed against whatever PyPI has today. A real install
  at a different time may resolve differently; `version_resolved` in the
  report records the distinction.
- Scanning inside model pickles is off by default. Unscanned files are
  reported as `unverified`.
- picklescan detects known dangerous patterns only. No detection is not a
  guarantee of safety.
- Gated models need `HF_TOKEN` and license acceptance on the Hub.
- cosign verification needs a local `cosign` binary.
- An OSV or network failure never becomes zero CVEs. `vulnerabilities` is
  `null` and the verdict is WARNING.

---

## Dependencies

`requests`, `prettytable`, `cyclonedx-bom`, `mcp`, `huggingface_hub`,
`picklescan`. The full list with licenses is in
[DEPENDENCIES.md](DEPENDENCIES.md).

`mcp` is pinned to `==1.28.1`. mcp 2.x removed `mcp.server.fastmcp`, so an
unpinned install produces a server that cannot start.

The SPDX and Blue Oak lists used for license judgement are not vendored; they
are downloaded and cached on first use. See
[License judgement](#the-lists-are-downloaded-and-cached-not-vendored).

---

## License

Apache License 2.0. Full text in [LICENSE](LICENSE).
