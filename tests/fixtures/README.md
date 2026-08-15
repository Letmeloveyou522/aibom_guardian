# Test fixtures — trimmed license registries

`license_checker` downloads the SPDX License List and the Blue Oak Council
License List on first use and caches them under `AIBOM_GUARDIAN_CACHE`.
`conftest.py` points that variable here, so the test suite runs offline and
does not depend on whatever happens to be in a developer's real cache.

These two files hold only the identifiers the tests assert on — 40 of SPDX's
727 — rather than a copy of either list. Neither publisher states
redistribution terms for their list, which is also why the full copies are
not vendored into the repository; see the note at the top of
`license_checker.py`.

## Regenerating

Run from the repository root, after a scan has populated the real cache:

```bash
python - <<'EOF'
import json, os
from pathlib import Path

cache = Path(os.environ.get(
    "LOCALAPPDATA", Path.home() / ".cache")) / "aibom-guardian" / "registries"
src = json.loads((cache / "spdx-licenses.json").read_text(encoding="utf-8"))
blue = json.loads((cache / "blueoak-list.json").read_text(encoding="utf-8"))

wanted = {lic["licenseId"] for lic in json.loads(
    Path("tests/fixtures/spdx-licenses.json").read_text(encoding="utf-8")
)["licenses"]}

licenses = [lic for lic in src["licenses"] if lic["licenseId"] in wanted]
Path("tests/fixtures/spdx-licenses.json").write_text(json.dumps(
    {"licenseListVersion": src["licenseListVersion"],
     "releaseDate": src.get("releaseDate"), "licenses": licenses},
    indent=1), encoding="utf-8")

ratings = [{"name": r["name"],
            "licenses": [e for e in r["licenses"] if e["id"] in wanted]}
           for r in blue["ratings"]]
Path("tests/fixtures/blueoak-list.json").write_text(json.dumps(
    {"version": blue["version"],
     "ratings": [r for r in ratings if r["licenses"]]},
    indent=1), encoding="utf-8")
EOF
```

Add an identifier to `tests/fixtures/spdx-licenses.json` by hand first if a
new test needs one, then re-run the above to fill in its real fields.
