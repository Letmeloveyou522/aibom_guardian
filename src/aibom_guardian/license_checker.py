"""
license_checker.py
-----------------------------------
Identifies a package or model license and says what using it obliges you to do.

    classify_license("GPL-3.0-only")            -> "REVIEW"
    classify_license_detailed("GPL-3.0-only")   -> status, SPDX id, why,
                                                   obligations, reference URL

- ALLOWED: permissive, safe to use and redistribute
- REVIEW:  usable, but it places obligations on you - read `obligations`
- BLOCKED: carries a use restriction, so it is not open source
- UNKNOWN: could not be identified - not the same as safe

Identified against two registries, never guessed from keywords. The result
cites which one decided. Both are downloaded on first use and cached
(`_cache_dir`).

  SPDX License List              727 ids, each with an `isOsiApproved` flag
  Blue Oak Council License List  225 licenses graded for permissiveness

Neither alone works. `isOsiApproved` records whether someone filed with OSI,
not how restrictive a license is: CC0-1.0, BSD-Source-Code and MIT-Festival
are all `false` and all permissive. Blue Oak grades permissiveness directly
and covers 161 SPDX ids OSI never approved - the set the flag gets wrong.

A license in SPDX that neither OSI approved nor Blue Oak rated is REVIEW, not
BLOCKED. BLOCKED needs a documented use restriction, and that list is short
because no registry answers these:

  * Commons Clause is in neither the SPDX list nor its 84 exceptions, and it
    rides on a real license ("Apache-2.0 WITH Commons Clause"), so reading the
    left side alone grades it ALLOWED.
  * OpenRAIL, Llama, Gemma and Qwen have no SPDX id at all - and they are the
    licenses an AIBOM tool exists to grade.

Input shapes
------------
`importlib.metadata` does not return tidy SPDX ids:

  "MIT"                                     an identifier
  "License :: OSI Approved :: MIT License"  a PyPI trove classifier
  "MIT AND (GPL-3.0 OR BSD-3-Clause)"       an SPDX expression
  "Copyright (c) 2005-2024, NumPy ..."      47 KB of full licence text

Each shape has its own path. Two regressions this pins:

  * numpy (BSD-3-Clause) graded BLOCKED - its 47,527-character License field
    contains "including" (a bare "nc"), "proprietary" inside a sentence that
    *permits* proprietary linking, and "noncommercial" from a bundled licence
    that does not govern numpy.
  * "GNU General Public License v3 (GPLv3)", the string PyPI actually serves,
    graded UNKNOWN - copyleft slipping through ungraded.
"""

import json
import logging
import os
import re
import time
from functools import lru_cache
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["classify_license", "classify_license_detailed", "normalize_to_spdx",
           "registry_versions", "set_offline",
           "ALLOWED", "REVIEW", "BLOCKED", "UNKNOWN"]

ALLOWED = "ALLOWED"
REVIEW = "REVIEW"
BLOCKED = "BLOCKED"
UNKNOWN = "UNKNOWN"

# The registries are downloaded on first use and cached, the way vulnerability
# scanners handle their databases. They are deliberately not vendored into
# this repository: Blue Oak's terms permit automating *access* to the JSON
# files but say nothing about redistributing them, and neither SPDX data
# repository declares a license for the list itself. Fetching is the one thing
# both publishers clearly allow, and a tool that grades other people's
# licensing should not ship files whose own terms it cannot state.
_SPDX_URL = "https://spdx.org/licenses/licenses.json"
_BLUEOAK_URL = "https://blueoakcouncil.org/list.json"

# SPDX ships roughly quarterly; a month keeps the copy current without asking
# the network on every run. A stale cache is always preferred to no registry.
_CACHE_MAX_AGE_SEC = 30 * 24 * 60 * 60
_FETCH_TIMEOUT_SEC = 15.0

_OFFLINE = False


def set_offline(offline: bool) -> None:
    """
    Tell the registry loader not to reach the network (the CLI's --offline).

    An already-cached copy is still used; only the download is suppressed.
    """
    global _OFFLINE
    if bool(offline) != _OFFLINE:
        _OFFLINE = bool(offline)
        _registry.cache_clear()


def _cache_dir() -> Path:
    """
    Where the downloaded registries live.

    AIBOM_GUARDIAN_CACHE overrides it, which is how the test suite stays offline
    and how a CI job can pre-seed the cache.
    """
    override = os.environ.get("AIBOM_GUARDIAN_CACHE")
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
    else:
        base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "aibom-guardian" / "registries"

# Sentinels the callers pass in when there was nothing to read. They are not
# license strings and must not be matched against anything.
_NON_LICENSE_VALUES = {"", "unknown", "none", "null", "not_installed",
                       "no license", "unlicensed"}

# A License field longer than this is the license *text*, not an identifier.
_FULL_TEXT_MIN_CHARS = 300

# Only the opening of a long license text describes the package's own license;
# bundled third-party licenses are appended after it. Everything past this
# point is somebody else's terms and must not drive the verdict.
_PRIMARY_TEXT_WINDOW = 4000


def _normalise(text: str) -> str:
    """Lowercase and collapse whitespace so lookups match predictably."""
    return re.sub(r"\s+", " ", str(text or "").lower()).strip()


# ---------------------------------------------------------------------------
# Registries
# ---------------------------------------------------------------------------

def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _fetch_registry(filename: str, url: str) -> tuple:
    """
    Return (payload, source) for one registry.

    Order: a fresh cache, then a download, then a stale cache. Falling back to
    a stale copy matters more than being current - an out-of-date list still
    identifies MIT, and no list at all grades everything UNKNOWN.
    """
    path = _cache_dir() / filename

    if path.exists():
        age = time.time() - path.stat().st_mtime
        if age < _CACHE_MAX_AGE_SEC:
            payload = _load_json(path)
            if payload is not None:
                return payload, "cache"

    if not _OFFLINE:
        try:
            import requests

            response = requests.get(url, timeout=_FETCH_TIMEOUT_SEC)
            response.raise_for_status()
            payload = response.json()
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload), encoding="utf-8")
            except OSError:
                pass            # an unwritable cache is not a reason to fail
            return payload, "download"
        except Exception:       # noqa: BLE001 - network, DNS, TLS, bad JSON
            pass

    if path.exists():
        payload = _load_json(path)
        if payload is not None:
            return payload, "stale cache"

    return None, None


@lru_cache(maxsize=1)
def _registry() -> dict:
    """
    Load the SPDX and Blue Oak lists into one lookup table.

    Keyed by the normalised SPDX id *and* the normalised license name, so
    "gpl-3.0-only" and "gnu general public license v3.0 only" both resolve.

    When neither list can be loaded the table is empty and grading falls back
    to the rules that live in code - use restrictions and copyleft families.
    That degrades toward REVIEW and UNKNOWN, never toward ALLOWED.
    """
    spdx, spdx_source = _fetch_registry("spdx-licenses.json", _SPDX_URL)
    blueoak, blueoak_source = _fetch_registry("blueoak-list.json", _BLUEOAK_URL)

    if spdx is None:
        logger.warning(
            "SPDX license list unavailable (%s); licenses will be graded from "
            "built-in rules only and most will come back UNKNOWN. Run once "
            "with network access to populate %s.",
            "offline" if _OFFLINE else "download failed",
            _cache_dir(),
        )
        spdx = {"licenses": []}
    if blueoak is None:
        blueoak = {"ratings": []}

    rated = {}
    for rating in blueoak.get("ratings", []):
        for entry in rating.get("licenses", []):
            rated[entry["id"]] = rating["name"]

    records, index = {}, {}
    for lic in spdx.get("licenses", []):
        spdx_id = lic["licenseId"]
        see_also = lic.get("seeAlso") or []
        record = {
            "spdx_id": spdx_id,
            "name": lic.get("name", spdx_id),
            "osi_approved": bool(lic.get("isOsiApproved")),
            "deprecated": bool(lic.get("isDeprecatedLicenseId")),
            "blue_oak": rated.get(spdx_id),
            "reference": lic.get("reference") or (see_also[0] if see_also else ""),
        }
        records[spdx_id] = record
        index.setdefault(_normalise(spdx_id), record)
        index.setdefault(_normalise(record["name"]), record)

    return {
        "records": records,
        "index": index,
        "available": bool(records),
        "spdx_version": spdx.get("licenseListVersion", "unavailable"),
        "spdx_source": spdx_source or "unavailable",
        "blueoak_version": str(blueoak.get("version", "unavailable")),
        "blueoak_source": blueoak_source or "unavailable",
    }


def registry_versions() -> dict:
    """
    Which registry snapshots produced the verdicts, and where they came from.

    A license decision is only auditable if the data behind it is identified,
    so callers should record this alongside the result - it belongs in the
    SBOM next to the license fields.
    """
    reg = _registry()
    return {
        "spdx_license_list": reg["spdx_version"],
        "spdx_source": reg["spdx_source"],
        "blue_oak_council_list": reg["blueoak_version"],
        "blue_oak_source": reg["blueoak_source"],
        "available": reg["available"],
    }


# Spellings that are not SPDX ids or names: PyPI trove classifier tails, and
# the abbreviations people actually type. Everything else resolves from the
# registry, so this table only has to cover what the registry cannot.
_ALIASES = {
    "apache": "Apache-2.0",
    "apache 2": "Apache-2.0",
    "apache 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "mit license": "MIT",
    "the mit license": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd license": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "modified bsd license": "BSD-3-Clause",
    "simplified bsd license": "BSD-2-Clause",
    "isc license": "ISC",
    "isc license (iscl)": "ISC",
    "zlib/libpng license": "Zlib",
    "the unlicense": "Unlicense",
    "the unlicense (unlicense)": "Unlicense",
    "public domain": "CC0-1.0",
    "python software foundation license": "Python-2.0",
    "psf": "Python-2.0",
    "psf-2.0": "Python-2.0",
    # Copyleft aliases carry a version, always. A bare "GPL" or "LGPL" is
    # deliberately absent: paramiko publishes "LGPL" and is LGPL-2.1, so
    # resolving that to LGPL-3.0-only would hand back a confident wrong
    # answer, and LGPL-2.1 and 3.0 do not impose the same terms. Those strings
    # fall to the family fallback instead, which reports the family and says
    # the version is unresolved.
    "gplv2": "GPL-2.0-only",
    "gpl-2.0": "GPL-2.0-only",
    "gpl2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gpl3": "GPL-3.0-only",
    "gnu general public license v2 (gplv2)": "GPL-2.0-only",
    "gnu general public license v3 (gplv3)": "GPL-3.0-only",
    "gnu general public license v2 or later (gplv2+)": "GPL-2.0-or-later",
    "gnu general public license v3 or later (gplv3+)": "GPL-3.0-or-later",
    "lgplv2": "LGPL-2.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "gnu lesser general public license v2 (lgplv2)": "LGPL-2.0-only",
    "gnu lesser general public license v2.1 (lgplv2.1)": "LGPL-2.1-only",
    "gnu lesser general public license v3 (lgplv3)": "LGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "gnu affero general public license v3": "AGPL-3.0-only",
    "gnu affero general public license v3 (agplv3)": "AGPL-3.0-only",
    "mpl 2.0": "MPL-2.0",
    "mozilla public license 2.0 (mpl 2.0)": "MPL-2.0",
    "boost software license": "BSL-1.0",
    "bsl": "BSL-1.0",
    "wtfpl": "WTFPL",
    "cc-by-sa-4.0": "CC-BY-SA-4.0",
    "cc by sa 4.0": "CC-BY-SA-4.0",
    "cc-by-nc-4.0": "CC-BY-NC-4.0",
    "cc by nc 4.0": "CC-BY-NC-4.0",
}


def _strip_classifier(part: str) -> str:
    """
    Reduce a PyPI trove classifier to its license name.

        "License :: OSI Approved :: MIT License" -> "MIT License"
    """
    if "::" in part:
        part = part.split("::")[-1]
    return part.strip()


def _lookup_keys(text: str):
    """
    The spellings of one identifier worth trying against the registry.

    Metadata rarely arrives as a bare id: it comes wrapped in a trove
    classifier, in parentheses, or with a trailing noun ("MIT license"). None
    of those change which license it is.
    """
    seen = []
    for candidate in (text, _strip_classifier(text)):
        key = _normalise(candidate)
        for variant in (key,
                        key.strip("()[]{}<>\"' ,;."),
                        re.sub(r"\s+licen[cs]e$", "", key)):
            if variant and variant not in seen:
                seen.append(variant)
    return seen


def _lookup(text: str):
    """Resolve one identifier to a registry record, or None."""
    reg = _registry()
    for key in _lookup_keys(text):
        alias = _ALIASES.get(key)
        if alias and alias in reg["records"]:
            return reg["records"][alias]
        record = reg["index"].get(key)
        if record:
            return record
    return None


def normalize_to_spdx(part: str) -> str:
    """
    Map an identifier, alias or trove classifier onto its SPDX id.

    Returns the original (stripped) string when the registry does not know it,
    so callers can tell "resolved" from "left as written".
    """
    record = _lookup(part)
    if record:
        return record["spdx_id"]
    return _strip_classifier(str(part or "")).strip()


# ---------------------------------------------------------------------------
# Obligations - what a verdict actually asks of you
# ---------------------------------------------------------------------------
# Matched against the resolved SPDX id by prefix, longest first. AGPL and LGPL
# are listed before GPL because their ids contain it.

_COPYLEFT_FAMILIES = [
    (("AGPL-",), "copyleft-network",
     "Network copyleft. Offering this over a network counts as distribution: "
     "users of the hosted service must be able to obtain the complete "
     "corresponding source of your version under the AGPL."),
    (("LGPL-", "MS-RL", "libtiff"), "copyleft-weak",
     "Weak copyleft. Dynamically linking the library keeps your own code "
     "under your terms, but you must ship the library's source (or a written "
     "offer) and allow users to relink. Static linking or modifying the "
     "library pulls your work in."),
    (("GPL-", "SMAIL-GPL", "CNRI-Python-GPL"), "copyleft-strong",
     "Strong copyleft. Distributing a work that links or embeds this requires "
     "releasing the complete corresponding source of the whole work under the "
     "GPL. Internal use without distribution triggers nothing."),
    (("MPL-", "EPL-", "CDDL-", "CPL-", "IPL-", "APSL-", "Sleepycat", "OSL-",
      "QPL-", "CECILL", "EUPL"), "copyleft-file",
     "File-level copyleft. Source files you take from the project stay under "
     "its license and their modifications must be published; files you write "
     "yourself do not become subject to it."),
    (("CC-BY-SA",), "copyleft-share-alike",
     "Share-alike. Derivative works must be released under the same license. "
     "Creative Commons licenses are written for content, not code, and carry "
     "no patent grant."),
]

_PERMISSIVE_OBLIGATION = (
    "Keep the copyright notice and license text with any redistribution. No "
    "obligation on your own source.")

_UNRATED_OBLIGATION = (
    "Not OSI-approved and not rated by Blue Oak Council, so no published "
    "review vouches for it. Read the text before shipping - the risk is that "
    "it carries a condition no registry has catalogued.")


def _copyleft_family(spdx_id: str):
    for prefixes, family, obligation in _COPYLEFT_FAMILIES:
        if spdx_id.startswith(prefixes):
            return family, obligation
    return None, None


# ---------------------------------------------------------------------------
# Use restrictions - the part no registry answers
# ---------------------------------------------------------------------------
# Every entry names the restriction it carries. These run before the registry
# lookup because a restriction can ride on top of a permissive id: SPDX's WITH
# operator carries a real open-source license on its left, so resolving only
# that side grades "Apache-2.0 WITH Commons Clause" as Apache-2.0.

_RESTRICTION_RULES = [
    # (pattern, family, reason, obligation)
    (r"\bnon[\s\-]?commercial\b|\bcc[\s\-]?by[\s\-]?nc\b|\bnc[\s\-](?:nd|sa)\b",
     "restricted",
     "Forbids commercial use.",
     "Cannot be used in a commercial product. OSI's Open Source Definition "
     "clause 6 forbids restricting a field of endeavour, so this is not open "
     "source."),
    (r"\bproprietary\b|\bcommercial\s+license\s+required\b"
     r"|\ball\s+rights\s+reserved\s*$",
     "restricted",
     "Proprietary or requires a paid license.",
     "Obtain a license from the vendor before use."),
    (r"\bevaluation\s+(?:use\s+)?only\b|\bacademic\s+use\s+only\b"
     r"|\bno[\s\-]?military\b|\bresearch\s+(?:purposes\s+)?only\b",
     "restricted",
     "Restricted to a named purpose.",
     "Permitted uses are enumerated; anything else needs a separate grant."),
    (r"\bcommons\s+clause\b",
     "source-available",
     "Commons Clause removes the right to sell the software.",
     "The base license is open source but the Commons Clause rider withdraws "
     "the right to sell - including hosting it as a paid service. Not in the "
     "SPDX license list or its exception list."),
    (r"\bbusl\b|\bbusiness\s+source\b|\bbsl[\s\-]?1\.1\b"
     r"|\belastic\s+license\b|\belastic[\s\-]?2\.0\b|\belv2\b"
     r"|\bsspl\b|\bserver\s+side\s+public\b"
     r"|\bredis\s+source\s+available\b|\bconfluent\s+community\b"
     r"|\bfunctional\s+source\s+license\b|\bfsl[\s\-]?1\.1\b"
     r"|\bpolyform\b",
     "source-available",
     "Source-available: published code with a field-of-use restriction.",
     "Typically forbids offering the software as a competing service. SPDX "
     "records these as isOsiApproved: false and Blue Oak does not rate them."),
]

# Behavioural-use licenses forbid named uses outright, and licenses with an
# acceptable-use policy incorporate restrictions by reference. Neither is open
# source under the OSI definition, and none of them has an SPDX id.
_AI_RESTRICTED_PATTERNS = [
    r"\bopen\s?rail\b",
    # RAIL variants: "-rail-m", "rail++", "bloom-rail-1.0", "bigscience-rail".
    # A trailing letter or digit is required so "railway" - which \b already
    # excludes - and other ordinary uses cannot match.
    r"\brail[\s\-]?\+*[msd]\b", r"\brail[\s\-]?\d",
    r"\b(?:bigscience|big\s?science|bloom)[\s\-]?(?:bloom[\s\-]?)?rail\b",
    r"\bresponsible\s+ai\s+license\b",
    r"\bacceptable\s+use\s+policy\b",
    r"\bcreativeml\b",
    r"\bfair\s+ai\s+public\s+license\b",       # FAIPL has revenue conditions
    r"\bstability\s+ai\s+non[\s\-]?commercial\b",
    r"\bcoqui\s+public\s+model\b",
]

# Community / bespoke vendor licenses. Commercially usable up to a point, but
# with named-entity carve-outs, monthly-active-user ceilings, naming
# obligations or a separate acceptable-use policy. A human has to read them.
_AI_COMMUNITY_PATTERNS = [
    r"\bllama\s?[234](?:\.\d)?\b", r"\bllama[\s\-]?community\b",
    r"\bgemma\b", r"\bgoogle\s+gemma\b",
    r"\bqwen\b", r"\btongyi\s+qianwen\b",
    r"\bdeepseek\b",
    r"\bfalcon[\s\-]?(?:llm|180b)\b",
    r"\bmistral\s+ai\s+(?:research|non[\s\-]?production)\b",
    r"\bcohere\b", r"\bc4ai\b",
    r"\bnvidia\s+(?:open\s+model|community)\b",
    r"\bseallm\b", r"\byi\s+(?:series|license)\b",
    r"\bglm\b", r"\bchatglm\b",
    r"\bbaichuan\b", r"\binternlm\b",
    r"\bstabilityai\s+community\b",
    r"\bapple\s+(?:ascl|sample\s+code)\b",
]

_AI_RESTRICTED_REASON = (
    "Behavioural-use (RAIL-family) or acceptable-use-policy license. It "
    "forbids named uses, so it is not OSI-approved open source.")
_AI_RESTRICTED_OBLIGATION = (
    "The use restrictions travel with the weights and bind everyone you pass "
    "the model to. Check the prohibited-use list against your product.")
_AI_COMMUNITY_REASON = (
    "Open-weight vendor community license. Redistribution is allowed but "
    "conditioned - typically a named-entity carve-out, a monthly-active-user "
    "ceiling, naming obligations, or a separate acceptable-use policy.")
_AI_COMMUNITY_OBLIGATION = (
    "Usable commercially in most cases, but the conditions are specific to "
    "the vendor. Confirm the user ceiling, attribution and naming rules "
    "before shipping.")


def _match(patterns, text: str) -> bool:
    return any(re.search(pattern, text) for pattern in patterns)


# ---------------------------------------------------------------------------
# Family fallback - when the registry cannot resolve an exact identifier
# ---------------------------------------------------------------------------
# The registries answer exact identifiers. Real package metadata is often not
# exact: PyQt5 publishes "GPL v3", psycopg2 publishes "LGPL with exceptions".
# Neither resolves to an SPDX id, and returning UNKNOWN for them would let
# copyleft through ungraded - the failure this module exists to prevent.
#
# So the last layer names the *family* without claiming a version, and says in
# the reason that it could not pin one down.
#
# Two rules keep this from becoming keyword-guessing again:
#   1. It runs only after both registries have failed to resolve the string.
#   2. It can only produce REVIEW. Guessing "this looks permissive" would
#      risk a false pass, so there are no permissive entries here - an
#      unidentified license stays UNKNOWN and is penalised as unverified.
#
# LGPL and AGPL are listed before GPL because their names contain it.

_FAMILY_FALLBACK = [
    # The `v?\d` alternatives catch "GPLv3" / "LGPLv2.1", where the version is
    # glued to the name and \b therefore never fires after it.
    (r"\ba\s?gpl\b|\ba\s?gplv?\d|\baffero\b", "AGPL", "copyleft-network"),
    (r"\bl\s?gpl\b|\bl\s?gplv?\d|\blesser\s+general\s+public\b"
     r"|\blibrary\s+or\s+lesser\s+general\s+public\b", "LGPL", "copyleft-weak"),
    (r"\bgpl\b|\bgplv?\d|\bgnu\s+general\s+public\b", "GPL", "copyleft-strong"),
    (r"\bmpl\b|\bmozilla\s+public\b", "MPL", "copyleft-file"),
    (r"\bepl\b|\beclipse\s+public\b", "EPL", "copyleft-file"),
    (r"\bcddl\b|\bcommon\s+development\s+and\s+distribution\b",
     "CDDL", "copyleft-file"),
    (r"\bcc[\s\-]?by[\s\-]?sa\b|\bshare[\s\-]?alike\b",
     "CC-BY-SA", "copyleft-share-alike"),
]

_FAMILY_OBLIGATIONS = {
    family: obligation
    for _prefixes, family, obligation in _COPYLEFT_FAMILIES
}


def _grade_by_family(text: str):
    """Name the copyleft family of a string the registry could not resolve."""
    for pattern, label, family in _FAMILY_FALLBACK:
        if not re.search(pattern, text):
            continue
        obligation = _FAMILY_OBLIGATIONS.get(family, "")
        return _verdict(
            REVIEW, "copyleft",
            f"Reads as a {label}-family copyleft license, but the exact "
            f"version could not be resolved against the SPDX license list. "
            f"Treat the obligations as the family's.",
            [obligation,
             f"Record the precise identifier from the project's LICENSE file; "
             f"'{text[:60]}' is not an SPDX identifier."],
            source="family-fallback")
    return None


# ---------------------------------------------------------------------------
# Grading one identifier
# ---------------------------------------------------------------------------

def _verdict(status, family, reason, obligations, spdx_id="", source="",
             reference="") -> dict:
    return {"status": status, "family": family, "reason": reason,
            "obligations": obligations, "spdx_id": spdx_id, "source": source,
            "reference": reference}


def _grade_identifier(part: str) -> dict:
    """
    Grade one license identifier and say what it obliges and who decided.

    Order is deliberate: a documented restriction outranks whatever else the
    string says, so "MIT, non-commercial use only" is BLOCKED, and
    "Apache-2.0 WITH Commons Clause" is graded on the rider rather than on the
    Apache half. AI vendor licenses (OpenRAIL, Llama, Gemma) run before the
    SPDX lookup because they have no SPDX id — skipping straight to the registry
    would grade them UNKNOWN and let copyleft/restriction terms slip through.
    """
    text = _normalise(part)
    if not text or text in _NON_LICENSE_VALUES:
        return _verdict(UNKNOWN, "none", "No license declared.", [])

    for pattern, family, reason, obligation in _RESTRICTION_RULES:
        if re.search(pattern, text):
            return _verdict(BLOCKED, family, reason, [obligation],
                            source="use-restriction")

    if _match(_AI_RESTRICTED_PATTERNS, text):
        return _verdict(BLOCKED, "ai-behavioural", _AI_RESTRICTED_REASON,
                        [_AI_RESTRICTED_OBLIGATION], source="ai-license-rules")

    if _match(_AI_COMMUNITY_PATTERNS, text):
        return _verdict(REVIEW, "ai-community", _AI_COMMUNITY_REASON,
                        [_AI_COMMUNITY_OBLIGATION], source="ai-license-rules")

    record = _lookup(part)
    if record:
        return _grade_record(record)

    # SPDX's WITH operator: "<license-id> WITH <exception-id>". An exception in
    # the SPDX sense only ever grants *additional* permission, so once the
    # restriction rules above have ruled out a rider that withdraws rights -
    # Commons Clause is the one that matters, and it is in neither SPDX list -
    # the base license on the left decides.
    if " with " in text:
        base, exception = text.split(" with ", 1)
        record = _lookup(base)
        if record:
            verdict = _grade_record(record)
            verdict["reason"] += (f" Carries the '{exception.strip()}' "
                                  f"exception, which only adds permission.")
            return verdict

    by_family = _grade_by_family(text)
    if by_family:
        return by_family

    if not _registry()["available"]:
        # Say which it is. "Unrecognised" and "we never loaded the list" look
        # identical in a report and mean very different things.
        return _verdict(UNKNOWN, "unrecognised",
                        "The SPDX license list could not be loaded, so this "
                        "string was never looked up.",
                        ["Run once with network access to populate "
                         f"{_cache_dir()}, then rescan."],
                        source="registry-unavailable")

    return _verdict(UNKNOWN, "unrecognised",
                    "Not found in the SPDX license list. Not the same as safe.",
                    ["Identify the license by reading the project's LICENSE "
                     "file before depending on it."],
                    source="spdx-license-list")


def _grade_record(record: dict) -> dict:
    """Turn a registry record into a verdict, citing which flag decided."""
    spdx_id = record["spdx_id"]
    reference = record["reference"]
    deprecated = (" The SPDX id is deprecated; prefer its replacement."
                  if record["deprecated"] else "")

    family, obligation = _copyleft_family(spdx_id)
    if family:
        return _verdict(
            REVIEW, "copyleft",
            f"{record['name']} ({spdx_id}) is a copyleft license.{deprecated}",
            [obligation], spdx_id, "spdx-license-list", reference)

    if record["blue_oak"]:
        return _verdict(
            ALLOWED, "permissive",
            f"{record['name']} ({spdx_id}). Blue Oak Council rates it "
            f"{record['blue_oak']}.{deprecated}",
            [_PERMISSIVE_OBLIGATION], spdx_id, "blue-oak-council", reference)

    if record["osi_approved"]:
        return _verdict(
            ALLOWED, "permissive",
            f"{record['name']} ({spdx_id}) is OSI-approved.{deprecated}",
            [_PERMISSIVE_OBLIGATION], spdx_id, "spdx-license-list", reference)

    return _verdict(
        REVIEW, "unrated",
        f"{record['name']} ({spdx_id}) is in the SPDX list but is neither "
        f"OSI-approved nor rated by Blue Oak Council.{deprecated}",
        [_UNRATED_OBLIGATION], spdx_id, "spdx-license-list", reference)


# ---------------------------------------------------------------------------
# Full license text
# ---------------------------------------------------------------------------
# Restrictions are listed first. A Commons Clause or BUSL file is an
# open-source license text with a condition bolted on, so the Apache and MIT
# signatures match it too - whichever runs first wins, and the restriction has
# to.

_TEXT_SIGNATURES = [
    (BLOCKED, r"commons\s+clause", "Commons Clause"),
    (BLOCKED, r"business\s+source\s+license", "BUSL-1.1"),
    (BLOCKED, r"elastic\s+license", "Elastic-2.0"),
    (BLOCKED, r"server\s+side\s+public\s+license", "SSPL-1.0"),
    (BLOCKED, r"non[\s\-]?commercial\s+use", "non-commercial clause"),
    (REVIEW, r"gnu\s+affero\s+general\s+public\s+license", "AGPL-3.0-only"),
    (REVIEW, r"gnu\s+lesser\s+general\s+public\s+license", "LGPL-3.0-only"),
    (REVIEW, r"gnu\s+general\s+public\s+license", "GPL-3.0-only"),
    (REVIEW, r"mozilla\s+public\s+license", "MPL-2.0"),
    (REVIEW, r"eclipse\s+public\s+license", "EPL-2.0"),
    (ALLOWED, r"permission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge", "MIT"),
    (ALLOWED, r"apache\s+license.{0,40}version\s+2", "Apache-2.0"),
    (ALLOWED, r"redistributions\s+in\s+binary\s+form\s+must\s+reproduce",
     "BSD-3-Clause"),
    (ALLOWED, r"permission\s+to\s+use,\s+copy,\s+modify,\s+and/or\s+distribute",
     "ISC"),
    (ALLOWED, r"this\s+software\s+is\s+provided\s+['\"]as[\-\s]is['\"]", "Zlib"),
]


def _grade_full_text(text: str) -> dict:
    """
    Identify a full license text by its opening wording, then grade the
    identifier it names - so a GPL text gets the same obligations as the id.

    Only the first `_PRIMARY_TEXT_WINDOW` characters are considered. A
    package's own license comes first; anything after it is a bundled
    third-party license that does not govern this package, and scanning it is
    what turned BSD-licensed numpy into a BLOCKED result.
    """
    head = _normalise(text[:_PRIMARY_TEXT_WINDOW])
    for status, signature, label in _TEXT_SIGNATURES:
        if not re.search(signature, head):
            continue
        verdict = _grade_identifier(label)
        if verdict["status"] == status:
            verdict["reason"] = (f"Identified from the license text as "
                                 f"{label}. {verdict['reason']}")
            return verdict
        return _verdict(status, "full-text",
                        f"Identified from the license text as {label}.", [],
                        source="license-text")
    return _verdict(UNKNOWN, "full-text",
                    "License text did not match a known license. Not the same "
                    "as safe.",
                    ["Read the text and record the license manually."],
                    source="license-text")


# ---------------------------------------------------------------------------
# SPDX expressions
# ---------------------------------------------------------------------------
# The SPDX specification fixes the operator order of precedence as
# "+ WITH AND OR", and lets parentheses override it. Flattening the string and
# asking "is there an OR anywhere?" grades the common shapes right and the
# restricting ones wrong: "(MIT OR Apache-2.0) AND CC-BY-NC-4.0" reads as an
# ordinary dual license, when the non-commercial term applies whichever side
# the consumer picks.
#
# WITH is deliberately not an operator here. It has to stay inside the atom so
# the exception is graded together with the license it modifies.
#
# Tokens split on whitespace and punctuation rather than on the words "and" and
# "or", which keeps ids that contain them - GPL-2.0-or-later - intact.

_TOKEN_PATTERN = r"\(|\)|[,;/]|[^\s(),;/]+"


def _tokenize(text: str) -> list:
    """Split an expression into (kind, value) tokens."""
    tokens, words = [], []

    def flush():
        if words:
            identifier = " ".join(words).strip()
            if identifier:
                tokens.append(("ID", identifier))
            words.clear()

    for chunk in re.findall(_TOKEN_PATTERN, text):
        lowered = chunk.lower()
        if chunk in "()":
            flush()
            tokens.append((chunk, chunk))
        elif chunk in ",;":
            flush()                      # a list applies every term at once
            tokens.append(("AND", chunk))
        elif chunk == "/" or lowered == "or":
            flush()
            tokens.append(("OR", chunk))
        elif lowered == "and":
            flush()
            tokens.append(("AND", chunk))
        else:
            words.append(chunk)
    flush()
    return tokens


def _has_operator(tokens: list) -> bool:
    return any(kind in ("AND", "OR") for kind, _ in tokens)


def _pick(verdicts: list, disjunctive: bool) -> dict:
    """
    Reduce several verdicts to one.

    Disjunctive ("MIT OR GPL-3.0") lets the consumer pick a term, so the most
    permissive wins. Conjunctive ("MIT AND CC-BY-NC") applies every term at
    once, so the strictest wins.
    """
    order = ((ALLOWED, REVIEW, UNKNOWN, BLOCKED) if disjunctive
             else (BLOCKED, UNKNOWN, REVIEW, ALLOWED))
    for status in order:
        for verdict in verdicts:
            if verdict["status"] == status:
                return verdict
    return _verdict(UNKNOWN, "compound", "Combined verdict over several terms.",
                    [])


def _parse_atom(tokens: list, pos: int) -> tuple:
    if pos >= len(tokens):
        return _verdict(UNKNOWN, "compound", "Incomplete expression.", []), pos

    kind, value = tokens[pos]
    if kind == "(":
        verdict, pos = _parse_or(tokens, pos + 1)
        if pos < len(tokens) and tokens[pos][0] == ")":
            pos += 1
        return verdict, pos
    if kind in (")", "AND", "OR"):
        # A stray operator or closing paren. Report it unidentified rather than
        # consuming it; the caller's loop advances past it.
        return _verdict(UNKNOWN, "compound", "Malformed expression.", []), pos
    return _grade_identifier(value), pos + 1


def _parse_and(tokens: list, pos: int) -> tuple:
    verdict, pos = _parse_atom(tokens, pos)
    collected = [verdict]
    while pos < len(tokens) and tokens[pos][0] == "AND":
        verdict, pos = _parse_atom(tokens, pos + 1)
        collected.append(verdict)
    return _pick(collected, disjunctive=False), pos


def _parse_or(tokens: list, pos: int) -> tuple:
    verdict, pos = _parse_and(tokens, pos)
    collected = [verdict]
    while pos < len(tokens) and tokens[pos][0] == "OR":
        verdict, pos = _parse_and(tokens, pos + 1)
        collected.append(verdict)
    return _pick(collected, disjunctive=True), pos


def _grade_expression(tokens: list) -> dict:
    verdict, pos = _parse_or(tokens, 0)
    if pos < len(tokens):
        # Malformed input - unbalanced parentheses, a stray operator. Grade the
        # identifiers left over as well and take the strictest, so a
        # restriction sitting past the break cannot be dropped.
        leftover = [_grade_identifier(value)
                    for kind, value in tokens[pos:] if kind == "ID"]
        if leftover:
            verdict = _pick([verdict] + leftover, disjunctive=False)
    return verdict


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_license_detailed(license_string) -> dict:
    """
    Identify a license and report what it obliges you to do.

    Returns:
        status       ALLOWED / REVIEW / BLOCKED / UNKNOWN
        family       permissive / copyleft / unrated / source-available /
                     restricted / ai-community / ai-behavioural /
                     unrecognised / full-text / compound / none
        reason       why, naming the license
        obligations  what you have to do to use it lawfully
        spdx_id      resolved SPDX identifier, "" when it has none
        source       which registry or rule decided
        reference    canonical URL for the license text

    UNKNOWN means "could not identify", never "fine". Callers grade it as a
    risk rather than a pass - see score_engine.LICENSE_PENALTY.
    """
    if license_string is None:
        return _verdict(UNKNOWN, "none", "No license declared.", [])
    if not isinstance(license_string, str):
        license_string = str(license_string)

    raw = license_string.strip()
    if not raw or raw.lower() in _NON_LICENSE_VALUES:
        return _verdict(UNKNOWN, "none", "No license declared.", [])

    # Full license text: identify by wording, not by keyword spotting.
    if len(raw) >= _FULL_TEXT_MIN_CHARS or raw.count("\n") > 3:
        return _grade_full_text(raw)

    tokens = _tokenize(_normalise(raw))
    if not tokens:
        return _verdict(UNKNOWN, "none", "No license declared.", [])

    # Without an operator this is one identifier, not an expression - and it
    # may legitimately contain parentheses, as the trove classifier
    # "... v3 (GPLv3)" does. Grading it whole is what recognises those.
    if not _has_operator(tokens):
        return _grade_identifier(raw)

    return _grade_expression(tokens)


def classify_license(license_string) -> str:
    """
    Classify a license string as ALLOWED / REVIEW / BLOCKED / UNKNOWN.

    Accepts a short identifier ("MIT"), a PyPI trove classifier
    ("License :: OSI Approved :: MIT License"), an SPDX expression
    ("MIT OR (GPL-3.0-only AND CC-BY-NC-4.0)"), or an entire license text.

    Expressions follow SPDX precedence: AND binds tighter than OR, parentheses
    override both, and WITH is not split - the exception is graded together
    with the license it modifies.
    """
    return classify_license_detailed(license_string)["status"]


if __name__ == "__main__":
    versions = registry_versions()
    print(f"SPDX License List {versions['spdx_license_list']} | "
          f"Blue Oak Council List v{versions['blue_oak_council_list']}\n")

    samples = [
        # software licenses
        "MIT",
        "License :: OSI Approved :: MIT License",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "GPL-2.0-or-later",
        "AGPL-3.0-only",
        "LGPL-2.1-only",
        "MPL-2.0",
        "CC0-1.0",
        "BSD-Source-Code",
        # expressions
        "MIT OR GPL-3.0-only",
        "(MIT OR Apache-2.0) AND CC-BY-NC-4.0",
        # source-available, no SPDX exception exists for the rider
        "Apache-2.0 WITH Commons Clause",
        "BUSL-1.1",
        "BSL-1.0",
        # AI model licenses - no SPDX identifier exists at all
        "CreativeML OpenRAIL-M",
        "Llama 3.1 Community License Agreement",
        "NOT_INSTALLED",
    ]
    for sample in samples:
        detail = classify_license_detailed(sample)
        spdx = detail["spdx_id"] or "-"
        print(f"{sample!r:52} {detail['status']:8} {spdx:22} "
              f"[{detail['family']}] via {detail['source'] or '-'}")
        for line in detail["obligations"]:
            print(f"{'':52} -> {line}")

    # The regression that started this rewrite.
    try:
        from importlib.metadata import metadata

        numpy_license = metadata("numpy").get("License", "")
        print(f"\nnumpy License field: {len(numpy_license)} chars "
              f"-> {classify_license(numpy_license)}  (expected ALLOWED)")
    except Exception as exc:  # noqa: BLE001 - numpy may not be installed
        print(f"\n(numpy not available: {exc})")
