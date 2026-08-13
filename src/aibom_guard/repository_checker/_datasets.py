"""
Reports which expected sections a dataset card documents: sources, collection
method, preprocessing, licence, citation.

Headings are matched in English and Korean - cards on the Hub use both, and
matching only English would report documented sections as missing.
"""

from __future__ import annotations

import re

from ._constants import INVALID_LICENSE_VALUES, MAX_EVIDENCE_CHARS


def check_dataset_documentation(
    readme_text: str | None,
    card_data: dict | None = None,
) -> dict:
    """Deterministic Dataset Card / README documentation checks."""
    card_data = card_data or {}
    text = readme_text or ""
    checked = True
    card_exists = bool(text.strip()) or bool(card_data)

    license_value = _extract_dataset_license(card_data, text)
    license_documented = license_value is not None

    source_documented, source_evidence, source_conf = _section_documented(
        text,
        headings=(
            r"source", r"data\s+sources?", r"origin", r"dataset\s+source",
            r"출처", r"원천\s*데이터", r"데이터\s*출처",
        ),
        body_hints=(
            r"https?://", r"\barxiv\b", r"\bdoi\b", r"collected from",
            r"derived from", r"based on", r"원본", r"출처",
        ),
    )
    collection_documented, collection_evidence, collection_conf = _section_documented(
        text,
        headings=(
            r"data\s+collection", r"collection\s+process", r"collection\s+method",
            r"curation", r"acquisition", r"수집\s*방법", r"데이터\s*수집",
            r"구축\s*방법", r"생성\s*방법",
        ),
        body_hints=(
            r"we collected", r"scraped", r"crawled", r"annotated",
            r"수집", r"크롤", r"구축",
        ),
    )
    processing_documented, processing_evidence, processing_conf = _section_documented(
        text,
        headings=(
            r"preprocessing", r"cleaning", r"annotation", r"labeling",
            r"filtering", r"processing", r"전처리", r"정제", r"라벨링",
            r"어노테이션", r"필터링", r"가공\s*방법",
        ),
        body_hints=(
            r"preprocessed", r"filtered", r"cleaned", r"tokeniz",
            r"전처리", r"정제", r"필터",
        ),
    )
    citation_documented, citation_evidence, citation_conf = _section_documented(
        text,
        headings=(r"citation", r"citing", r"bibtex", r"참고\s*문헌", r"인용"),
        body_hints=(r"@\w+\{", r"please cite", r"bibtex", r"인용"),
    )

    missing = []
    if not license_documented:
        missing.append("license")
    if source_documented is False:
        missing.append("source")
    if collection_documented is False:
        missing.append("collection_method")
    if processing_documented is False:
        missing.append("processing_method")
    if citation_documented is False:
        missing.append("citation")

    return {
        "checked": checked,
        "card_exists": card_exists,
        "license": license_value,
        "license_documented": license_documented,
        "source_documented": source_documented,
        "collection_method_documented": collection_documented,
        "processing_method_documented": processing_documented,
        "citation_documented": citation_documented,
        "missing_fields": missing,
        "evidence": {
            "source": source_evidence,
            "collection_method": collection_evidence,
            "processing_method": processing_evidence,
            "citation": citation_evidence,
            "license": license_value,
        },
        "confidence": {
            "source": source_conf,
            "collection_method": collection_conf,
            "processing_method": processing_conf,
            "citation": citation_conf,
        },
    }


def _extract_dataset_license(card_data: dict, text: str) -> str | None:
    for key in ("license", "licence", "licenses"):
        if key in card_data and card_data[key] is not None:
            val = card_data[key]
            if isinstance(val, list):
                if not val:
                    continue
                val = val[0]
            lic = str(val).strip()
            if lic.lower() not in INVALID_LICENSE_VALUES:
                return lic

    # YAML front matter
    fm = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if fm:
        for line in fm.group(1).splitlines():
            m = re.match(r"^license\s*:\s*[\"']?([^\"'\n#]+)", line, re.IGNORECASE)
            if m:
                lic = m.group(1).strip()
                if lic.lower() not in INVALID_LICENSE_VALUES:
                    return lic

    # License section
    section = _extract_section(text, (r"license", r"licence", r"라이선스"))
    if section:
        # Prefer an SPDX-like token
        token = re.search(r"\b([A-Za-z0-9.+-]+(?:-[0-9.]+)?)\b", section)
        if token:
            lic = token.group(1)
            if lic.lower() not in INVALID_LICENSE_VALUES and lic.lower() not in (
                "the", "a", "an", "this", "under", "see",
            ):
                return lic
    return None


def _extract_section(text: str, heading_patterns: tuple[str, ...]) -> str | None:
    if not text:
        return None
    heading_re = "|".join(heading_patterns)
    pattern = re.compile(
        rf"^(?:\#{{1,3}}\s*|{re.escape('##')}\s*)?(?:{heading_re})\s*$",
        re.IGNORECASE | re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        # also allow bold headings
        pattern2 = re.compile(
            rf"^\*\*(?:{heading_re})\*\*\s*$",
            re.IGNORECASE | re.MULTILINE,
        )
        match = pattern2.search(text)
    if not match:
        return None
    start = match.end()
    next_heading = re.search(r"^\#{1,3}\s+\S", text[start:], re.MULTILINE)
    end = start + next_heading.start() if next_heading else min(len(text), start + 800)
    return text[start:end].strip()


def _section_documented(
    text: str,
    headings: tuple[str, ...],
    body_hints: tuple[str, ...],
) -> tuple[bool | None, str | None, str]:
    section = _extract_section(text, headings)
    if section:
        snippet = section[:MAX_EVIDENCE_CHARS]
        # Require some substance beyond the heading itself
        if len(section) >= 20 and re.search("|".join(body_hints), section, re.IGNORECASE):
            return True, snippet, "high"
        if len(section) >= 40:
            return True, snippet, "medium"
        return None, snippet, "low"

    # Do not treat a lone keyword in the body as documented
    return False, None, "high"
