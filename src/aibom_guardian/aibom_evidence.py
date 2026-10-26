"""Traceable model disclosures, separate from safety scores and certification.

This is a Guardian subset of transparency fields, not a G7 conformance test.
See docs/trust_score_methodology.md for sources and coverage boundaries.
"""
import re


REFERENCES = {
    "cyclonedx-mlbom": "https://cyclonedx.org/capabilities/mlbom/",
    "openchain-ai": "https://openchain-project.github.io/OpenChain-KWG/guide/ai-sbom_guide/",
    "owasp-supply-chain": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/",
}


def model_evidence(report):
    fields = []

    def add(name, value, source, *, status=None, note=None):
        fields.append({"field": name, "status": status or ("present" if value else "not_observed"),
                       "value": value, "source": source, "note": note,
                       "reference": "cyclonedx-mlbom"})

    for name in ("model_id", "url", "author", "license", "base_model", "datasets",
                 "pipeline", "library", "architectures", "languages"):
        add(name, report.get(name), "huggingface_metadata",
            note="Publisher metadata; not independently verified. Author can be inferred from namespace.")
    sha = report.get("commit_sha")
    valid_sha = isinstance(sha, str) and re.fullmatch(r"[0-9a-fA-F]{40}", sha)
    requested = report.get("requested_revision")
    mismatch = (isinstance(requested, str) and re.fullmatch(r"[0-9a-fA-F]{40}", requested)
                and (not valid_sha or requested.lower() != sha.lower()))
    add("resolved_revision", sha, "huggingface_metadata.sha",
        status="unverified" if not valid_sha or mismatch else "present",
        note="API revision identity, not a signature or file integrity verification.")
    hashes = report.get("file_hashes") or {}
    valid_hashes = {k: v for k, v in hashes.items()
                    if isinstance(v, str) and re.fullmatch(r"[0-9a-fA-F]{64}", v)}
    add("published_file_hashes", valid_hashes, "huggingface_lfs_metadata",
        status="unverified" if len(valid_hashes) != len(hashes) else None,
        note="Published digests only; local bytes have not been compared by this check.")
    add("file_inventory", report.get("files"), "huggingface_metadata.siblings")
    card = report.get("model_card") or {}
    add("model_card", card.get("card_file"), "repository_file_list",
        status="present" if card.get("read_status") == "read" else
               "unverified" if card.get("present") else "not_observed",
        note="A readable card does not establish the correctness of its statements.")
    scan = report.get("pickle_scan") or {}
    add("pickle_static_scan", {k: scan.get(k) for k in ("status", "scanned", "skipped")},
        "picklescan", status="present" if scan.get("status") == "OK" else "unverified",
        note="Only listed scanned files; no model execution or behavioral assessment.")
    for name in ("training_data_rights", "intended_use_approval", "bias_and_behavior",
                 "deployment_security_controls"):
        add(name, None, "human_review", status="needs_review",
            note="Cannot be established by this metadata/static scanner.")
    return {"profile": "guardian-model-evidence-1", "conformance_claim": False,
            "score_effect": "none", "references": REFERENCES,
            "counts": {s: sum(f["status"] == s for f in fields)
                       for s in ("present", "not_observed", "unverified", "needs_review")},
            "fields": fields}
