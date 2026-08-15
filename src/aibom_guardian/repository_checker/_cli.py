"""
Standalone CLI: python -m aibom_guardian.repository_checker <target>
"""

from __future__ import annotations

import argparse
import json
import logging

from ._api import check_repository


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m aibom_guardian.repository_checker",  # else argparse says "__main__.py"
        description="AIBOM-Guardian repository / supply-chain trust checker",
    )
    parser.add_argument("target", help="GitHub URL, HF URL/id, or PyPI package")
    parser.add_argument(
        "--type", dest="target_type", default="auto",
        choices=["auto", "github", "hf_model", "hf_dataset", "pypi", "local"],
    )
    parser.add_argument("--revision", default=None)
    parser.add_argument("--local-file", default=None)
    parser.add_argument("--expected-sha256", default=None)
    parser.add_argument("--artifact-filename", default=None)
    parser.add_argument("--signature-file", default=None)
    parser.add_argument("--signature-bundle", default=None)
    parser.add_argument("--signature-key", default=None)
    parser.add_argument("--certificate-identity", default=None)
    parser.add_argument("--certificate-oidc-issuer", default=None)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", action="store_true", help="print full JSON result")
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    result = check_repository(
        args.target,
        target_type=args.target_type,
        revision=args.revision,
        local_file=args.local_file,
        expected_sha256=args.expected_sha256,
        artifact_filename=args.artifact_filename,
        signature_file=args.signature_file,
        signature_bundle=args.signature_bundle,
        signature_key=args.signature_key,
        certificate_identity=args.certificate_identity,
        certificate_oidc_issuer=args.certificate_oidc_issuer,
        timeout=args.timeout,
    )
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"target : {result['target']}")
        print(f"score  : {result['trust_score']}")
        print(f"verdict: {result['verdict']}")
        print(f"openssf: {result.get('openssf_score')}")
        print(f"prov   : {result.get('provenance')} ({(result.get('provenance_detail') or {}).get('status')})")
        if result.get("issues"):
            print("issues :")
            for issue in result["issues"][:10]:
                print(f"  - [{issue['severity']}] {issue['detail']}")
    return 0
