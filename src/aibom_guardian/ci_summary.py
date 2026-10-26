"""Render saved Guardian reports for CI job summaries; never change scan policy."""
import argparse
import html
import json
from pathlib import Path

from .reporting import compare_reports, project_summary


def _cell(value):
    text = html.escape(str(value), quote=True)
    for char in ('|', '`', '*', '_', '[', ']', '\\'):
        text = text.replace(char, f'&#{ord(char)};')
    return ' '.join(text.split())[:300]


def render(report, before=None):
    # Reuse the comparison validator, including malformed row detection.
    compare_reports(report, report)
    summary = project_summary(report)
    lines = ['## AIBOM Guardian scan', '',
             'Policy verdicts are not a guarantee of safety. Unverified results need review.', '',
             '| Packages | ALLOW | WARNING | BLOCK | Unscanned entries |',
             '| --- | --- | --- | --- | --- |',
             f"| {summary['package_count']} | {summary['verdicts']['ALLOW']} | {summary['verdicts']['WARNING']} | {summary['verdicts']['BLOCK']} | {summary['unscanned_entry_count']} |", '',
             f"Unverified vulnerability lookups: {summary['vulnerabilities_unverified_count']}. "
             f"Unverified license lookups: {summary['license_unverified_count']}.", '',
             'Scope: ' + _cell(json.dumps(summary['scope'], ensure_ascii=False)) + '.', '',
             '| Package | Version | Verdict | Advisory count | License |',
             '| --- | --- | --- | --- | --- |']
    for row in summary['attention_packages'][:100]:
        values = [row['package'], row['version'], row['verdict'],
                  'unverified' if row['advisory_count'] is None else row['advisory_count'],
                  'unverified' if row['license_unverified'] else row['license_status']]
        lines.append('| ' + ' | '.join(_cell(v) for v in values) + ' |')
    if len(summary['attention_packages']) > 100:
        lines += ['', 'Only the first 100 attention rows are shown. See the full JSON report.']
    if report.get('models'):
        lines += ['', 'Model details are in the full JSON report; the table above covers packages only.']
    if report.get('unscanned'):
        lines += ['', 'Unscanned requirements/errors (first 20):', '']
        lines += ['- ' + _cell(item) for item in report['unscanned'][:20]]
    if before is not None:
        diff = compare_reports(before, report)
        lines += ['', '### Comparison with supplied baseline', '',
                  'Missing advisory IDs or removed packages do not prove remediation.', '']
        for key in ('metadata_available', 'scope_changed', 'environment_changed', 'policy_changed', 'options_changed'):
            lines.append(f'- {key}: {str(diff[key]).lower()}')
        lines += ['', '| Package | Comparison | Newly reported IDs | No longer reported IDs |',
                  '| --- | --- | --- | --- |']
        for row in diff['findings'][:100]:
            values = [row['package'], row['status'], ', '.join(row.get('new', [])),
                      ', '.join(row.get('no_longer_reported', []))]
            lines.append('| ' + ' | '.join(_cell(v) for v in values) + ' |')
        lines += ['', f"Added components: {len(diff['added'])}; removed components: {len(diff['removed'])}. "
                  'Comparison rows are limited to 100. Use the JSON comparison for full details.']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report')
    parser.add_argument('--before', help='Optional saved baseline report')
    args = parser.parse_args()
    try:
        report = json.loads(Path(args.report).read_text(encoding='utf-8-sig'))
        before = json.loads(Path(args.before).read_text(encoding='utf-8-sig')) if args.before else None
        print(render(report, before), end='')
    except (OSError, ValueError, TypeError, AttributeError) as exc:
        parser.exit(1, f'Cannot render report: {type(exc).__name__}\n')


if __name__ == '__main__':
    main()
