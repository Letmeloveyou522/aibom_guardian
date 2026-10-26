"""Evaluate saved score inputs against explicitly sourced review labels."""
import argparse
import hashlib
import json
from pathlib import Path

from .reporting import POLICY_VERSION
from .score_engine import CATEGORY_WEIGHTS, calculate_trust_score

VERDICTS = ('ALLOW', 'WARNING', 'BLOCK')
BASES = ('synthetic', 'team_review', 'external_review')


def evaluate(document):
    if not isinstance(document, dict) or not isinstance(document.get('cases'), list) or not document['cases']:
        raise ValueError('Expected a non-empty cases array')
    rows, seen = [], set()
    groups = {basis: {a: {b: 0 for b in VERDICTS} for a in VERDICTS} for basis in BASES}
    for case in document['cases']:
        if not isinstance(case, dict) or not isinstance(case.get('id'), str) or not case['id'].strip():
            raise ValueError('Each case requires an ID')
        if case['id'] in seen:
            raise ValueError('Duplicate case ID')
        seen.add(case['id'])
        evidence = case.get('input')
        if not isinstance(evidence, dict) or evidence.get('type') not in ('library', 'model'):
            raise ValueError('Provide library/model score_engine inputs, not raw scan reports')
        if 'issues' not in evidence or (evidence['issues'] is not None and (
            not isinstance(evidence['issues'], list) or any(not isinstance(i, dict) for i in evidence['issues'])
        )):
            raise ValueError('Score input must contain an issues array or null for unverified collection')
        if not isinstance(evidence.get('license_status'), str):
            raise ValueError('Score input requires license_status')
        label = case.get('label')
        if label is not None:
            if not isinstance(label, dict) or label.get('verdict') not in VERDICTS or label.get('basis') not in BASES:
                raise ValueError('Labels require a verdict and an explicit basis')
            if not isinstance(label.get('rationale'), str) or not label['rationale'].strip():
                raise ValueError('Labels require a rationale')
            if label['basis'] != 'synthetic' and any(
                not isinstance(label.get(k), str) or not label[k].strip()
                for k in ('reviewer', 'reviewed_at', 'reference')
            ):
                raise ValueError('Review labels require reviewer, reviewed_at and reference')
        result = calculate_trust_score(evidence)
        expected = label['verdict'] if label else None
        if label:
            groups[label['basis']][expected][result['verdict']] += 1
        rows.append({'id': case['id'], 'label': label, 'predicted': result['verdict'],
                     'matches_label': result['verdict'] == expected if label else None,
                     'trust_score': result['trust_score'], 'confidence': result['confidence'],
                     'hard_block': result['hard_block'], 'hard_block_reasons': result['hard_block_reasons'],
                     'breakdown': result['breakdown']})
    metrics = {}
    for basis, matrix in groups.items():
        count = sum(sum(row.values()) for row in matrix.values())
        per_class = {}
        for verdict in VERDICTS:
            actual = sum(matrix[verdict].values())
            predicted = sum(matrix[a][verdict] for a in VERDICTS)
            tp = matrix[verdict][verdict]
            per_class[verdict] = {'support': actual,
                                  'precision': tp / predicted if predicted else None,
                                  'recall': tp / actual if actual else None}
        metrics[basis] = {'labeled_cases': count, 'confusion_matrix': matrix,
                          'agreement': sum(matrix[v][v] for v in VERDICTS) / count if count else None,
                          'allowed_despite_review_or_block_label': matrix['WARNING']['ALLOW'] + matrix['BLOCK']['ALLOW'],
                          'blocked_despite_allow_label': matrix['ALLOW']['BLOCK'],
                          'per_class': per_class}
    encoded = json.dumps(document, sort_keys=True, ensure_ascii=False).encode('utf-8')
    return {'policy_version': POLICY_VERSION, 'category_weights': dict(CATEGORY_WEIGHTS),
            'dataset_sha256': hashlib.sha256(encoded).hexdigest(),
            'engine_sha256': hashlib.sha256(Path(__file__).with_name('score_engine.py').read_bytes()).hexdigest(),
            'case_count': len(rows), 'unlabeled_count': sum(r['label'] is None for r in rows),
            'metrics_by_label_basis': metrics, 'cases': rows,
            'limitations': ['Agreement with supplied labels, not a probability of safety.',
                            'Synthetic rule checks are not external validation.',
                            'Reviewer claims and references are recorded, not independently authenticated.',
                            'Repository scoring and upstream detection accuracy are not evaluated.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset')
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.dataset).read_text(encoding='utf-8-sig'))
        result = evaluate(data)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (OSError, ValueError, TypeError) as exc:
        parser.exit(1, f'Evaluation failed: {type(exc).__name__}: {exc}\n')


if __name__ == '__main__':
    main()
