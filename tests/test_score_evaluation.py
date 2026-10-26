import copy

import pytest

from aibom_guardian.score_evaluation import evaluate


def case(id='case', verdict='BLOCK', basis='synthetic'):
    return {'id': id, 'input': {'type': 'library', 'license_status': 'ALLOWED', 'issues': []},
            'label': {'verdict': verdict, 'basis': basis, 'rationale': 'Deliberate disagreement fixture'}}


def test_disagreement_matrix_and_unlabeled_are_separate():
    unreviewed = case('unreviewed')
    unreviewed['label'] = None
    result = evaluate({'cases': [case(), unreviewed]})
    metrics = result['metrics_by_label_basis']['synthetic']
    assert metrics['confusion_matrix']['BLOCK']['ALLOW'] == 1
    assert metrics['allowed_despite_review_or_block_label'] == 1
    assert metrics['agreement'] == 0
    assert metrics['per_class']['BLOCK']['precision'] is None
    assert result['unlabeled_count'] == 1
    assert result['metrics_by_label_basis']['external_review']['agreement'] is None


def test_review_provenance_required_and_not_pooled():
    reviewed = case('external', 'ALLOW', 'external_review')
    with pytest.raises(ValueError):
        evaluate({'cases': [reviewed]})
    reviewed['label'].update(reviewer='test reviewer', reviewed_at='2026-10-18', reference='fixture-only')
    data = {'cases': [case(), reviewed]}
    original = copy.deepcopy(data)
    result = evaluate(data)
    assert result['metrics_by_label_basis']['external_review']['agreement'] == 1
    assert result['metrics_by_label_basis']['synthetic']['agreement'] == 0
    assert data == original
    assert result['dataset_sha256'] == evaluate(data)['dataset_sha256']
    assert len(result['engine_sha256']) == 64


def test_unverified_collection_is_preserved():
    item = case()
    item['input']['issues'] = None
    item['label'] = None
    result = evaluate({'cases': [item]})
    assert result['cases'][0]['predicted'] == 'WARNING'
    assert result['cases'][0]['confidence'] < 0.7
    assert item['input']['issues'] is None


@pytest.mark.parametrize('data', [{}, {'cases': []}, {'cases': [case(), case()]},
                                   {'cases': [{'id': 'raw-report', 'input': {'packages': []}}]}])
def test_invalid_dataset_rejected(data):
    with pytest.raises(ValueError):
        evaluate(data)
