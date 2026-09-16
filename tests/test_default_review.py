import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('default_review', ROOT / 'scripts/analyze_default_review.py')
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DefaultReviewTests(unittest.TestCase):
    def test_complete_combined_labels_and_recovery(self):
        refs, matches = MODULE.recovery(ROOT / 'data/results/default_review')
        truth = lambda value: str(value).lower() in ('1', 'true', 'yes')
        for tier, count, recovered in [('primary', 114, 21), ('broad', 187, 37)]:
            selected = [r for r in refs if truth(r['validated_issue_reference']) and truth(r[f'quality_{tier}_reference'])]
            self.assertEqual(len(selected), count)
            self.assertEqual(sum((r['case_id'], r['reference_id']) in matches for r in selected), recovered)

    def test_no_private_annotation_fields(self):
        rows = MODULE.read_csv(ROOT / 'data/results/default_review/human_decisions.csv')
        self.assertEqual(len(rows), 1106)
        self.assertEqual(set(rows[0]), {'case_id', 'finding_id', 'relation', 'matched_reference_ids', 'reference_scope'})


if __name__ == '__main__':
    unittest.main()
