import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recovery', ROOT / 'scripts/analyze_native_skill_recovery.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def test_released_primary_and_broad_counts(self):
        rows = recovery.compare(ROOT / 'data/results/native_skill_review')
        self.assertEqual(len(rows), 187)
        tables = recovery.tables(rows)
        for tier, expected in [('primary', (114, 21, 32, 14, 18, 7, 75)),
                               ('broad', (187, 37, 53, 28, 25, 9, 125))]:
            summary = next(r for r in tables['comparison_summary.csv']
                           if r['tier'] == tier and r['group'] == 'all')
            fields = ('reference_n', 'baseline_recovered_n', 'skill_recovered_n',
                      'both_n', 'skill_only_n', 'baseline_only_n', 'neither_n')
            self.assertEqual(tuple(summary[k] for k in fields), expected)
        broad = [r for r in tables['root_cause_comparison.csv']
                 if r['tier'] == 'broad' and r['group'] == 'all']
        self.assertEqual(len(broad), 5)
        self.assertEqual(sum(r['skill_recovered_n'] for r in broad), 53)

    def test_empty_stratum_is_not_zero_recall(self):
        result = recovery.summarize([])
        self.assertEqual(result['reference_n'], 0)
        self.assertEqual(result['skill_recall_pct'], '')


if __name__ == '__main__':
    unittest.main()
