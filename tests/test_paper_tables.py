"""Small tests for numerical export checks; no experiment or network access."""
import importlib.util
from pathlib import Path
import unittest

import pandas as pd

spec = importlib.util.spec_from_file_location(
    'tables', Path(__file__).resolve().parents[1]/'scripts/analysis/export_paper_tables.py')
tables = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tables)


class TableChecks(unittest.TestCase):
    def test_boolean_fields(self):
        self.assertEqual(tables.truth(pd.Series([1, 0, 'true', 'false', 'yes', ''])).tolist(),
                         [True, False, True, False, True, False])

    def test_accepts_roundoff(self):
        tables.compare(pd.DataFrame({'value': [0.1+0.2]}), pd.DataFrame({'value': [0.3]}))

    def test_rejects_changed_result(self):
        with self.assertRaises(AssertionError):
            tables.compare(pd.DataFrame({'value': [0.4]}), pd.DataFrame({'value': [0.3]}))

    def test_rejects_missing_row(self):
        with self.assertRaises(AssertionError):
            tables.compare(pd.DataFrame({'value': [1]}), pd.DataFrame({'value': [1, 2]}))


if __name__ == '__main__':
    unittest.main()
