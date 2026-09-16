import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from run_native_skill_reviews import valid_result
import run_native_skill_reviews as runner


class NativeReleaseTests(unittest.TestCase):
    def test_preflight_leaves_output_creation_to_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cases=root/'cases.csv'
            cases.write_text('case_id\ncase-test\n')
            def child(command,**kwargs):
                output=Path(command[command.index('--output-dir')+1])
                self.assertFalse(output.exists())
                output.mkdir()
                return SimpleNamespace(returncode=0)
            argv=['runner','--cases',str(cases),'--worktree-root',str(root),
                  '--output',str(root/'out'),'--workers','1']
            with patch.object(sys,'argv',argv),patch.object(runner.subprocess,'run',side_effect=child):
                runner.main()

    def test_valid_result_requires_verified_skill_and_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            self.assertFalse(valid_result(p))
            (p/'execution.json').write_text(json.dumps({'status':'completed'}))
            (p/'review_response.json').write_text(json.dumps({'findings':[]}))
            (p/'skill_loading_audit.json').write_text(json.dumps({'verified':False}))
            self.assertFalse(valid_result(p))
            (p/'skill_loading_audit.json').write_text(json.dumps({'verified':True}))
            self.assertTrue(valid_result(p))

    def test_released_counts(self):
        result=subprocess.run([sys.executable,str(ROOT/'scripts/summarize_native_skill_reviews.py')],
                              check=True,capture_output=True,text=True)
        summary=json.loads(result.stdout)
        self.assertEqual(summary['review_count'],267)
        self.assertEqual(summary['candidate_finding_count'],1484)


if __name__=='__main__':unittest.main()
