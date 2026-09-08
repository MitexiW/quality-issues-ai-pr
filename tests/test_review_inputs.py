import csv
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def write_rows(path, rows):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


class ReviewInputsTest(unittest.TestCase):
    def test_queues_cover_all_alerts_and_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/'model.csv'
            rows = [dict(alert_id=str(i), condition_present='yes',
                         introduced_by_pr='yes', valid_issue=value)
                    for i, value in enumerate(['yes', 'contextual_exception', 'uncertain'])]
            write_rows(source, rows)
            command = [sys.executable, str(ROOT/'scripts/prepare_human_review_queues.py'),
                       '--input', str(source), '--output-dir', str(root/'queues')]
            subprocess.run(command, check=True, capture_output=True)
            actual = []
            for name, count in [('retained', 1), ('excluded', 2)]:
                with (root/'queues'/f'{name}.csv').open() as stream:
                    queue = list(csv.DictReader(stream))
                self.assertEqual(len(queue), count)
                actual.extend(r['alert_id'] for r in queue)
            self.assertEqual(sorted(actual), ['0', '1', '2'])
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_export_diff_from_local_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root/'cache'/'example_project.git'
            repo.mkdir(parents=True)
            env = dict(os.environ, GIT_AUTHOR_NAME='Test', GIT_COMMITTER_NAME='Test',
                       GIT_AUTHOR_EMAIL='test@example.invalid', GIT_COMMITTER_EMAIL='test@example.invalid')
            def git(*args):
                return subprocess.run(['git', '-C', str(repo), *args], check=True,
                                      capture_output=True, text=True, env=env).stdout.strip()
            git('init')
            (repo/'a.txt').write_text('before\n')
            git('add', 'a.txt')
            git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-m', 'base')
            base = git('rev-parse', 'HEAD')
            (repo/'a.txt').write_text('after\n')
            git('add', 'a.txt')
            git('-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', 'commit', '-m', 'head')
            head = git('rev-parse', 'HEAD')
            # Exporter uses a bare-cache path, as does the experiment.
            bare = root/'bare'/'example_project.git'
            bare.parent.mkdir()
            subprocess.run(['git', 'clone', '--bare', str(repo), str(bare)],
                           check=True, capture_output=True)
            write_rows(root/'cases.csv', [dict(group='ai', repo_name='example/project', pr_number='1')])
            jobs = [dict(repo_name='example/project', pr_number='1', revision=r, checkout_ref=sha)
                    for r, sha in [('before', base), ('after', head)]]
            write_rows(root/'jobs.csv', jobs)
            command = [sys.executable, str(ROOT/'scripts/rq3/export_rq3_diffs.py'),
                       '--cases', str(root/'cases.csv'), '--ai-jobs', str(root/'jobs.csv'),
                       '--human-jobs', str(root/'jobs.csv'), '--ai-cache-dir', str(root/'bare'),
                       '--human-cache-dir', str(root/'bare'), '--output', str(root/'diffs.jsonl')]
            subprocess.run(command, check=True, capture_output=True)
            import json
            diff = json.loads((root/'diffs.jsonl').read_text())
            self.assertIn('-before\n+after', diff['diff'])
            self.assertEqual(diff['base_sha'], base)


if __name__ == '__main__':
    unittest.main()
