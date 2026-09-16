import csv
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT/path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


snapshot = load('snapshot', 'scripts/analysis/build_validated_issue_snapshot.py')
prepare = load('prepare', 'scripts/prepare_native_skill_assessment.py')
recovery = load('recovery', 'scripts/analyze_native_skill_recovery.py')


def write(path, records):
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


class NewSnapshotTests(unittest.TestCase):
    def fixture(self, root):
        raw, assessment = root/'raw', root/'assessment'
        raw.mkdir(); assessment.mkdir()
        (raw/'snapshot_manifest.json').write_text(json.dumps({'snapshot_id':'new_raw', 'rq2_ready':True}))
        (assessment/'manifest.json').write_text(json.dumps({'status':'formal_complete'}))
        write(raw/'analysis_pr_level.csv', [dict(group='ai', repo_name='test/repo', pr_number='1',
            quality_gate_pass='true', introduced_quality_alerts=1, introduced_security_alerts=0),
            dict(group='human', repo_name='test/zero', pr_number='2', quality_gate_pass='true',
                 introduced_quality_alerts=0, introduced_security_alerts=0)])
        write(assessment/'model_adjudications.csv', [dict(alert_id='a',group='ai',repo_name='test/repo',
            pr_number='1',issue_domain='quality',condition_present='yes',introduced_by_pr='yes',valid_issue='yes',
            quality_category='maintainability',language='Python',task_type='feat',rule_id='test/rule',
            location_class='production',problem_severity='warning',precision='high')])
        label = dict(alert_id='a', status='completed', disposition='confirmed_valid',
                     human_condition_present='yes',human_introduced_by_pr='yes',human_valid_issue='yes')
        write(root/'labels.csv', [label])
        return SimpleNamespace(raw_snapshot_dir=raw, adjudication_dir=assessment,
            output_dir=root/'out',human_labels=root/'labels.csv',derived_snapshot_id='new_confirmed',new_experiment=True)

    def test_new_sample_and_zero_alert_pr(self):
        with tempfile.TemporaryDirectory() as temp:
            args=self.fixture(Path(temp)); snapshot.run(args)
            manifest=json.loads((args.output_dir/'snapshot_manifest.json').read_text())
            self.assertEqual(manifest['counts']['quality_gated_pr_n'],2)
            self.assertEqual(manifest['counts']['validated_quality_n'],1)
            self.assertEqual(manifest['snapshot_id'],'new_confirmed')

    def test_historical_mode_stays_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            args=self.fixture(Path(temp)); args.new_experiment=False
            with self.assertRaises(snapshot.SnapshotError): snapshot.run(args)

    def test_reject_missing_raw_alert(self):
        with tempfile.TemporaryDirectory() as temp:
            args=self.fixture(Path(temp))
            records=prepare.rows(args.raw_snapshot_dir/'analysis_pr_level.csv')
            records[0]['introduced_quality_alerts']='2'
            write(args.raw_snapshot_dir/'analysis_pr_level.csv', records)
            with self.assertRaises(snapshot.SnapshotError): snapshot.run(args)

    def test_reject_inconsistent_human_label(self):
        with tempfile.TemporaryDirectory() as temp:
            args=self.fixture(Path(temp)); records=prepare.rows(args.human_labels)
            records[0]['human_valid_issue']='no'; write(args.human_labels,records)
            with self.assertRaises(snapshot.SnapshotError): snapshot.run(args)


class NewReviewTests(unittest.TestCase):
    def test_prepare_manual_decision_then_score(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); run=root/'run'/'case-test'
            for i,valid in [(1,False),(2,True),(3,True)]:
                attempt=run/f'attempt-{i:03d}';attempt.mkdir(parents=True)
                (attempt/'launcher_status.json').write_text('{}')
                (attempt/'execution.json').write_text(json.dumps({'status':'completed' if valid else 'failed'}))
                (attempt/'skill_loading_audit.json').write_text(json.dumps({'verified':valid}))
                (attempt/'review_response.json').write_text(json.dumps({'findings':[{'description':str(i)}]}))
            write(root/'cases.csv',[dict(case_id='case-test')])
            write(root/'refs.csv',[dict(case_id='case-test',reference_id='ref-1',group='ai',
                validated_issue_reference='true',quality_broad_reference='true',quality_primary_reference='true',
                semantic_recovered='0',file_path='src/example.py',rule_id='test/rule')])
            write(root/'mapping.csv',[dict(case_id='case-test',reference_id='ref-1',root_cause_category='example')])
            args=SimpleNamespace(run_dir=root/'run',cases=root/'cases.csv',references=root/'refs.csv',
                                 root_cause_mapping=root/'mapping.csv',output=root/'prepared')
            prepare.prepare(args)
            index=prepare.rows(args.output/'review_index.csv')
            self.assertEqual(index[0]['selected_attempt'],'attempt-002')
            packet=(args.output/'assessment_packets.json').read_text()
            self.assertNotIn('semantic_recovered',packet)
            self.assertIn('src/example.py',packet)
            with self.assertRaises(ValueError): recovery.compare(args.output)
            decision=args.output/'human_assessment/human_decisions.json'
            rows=json.loads(decision.read_text());rows[0].update(relation='same_issue',matched_reference_ids=['ref-1'])
            decision.write_text(json.dumps(rows))
            scored=recovery.compare(args.output)
            self.assertEqual(scored[0]['skill_recovered'],1)
            rows[0]['matched_reference_ids']=['outside'];decision.write_text(json.dumps(rows))
            with self.assertRaises(ValueError): recovery.compare(args.output)
            with self.assertRaises(ValueError): prepare.prepare(args)

    def test_unfinished_attempt_blocks_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp);(p/'attempt-001').mkdir()
            with self.assertRaises(ValueError): prepare.select_attempt(p)


if __name__ == '__main__': unittest.main()
