"""Recount the released native-Skill review outputs; no model calls."""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results',type=Path,default=Path(__file__).resolve().parents[1]/'data/results/native_skill_review')
    a=p.parse_args()
    rows=list(csv.DictReader((a.results/'review_index.csv').open()))
    if len({r['case_id'] for r in rows})!=len(rows):raise ValueError('Duplicate case IDs')
    count=0
    for r in rows:
        path=a.results/r['review_path']
        findings=json.loads(path.read_text())['findings']
        if len(findings)!=int(r['finding_count']):raise ValueError(f'Count mismatch: {path}')
        if not json.loads((path.parent/'skill_loading_audit.json').read_text())['verified']:raise ValueError('Unverified Skill')
        count+=len(findings)
    totals={'review_count':len(rows),'candidate_finding_count':count,
            'selected_by_run':dict(Counter(r['source_run'] for r in rows)),
            'models':dict(Counter(r['model'] for r in rows))}
    expected=json.loads((a.results/'summary.json').read_text())
    for k in ('review_count','candidate_finding_count'):
        if expected[k]!=totals[k]:raise ValueError(f'Summary mismatch: {k}')
    print(json.dumps(totals,indent=2))


if __name__=='__main__':main()
