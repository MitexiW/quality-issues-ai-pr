"""Recompute default RQ3 recovery from all released reviews and human labels."""
import argparse
import csv
import json
import re
from pathlib import Path


def read_csv(path):
    with path.open(newline='', encoding='utf-8') as stream:
        return list(csv.DictReader(stream))


def recovery(results):
    labels = read_csv(results / 'human_decisions.csv')
    expected = set()
    for row in read_csv(results / 'review_index.csv'):
        findings = json.loads((results / row['review_path']).read_text())['findings']
        if len(findings) != int(row['finding_count']):
            raise ValueError('Review finding count mismatch')
        for finding in findings:
            key = row['case_id'], finding['finding_id']
            if key in expected:
                raise ValueError('Duplicate finding')
            expected.add(key)
    if len(labels) != len(expected) or {(r['case_id'], r['finding_id']) for r in labels} != expected:
        raise ValueError('Human labels must cover every finding exactly once')
    references = read_csv(results / 'reference_inputs.csv')
    keys = {(r['case_id'], r['reference_id']) for r in references}
    if len(keys) != len(references):
        raise ValueError('Duplicate reference')
    matched = {}
    for row in labels:
        ids = [x for x in re.split(r'[|;]', row['matched_reference_ids']) if x]
        if row['relation'] not in ('same_issue', 'related_distinct', 'no_match', 'no_reference'):
            raise ValueError('Unfinished human decision')
        if (row['relation'] == 'same_issue') != bool(ids) or len(ids) != len(set(ids)):
            raise ValueError('Invalid matched reference list')
        for ref in ids:
            key = row['case_id'], ref
            if key not in keys:
                raise ValueError('Unknown or cross-PR reference')
            matched.setdefault(key, []).append(row['finding_id'])
    return references, matched


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results', type=Path, default=Path(__file__).resolve().parents[1] / 'data/results/default_review')
    p.add_argument('--output', type=Path, default=Path('outputs/default-review'))
    a = p.parse_args()
    references, matched = recovery(a.results)
    for r in references:
        key = r['case_id'], r['reference_id']
        r['semantic_recovered'] = int(key in matched)
        r['semantic_recovered_by_finding_ids'] = '|'.join(matched.get(key, []))
    a.output.mkdir(parents=True, exist_ok=True)
    with (a.output / 'reference_inputs.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(references[0]))
        writer.writeheader(); writer.writerows(references)
    truth = lambda value: str(value).lower() in ('1', 'true', 'yes')
    for tier in ('primary', 'broad'):
        selected = [r for r in references if truth(r['validated_issue_reference']) and truth(r[f'quality_{tier}_reference'])]
        print(f"{tier}: {sum(r['semantic_recovered'] for r in selected)}/{len(selected)}")


if __name__ == '__main__':
    main()
