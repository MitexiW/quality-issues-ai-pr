"""Recompute descriptive RQ3 recovery from released human labels; no API calls."""
import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def read_csv(path):
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def truth(value):
    return str(value).lower() in ('1', 'true', 'yes')


def compare(results):
    inputs = results / 'human_assessment'
    references = read_csv(inputs / 'reference_inputs.csv')
    default_results = results.parent / 'default_review'
    if default_results.exists():
        from analyze_default_review import recovery
        _, baseline_matches = recovery(default_results)
        references = [{**r, 'semantic_recovered': int((r['case_id'], r['reference_id']) in baseline_matches)}
                      for r in references]
    mapping = read_csv(inputs / 'root_cause_mapping.csv')
    decisions = json.loads((inputs / 'human_decisions.json').read_text())
    index = read_csv(results / 'review_index.csv')
    expected = {}
    for case in index:
        findings = json.loads((results / case['review_path']).read_text())['findings']
        if len(findings) != int(case['finding_count']):
            raise ValueError('Finding count mismatch')
        for number in range(1, len(findings) + 1):
            fid = f"{case['case_id']}-f{number:04d}"
            if fid in expected:
                raise ValueError('Duplicate finding')
            expected[fid] = case['case_id']
    keys = {(r['case_id'], r['reference_id']) for r in references}
    categories = {(r['case_id'], r['reference_id']): r for r in mapping}
    if len(keys) != len(references) or len(categories) != len(mapping) or keys != set(categories):
        raise ValueError('Reference/category mapping mismatch')
    if len(decisions) != len(expected) or {d['finding_id'] for d in decisions} != set(expected):
        raise ValueError('Each finding must have exactly one human decision')
    cases_with_refs = {key[0] for key in keys}
    matched = {}
    for decision in decisions:
        case = decision['case_id']
        relation = decision['relation']
        refs = decision['matched_reference_ids']
        if expected[decision['finding_id']] != case:
            raise ValueError('Finding belongs to another PR')
        if relation not in ('same_issue', 'related_distinct', 'no_match', 'no_reference'):
            raise ValueError('Unfinished human decision')
        if (relation == 'same_issue') != bool(refs) or len(refs) != len(set(refs)):
            raise ValueError('Invalid matched reference list')
        if (relation == 'no_reference') != (case not in cases_with_refs):
            raise ValueError('Invalid no_reference label')
        for ref in refs:
            if (case, ref) not in keys:
                raise ValueError('Out-of-scope or cross-PR match')
            matched.setdefault((case, ref), []).append(decision['finding_id'])
    rows = []
    for ref in references:
        key = ref['case_id'], ref['reference_id']
        if not truth(ref['validated_issue_reference']) or not truth(ref['quality_broad_reference']):
            raise ValueError('References must be human-confirmed broad-tier references')
        old, new = int(truth(ref['semantic_recovered'])), int(key in matched)
        rows.append(dict(case_id=key[0], reference_id=key[1], group=ref['group'],
                         primary=int(truth(ref['quality_primary_reference'])),
                         baseline_recovered=old, skill_recovered=new,
                         paired_outcome={(0, 0): 'neither', (0, 1): 'skill_only',
                                         (1, 0): 'baseline_only', (1, 1): 'both'}[old, new],
                         skill_finding_ids=json.dumps(matched.get(key, [])),
                         root_cause_category=categories[key]['root_cause_category']))
    return rows


def summarize(rows, **labels):
    n = len(rows)
    old = sum(r['baseline_recovered'] for r in rows)
    new = sum(r['skill_recovered'] for r in rows)
    paired = Counter(r['paired_outcome'] for r in rows)
    return dict(**labels, reference_n=n, baseline_recovered_n=old, skill_recovered_n=new,
                baseline_recall_pct=100 * old / n if n else '',
                skill_recall_pct=100 * new / n if n else '',
                difference_pp=100 * (new - old) / n if n else '',
                **{key + '_n': paired[key] for key in ('both', 'skill_only', 'baseline_only', 'neither')})


def tables(rows):
    summaries, categories = [], []
    for tier in ('primary', 'broad'):
        for group in ('all', 'ai', 'human'):
            selected = [r for r in rows if (tier == 'broad' or r['primary'])
                        and (group == 'all' or r['group'] == group)]
            summaries.append(summarize(selected, tier=tier, group=group))
            for category in sorted({r['root_cause_category'] for r in rows}):
                categories.append(summarize([r for r in selected if r['root_cause_category'] == category],
                                            tier=tier, group=group, root_cause_category=category))
    return {'reference_comparison.csv': rows, 'comparison_summary.csv': summaries,
            'root_cause_comparison.csv': categories}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results', type=Path, default=Path(__file__).resolve().parents[1] / 'data/results/native_skill_review')
    parser.add_argument('--output', type=Path, default=Path('outputs/native-skill-recovery'))
    args = parser.parse_args()
    outputs = tables(compare(args.results))
    args.output.mkdir(parents=True, exist_ok=True)
    for name, rows in outputs.items():
        with (args.output / name).open('w', encoding='utf-8', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
    print(json.dumps([r for r in outputs['comparison_summary.csv'] if r['group'] == 'all'], indent=2))


if __name__ == '__main__':
    main()
