"""Prepare human matching materials from new native-Skill review attempts."""
import argparse
import csv
import html
import json
import shutil
from pathlib import Path


def rows(path):
    csv.field_size_limit(16 * 1024 * 1024)
    with path.open(encoding='utf-8', newline='') as stream:
        return list(csv.DictReader(stream))


def truth(value):
    return str(value).lower() in ('true', '1', 'yes')


def write_csv(path, records, fields):
    with path.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)


def select_attempt(directory):
    attempts = sorted(directory.glob('attempt-*'))
    for attempt in attempts:
        if not (attempt/'launcher_status.json').exists():
            raise ValueError(f'Unfinished attempt: {attempt}; inspect before preparing assessment')
    for attempt in attempts:
        try:
            status = json.loads((attempt/'execution.json').read_text())
            audit = json.loads((attempt/'skill_loading_audit.json').read_text())
            response = json.loads((attempt/'review_response.json').read_text())
            if status.get('status') == 'completed' and audit.get('verified') is True and isinstance(response.get('findings'), list):
                return attempt, response
        except (OSError, ValueError):
            continue
    raise ValueError(f'No valid completed review: {directory}')


def prepare(args):
    if args.output.exists():
        raise ValueError('Use a new output directory; existing human decisions are never overwritten')
    cases = rows(args.cases)
    case_ids = [r['case_id'] for r in cases]
    if len(set(case_ids)) != len(case_ids) or not case_ids or any(Path(c).name != c or c in ('.', '..') for c in case_ids):
        raise ValueError('Invalid or duplicate case IDs')
    selected = {c: select_attempt(args.run_dir/c) for c in case_ids}
    raw_refs = rows(args.references)
    refs = [r for r in raw_refs if r['case_id'] in selected
            and truth(r['validated_issue_reference']) and truth(r['quality_broad_reference'])]
    keys = {(r['case_id'], r['reference_id']) for r in refs}
    if len(keys) != len(refs):
        raise ValueError('Duplicate references')
    reference_fields = ['case_id', 'reference_id', 'group', 'validated_issue_reference',
                        'quality_broad_reference', 'quality_primary_reference', 'semantic_recovered']
    for ref in refs:
        if any(k not in ref for k in reference_fields) or ref['semantic_recovered'].lower() not in ('0', '1', 'true', 'false'):
            raise ValueError('References require tier flags and explicit baseline recovery for the comparison')
    mapping = {}
    for row in rows(args.root_cause_mapping):
        key = row['case_id'], row['reference_id']
        if key not in keys:
            continue
        category = row.get('root_cause_category') or row.get('rq1_mechanism_category')
        if key in mapping or not category:
            raise ValueError('Missing or duplicate root-cause category')
        mapping[key] = dict(case_id=key[0], reference_id=key[1], root_cause_category=category)
    if set(mapping) != keys:
        raise ValueError('Root-cause mapping must cover the confirmed references')
    inputs = args.output/'human_assessment'
    inputs.mkdir(parents=True)
    index, decisions, packets = [], [], []
    for case in cases:
        cid = case['case_id']
        attempt, response = selected[cid]
        destination = args.output/'reviews'/cid
        destination.mkdir(parents=True)
        for name in ('review_response.json', 'skill_loading_audit.json'):
            shutil.copyfile(attempt/name, destination/name)
        index.append(dict(case_id=cid, review_path=f'reviews/{cid}/review_response.json',
                          finding_count=len(response['findings']), selected_attempt=attempt.name))
        findings = []
        for number, finding in enumerate(response['findings'], 1):
            fid = f'{cid}-f{number:04d}'
            decisions.append(dict(case_id=cid, finding_id=fid, relation='', matched_reference_ids=[]))
            findings.append(dict(finding_id=fid, finding=finding))
        # Exclude baseline recovery and authorship from reviewer-facing packets.
        visible = ('reference_id', 'rule_id', 'rule_name', 'message', 'path', 'file', 'file_path', 'start_line',
                   'end_line', 'description', 'code_snippet', 'reference_message', 'reference_path')
        packets.append(dict(case_id=cid, findings=findings,
                            references=[{k:r[k] for k in visible if k in r}
                                        for r in refs if r['case_id'] == cid]))
    write_csv(args.output/'review_index.csv', index, list(index[0]))
    write_csv(inputs/'reference_inputs.csv', [{k:r[k] for k in reference_fields} for r in refs], reference_fields)
    write_csv(inputs/'root_cause_mapping.csv', list(mapping.values()), ['case_id', 'reference_id', 'root_cause_category'])
    (inputs/'human_decisions.json').write_text(json.dumps(decisions, indent=2)+'\n')
    (args.output/'assessment_packets.json').write_text(json.dumps(packets, indent=2, ensure_ascii=False)+'\n')
    sections = []
    for packet in packets:
        sections.append('<h2>'+html.escape(packet['case_id'])+'</h2><pre>'+html.escape(json.dumps(packet,indent=2,ensure_ascii=False))+'</pre>')
    (args.output/'assessment.html').write_text('<meta charset="utf-8"><title>Human semantic matching</title>'
        '<h1>Human semantic matching</h1><p>Inspect the PR diff and repository context. '
        'Record decisions in human_assessment/human_decisions.json. This page is read-only.</p>'
        + ''.join(sections), encoding='utf-8')
    print(f'Prepared {len(cases)} reviews, {len(decisions)} decisions and {len(refs)} references at {args.output}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-dir', type=Path, required=True)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--root-cause-mapping', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    prepare(parser.parse_args())


if __name__ == '__main__':
    main()
