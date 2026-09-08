"""Split complete model assessments into two full human-review queues."""
import argparse
import csv
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    with args.input.open(newline='') as stream:
        reader = csv.DictReader(stream)
        fields, rows = list(reader.fieldnames or []), list(reader)
    required = {'alert_id', 'condition_present', 'introduced_by_pr', 'valid_issue'}
    if not required.issubset(fields):
        raise ValueError(f'Missing columns: {sorted(required-set(fields))}')
    ids = [r['alert_id'] for r in rows]
    if not rows or not all(ids) or len(ids) != len(set(ids)):
        raise ValueError('Expected nonempty assessments with unique alert IDs')
    groups = {'retained': [], 'excluded': []}
    for row in rows:
        judgments = []
        for field in required-{'alert_id'}:
            value = row[field].strip().lower()
            allowed = {'yes', 'no', 'uncertain'}
            if field == 'valid_issue':
                allowed.add('contextual_exception')
            if value not in allowed:
                raise ValueError(f'Missing/invalid model judgment: {row["alert_id"]}')
            judgments.append(value)
        name = 'retained' if all(v == 'yes' for v in judgments) else 'excluded'
        row['verification_audit_scope'] = ('complete_model_retained_census' if name == 'retained'
                                           else 'model_excluded_full_census')
        groups[name].append(row)
    if 'verification_audit_scope' not in fields:
        fields.append('verification_audit_scope')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    paths = {name: args.output_dir/f'{name}.csv' for name in groups}
    if any(p.exists() for p in paths.values()):
        raise ValueError('Use a new output directory; review queues must not be overwritten')
    for name, members in groups.items():
        with paths[name].open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fields)
            writer.writeheader()
            writer.writerows(members)
        print(f'{name}: {len(members)} -> {paths[name]}')


if __name__ == '__main__':
    main()
