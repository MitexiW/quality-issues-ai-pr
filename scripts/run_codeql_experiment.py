#!/usr/bin/env python3
"""Rebuild candidates and prepare or run a fresh paired-CodeQL experiment.

Default is offline setup only. --execute explicitly enables GitHub/CodeQL.
Fresh results are not assumed to equal historical successful-scan counts.
"""
import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def key(row):
    return row['repo_name'].lower(), str(row['pr_number'])


def read(path):
    with path.open(newline='') as stream:
        reader = csv.DictReader(stream)
        return reader.fieldnames, list(reader)


def write(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT/'outputs/codeql_experiment')
    parser.add_argument('--metadata-dir', type=Path, default=ROOT/'data/inputs/aidev_selection')
    parser.add_argument('--group', choices=['ai', 'human', 'both'], default='both')
    parser.add_argument('--limit-per-group', type=int, default=0,
                        help='0 selects all eligible non-overlapping PRs; use 1 for a small test')
    parser.add_argument('--execute', action='store_true', help='Download repositories and run CodeQL')
    parser.add_argument('--selection-only', action='store_true', help='Only rebuild candidate lists; no CodeQL installation needed')
    parser.add_argument('--codeql', default='codeql')
    parser.add_argument('--workers', type=int, default=1)
    args = parser.parse_args()
    if args.selection_only and args.execute:
        parser.error('--selection-only and --execute cannot be combined')
    if args.limit_per_group < 0 or args.workers < 1:
        parser.error('limit must be nonnegative and workers must be positive')
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    config = {'metadata_dir': str(args.metadata_dir.resolve()), 'limit_per_group': args.limit_per_group,
              'query_suite': 'security-and-quality', 'selection': 'stars>500; eight languages; merged; feat/fix/refactor; exclude cross-group overlap'}
    settings = out/'settings.json'
    if settings.exists() and json.loads(settings.read_text()) != config:
        raise ValueError('Use a new output directory when changing selection settings')
    selected = {}
    for group in ['ai', 'human']:
        candidate = out/f'{group}_candidate_prs.csv'
        subprocess.run([sys.executable, str(ROOT/'scripts/codeql/filter_study_candidates.py'),
                        '--source', group, '--cache-dir', str(args.metadata_dir.resolve()),
                        '--output', str(candidate)], check=True, cwd=ROOT)
        selected[group] = read(candidate)
    overlap = {key(r) for r in selected['ai'][1]} & {key(r) for r in selected['human'][1]}
    write(out/'cross_group_overlap.csv', ['repo_name', 'pr_number'],
          [dict(zip(['repo_name', 'pr_number'], k)) for k in sorted(overlap)])
    settings.write_text(json.dumps(config, indent=2)+'\n')
    counts = {}
    for group in ['ai', 'human']:
        fields, rows = selected[group]
        eligible = [r for r in rows if key(r) not in overlap]
        chosen = eligible[:args.limit_per_group] if args.limit_per_group else eligible
        counts[group] = {'initial_candidates': len(rows), 'after_overlap_exclusion': len(eligible),
                         'selected_for_this_run': len(chosen)}
        if args.group not in [group, 'both']:
            continue
        candidates = out/f'{group}_scan_candidates.csv'
        write(candidates, fields, chosen)
        if args.selection_only or not chosen:
            continue
        command = [sys.executable, str(ROOT/'scripts/codeql/run_scale_codeql_experiment.py'),
                   '--candidate-prs', str(candidates), '--target-prs', str(len(chosen)),
                   '--output-root', str(out/group), '--no-dedupe-analyzed',
                   '--query-suite', 'security-and-quality', '--codeql', args.codeql,
                   '--workers', str(args.workers), '--keep-all-databases', '--cleanup-every', '0']
        if not args.execute:
            command.append('--setup-only')
        else:
            command.append('--require-token')
        subprocess.run(command, check=True, cwd=ROOT)
    (out/'selection_counts.json').write_text(json.dumps(counts, indent=2)+'\n')
    print('Selection/setup complete. Execution requested:', args.execute, 'Outputs:', out)


if __name__ == '__main__':
    main()
