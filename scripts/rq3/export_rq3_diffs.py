"""Export full base-to-head diffs from existing Git caches, without network access."""
import argparse
import csv
import json
import os
from pathlib import Path
import re
import subprocess


def read(path):
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cases', type=Path, required=True)
    p.add_argument('--ai-jobs', type=Path, required=True)
    p.add_argument('--human-jobs', type=Path, required=True)
    p.add_argument('--ai-cache-dir', type=Path, required=True)
    p.add_argument('--human-cache-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    jobs = {}
    for group in ['ai', 'human']:
        for row in read(getattr(args, group+'_jobs')):
            key = (group, row['repo_name'].lower(), row['pr_number'], row['revision'])
            if key in jobs:
                raise ValueError(f'Duplicate job: {key}')
            jobs[key] = row
    result, seen = [], set()
    env = dict(os.environ, GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    for row in read(args.cases):
        group, repo, pr = row['group'], row['repo_name'], row['pr_number']
        if (repo.lower(), pr) in seen:
            raise ValueError(f'Duplicate PR: {repo}#{pr}')
        seen.add((repo.lower(), pr))
        refs = []
        for revision, field in [('before', 'base_sha'), ('after', 'head_sha')]:
            job = jobs[(group, repo.lower(), pr, revision)]
            sha = job.get('checkout_ref') or job.get(field)
            if not sha or not re.fullmatch(r'[0-9a-fA-F]{40}', sha):
                raise ValueError(f'Missing recorded commit: {repo}#{pr} {revision}')
            refs.append(sha)
        cache = getattr(args, group+'_cache_dir')/(repo.replace('/', '_')+'.git')
        if not cache.is_dir():
            raise ValueError(f'Missing Git cache: {cache}; acquire the repository first')
        patch = subprocess.run(['git', '--git-dir', str(cache.resolve()), 'diff',
                                '--no-ext-diff', '--no-textconv', '--binary', '--full-index',
                                refs[0], refs[1], '--'], env=env, check=True,
                               capture_output=True).stdout.decode('utf-8', errors='strict')
        if 'diff --git ' not in patch:
            raise ValueError(f'Empty diff: {repo}#{pr}')
        result.append(dict(repo_name=repo, pr_number=pr, base_sha=refs[0], head_sha=refs[1], diff=patch))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x') as stream:
        for row in result:
            stream.write(json.dumps(row)+'\n')
    print(f'Exported {len(result)} complete diffs to {args.output}')


if __name__ == '__main__':
    main()
