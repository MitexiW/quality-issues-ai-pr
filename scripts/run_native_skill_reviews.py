"""Public rerun entry point for the native root-cause review Skill."""
import argparse
import csv
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def valid_result(path):
    try:
        execution=json.loads((path/'execution.json').read_text())
        audit=json.loads((path/'skill_loading_audit.json').read_text())
        response=json.loads((path/'review_response.json').read_text())
        return execution.get('status')=='completed' and audit.get('verified') is True and isinstance(response.get('findings'),list)
    except (OSError,ValueError):
        return False


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cases',type=Path,default=ROOT/'data/results/rq3_formal_plan_20260727_v1/formal_cases.csv')
    p.add_argument('--worktree-root',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--workers',type=int,choices=range(1,9),default=4)
    p.add_argument('--limit',type=int)
    p.add_argument('--model',default='deepseek-v4-pro[1m]')
    p.add_argument('--api-key-env',default='RQ3_API_KEY')
    p.add_argument('--base-url',default='https://api.deepseek.com/anthropic')
    p.add_argument('--execute',action='store_true')
    p.add_argument('--accept-api-charges',action='store_true')
    p.add_argument('--retry-failed',action='store_true')
    a=p.parse_args()
    if a.execute and not a.accept_api_charges:p.error('--execute requires --accept-api-charges')
    if a.limit is not None and a.limit<1:p.error('--limit must be positive')
    with a.cases.open() as stream:
        cases=list(csv.DictReader(stream))
    ids=[r['case_id'] for r in cases]
    if len(set(ids))!=len(ids) or any(Path(c).name!=c or c in ('.','..') for c in ids):p.error('Invalid or duplicate case IDs')
    if a.limit:cases=cases[:a.limit]
    def run(row):
        case=row['case_id'];directory=a.output/case
        attempts=sorted(directory.glob('attempt-*'))
        if any(valid_result(d) for d in attempts):return case,'skipped_valid'
        if any(not (d/'launcher_status.json').exists() for d in attempts):return case,'unfinished_inspect_before_retry'
        if a.execute and attempts and not a.retry_failed:return case,'failed_use_retry_failed'
        preflights=list(directory.glob('preflight-*'))
        dest=directory/(f'attempt-{len(attempts)+1:03d}' if a.execute else f'preflight-{len(preflights)+1:03d}')
        directory.mkdir(parents=True,exist_ok=True)
        command=[sys.executable,str(ROOT/'scripts/run_native_skill_case.py'),
            '--worktree-root',str(a.worktree_root.resolve()),'--case-id',case,
            '--provider','deepseek','--base-url',a.base_url,'--api-key-env',a.api_key_env,
            '--model',a.model,'--effort','max','--max-turns','100','--no-sdk-budget',
            '--prompt',str(ROOT/'config/native_review/launch_prompt.txt'),
            '--output-schema',str(ROOT/'config/study/llm_review_output_schema.json'),
            '--output-dir',str(dest.resolve())]
        if a.execute:command+=['--execute']
        print(f'{case}: starting {"paid review" if a.execute else "offline preflight"}',flush=True)
        with (directory/(dest.name+'.log')).open('w') as log:
            code=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,cwd=ROOT).returncode
        status='completed' if code==0 and (not a.execute or valid_result(dest)) else 'failed'
        dest.mkdir(parents=True,exist_ok=True)
        (dest/'launcher_status.json').write_text(json.dumps({'status':status,'returncode':code,'requested_model':a.model})+'\n')
        print(f'{case}: {status}',flush=True)
        return case,status
    # One launch per output directory; no concurrent retry launchers.
    import fcntl
    a.output.mkdir(parents=True,exist_ok=True)
    with (a.output/'.launcher.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:p.error('Another launcher is using this output directory')
        with ThreadPoolExecutor(max_workers=a.workers) as pool:results=list(pool.map(run,cases))
    print(json.dumps(dict(results),indent=2))
    if any(status not in ('completed','skipped_valid') for _,status in results):sys.exit(1)


if __name__=='__main__':main()
