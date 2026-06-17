#!/usr/bin/env python3
"""Fetch CI job logs for failed steps."""
import urllib.request, json, sys

token = open('/data/data/com.termux/files/home/.ghtoken').read().strip()

run_id = sys.argv[1] if len(sys.argv) > 1 else '27702172966'
job_id = sys.argv[2] if len(sys.argv) > 2 else None

# Get jobs
url = f'https://api.github.com/repos/iamzulx/veil7/actions/runs/{run_id}/jobs'
req = urllib.request.Request(url, headers={
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github+json'
})
resp = urllib.request.urlopen(req, timeout=15)
data = json.loads(resp.read())

for job in data.get('jobs', []):
    if job['conclusion'] != 'failure':
        continue
    if job_id and str(job['id']) != job_id:
        continue
    
    print(f'\n{"="*60}')
    print(f'JOB: {job["name"]} (id={job["id"]})')
    print(f'{"="*60}')
    
    # Get logs
    log_url = f'https://api.github.com/repos/iamzulx/veil7/actions/jobs/{job["id"]}/logs'
    req2 = urllib.request.Request(log_url, headers={
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json'
    })
    try:
        resp2 = urllib.request.urlopen(req2, timeout=30)
        logs = resp2.read().decode('utf-8', errors='replace')
        # Find the failed step and extract relevant error lines
        lines = logs.split('\n')
        in_failed_step = False
        error_lines = []
        for line in lines:
            # Detect step boundaries
            if '##[group]' in line or '##[error]' in line:
                in_failed_step = True
            if '##[error]' in line:
                error_lines.append(line)
            elif in_failed_step and ('error' in line.lower() or 'failed' in line.lower() or 'panic' in line.lower()):
                error_lines.append(line)
        
        # Also get last 50 lines which usually contain the error
        print('\n--- Last 30 lines of log ---')
        for line in lines[-30:]:
            if line.strip():
                print(line)
        
        if error_lines:
            print('\n--- Error lines ---')
            for el in error_lines[:20]:
                print(el)
    except Exception as e:
        print(f'  Could not fetch logs: {e}')
