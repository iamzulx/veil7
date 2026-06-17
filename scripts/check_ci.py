#!/usr/bin/env python3
"""Check CI status for veil7 GitHub Actions."""
import urllib.request, json, sys

token = open('/data/data/com.termux/files/home/.ghtoken').read().strip()

# Get jobs for the latest CI run
run_id = sys.argv[1] if len(sys.argv) > 1 else '27702172966'
url = f'https://api.github.com/repos/iamzulx/veil7/actions/runs/{run_id}/jobs'
req = urllib.request.Request(url, headers={
    'Authorization': f'Bearer {token}',
    'Accept': 'application/vnd.github+json'
})
resp = urllib.request.urlopen(req, timeout=15)
data = json.loads(resp.read())

for job in data.get('jobs', []):
    status = job['conclusion'] or job['status']
    print(f'\n=== {job["name"]} -> {status} ===')
    for step in job.get('steps', []):
        marker = '❌' if step['conclusion'] == 'failure' else '✅'
        print(f'  {marker} {step["name"]}: {step["conclusion"] or step["status"]}')
    
    # If job failed, get the log URL
    if job['conclusion'] == 'failure':
        log_url = job.get('html_url', '')
        print(f'  Log: {log_url}')
