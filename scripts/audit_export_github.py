import requests, json, os
from datetime import datetime, timedelta

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
ORG = os.getenv('GITHUB_ORG', 'your-org')

if not GITHUB_TOKEN:
    print("Error: GITHUB_TOKEN environment variable not set.")
    exit(1)

headers = {
    'Authorization': f'token {GITHUB_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

def get_audit_log(since=None):
    if not since:
        since = (datetime.now() - timedelta(days=30)).isoformat()
    
    url = f'https://api.github.com/orgs/{ORG}/audit-log'
    params = {'phrase': f'created:>={since}', 'per_page': 100}
    
    events = []
    while url:
        try:
            resp = requests.get(url, headers=headers, params=params)
            resp.raise_for_status()
            events.extend(resp.json())
            url = resp.links.get('next', {}).get('url')
        except Exception as e:
            print(f"Error fetching logs: {e}")
            break
    
    return events

if __name__ == "__main__":
    print(f"Fetching GitHub audit logs for org: {ORG}...")
    events = get_audit_log()
    filename = f'github_audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(filename, 'w') as f:
        json.dump(events, f, indent=2)
    print(f"Exported {len(events)} events to {filename}")
