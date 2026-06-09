import requests, json, os

HARBOR_URL = os.getenv('HARBOR_URL', 'https://harbor.local')
HARBOR_USER = os.getenv('HARBOR_USER', 'admin')
HARBOR_PASS = os.getenv('HARBOR_PASS', 'Harbor12345')

def get_audit_logs(project='library', page=1, page_size=100):
    url = f'{HARBOR_URL}/api/v2.0/projects/{project}/logs'
    params = {'page': page, 'page_size': page_size}
    try:
        resp = requests.get(url, auth=(HARBOR_USER, HARBOR_PASS), params=params, verify=False) # verify=False for local self-signed certs
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"Error fetching Harbor logs: {e}")
        return []

if __name__ == "__main__":
    print(f"Fetching Harbor audit logs from {HARBOR_URL}...")
    logs = get_audit_logs()
    for log in logs:
        print(f"{log.get('op_time')} - {log.get('operation')} - {log.get('resource_type')} - {log.get('resource')}")
    
    filename = f'harbor_audit.json'
    with open(filename, 'w') as f:
        json.dump(logs, f, indent=2)
    print(f"Exported {len(logs)} logs to {filename}")
