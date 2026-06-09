import requests, json, os

ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')

policy = {
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "50GB",
            "max_age": "7d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "readonly": {},
          "forcemerge": { "max_num_segments": 1 }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "freeze": {}
        }
      }
    }
  }
}

def setup_ilm():
    url = f"{ELASTICSEARCH_URL}/_ilm/policy/forensic_logs"
    headers = {'Content-Type': 'application/json'}
    try:
        resp = requests.put(url, headers=headers, json=policy)
        print(f"Status: {resp.status_code}")
        print(f"Response: {resp.text}")
    except Exception as e:
        print(f"Error setting up ILM: {e}")

if __name__ == "__main__":
    print(f"Setting up Immutable ILM policy at {ELASTICSEARCH_URL}...")
    setup_ilm()
