from flask import Flask, request
import requests, json, os

app = Flask(__name__)
LOGSTASH_URL = os.getenv('LOGSTASH_URL', 'http://localhost:5044')

@app.route('/webhook', methods=['POST'])
def github_webhook():
    try:
        payload = request.json
        # Enrich payload with source and timestamp if missing
        payload['source'] = 'github'
        # Github events usually have 'created_at' or 'updated_at' inside nested objects depending on event type
        # We'll rely on Logstash date filter or let proper timestamp be extracted if possible.
        # But for simpler correlation, we can add a reception timestamp.
        
        print(f"Received webhook event: {request.headers.get('X-GitHub-Event')}")
        
        # Forward to Logstash
        requests.post(LOGSTASH_URL, json=payload)
        return 'OK', 200
    except Exception as e:
        print(f"Error forwarding webhook: {e}")
        return 'Error', 500

if __name__ == '__main__':
    print(f"Starting Webhook Forwarder, sending to {LOGSTASH_URL}...")
    app.run(port=8080, host='0.0.0.0')
