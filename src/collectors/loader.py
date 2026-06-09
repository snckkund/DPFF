import os
import json
import yaml
from datetime import datetime
from src.correlation_engine.models import PipelineEvent, GitCommit, BuildInfo, RegistryImage, Deployment

class SimulationLoader:
    def __init__(self, simulation_dir):
        self.simulation_dir = simulation_dir
        self.events = []

    def load_all(self):
        self._load_attack1()
        self._load_attack2()
        self._load_attack3()
        self._load_attack4()
        self._load_mixed_scenarios()
        return self.events

    def _load_mixed_scenarios(self):
        # Mixed Scenarios (Benign & Malicious)
        base_path = os.path.join(self.simulation_dir, 'mix')
        if not os.path.exists(base_path): return
        
        from datetime import timezone

        scenarios = ['benign', 'malicious']
        for scenario in scenarios:
            log_path = os.path.join(base_path, scenario, 'logs.txt')
            if os.path.exists(log_path):
                with open(log_path, 'r') as f:
                    for line in f:
                        if 'Executing:' in line:
                            # [2026-02-05T16:00:20Z] Executing: npm test
                            parts = line.split(']')
                            ts_str = parts[0].strip('[')
                            ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                            cmd = parts[1].split('Executing:')[1].strip()
                            
                            self.events.append(PipelineEvent(
                                timestamp=ts,
                                source=f'CI Runner ({scenario})',
                                event_type='Step Execution',
                                details=f'Command: {cmd}'
                            ))
            
            # Load K8s Events if present
            k8s_path = os.path.join(base_path, scenario, 'k8s_events.json')
            if os.path.exists(k8s_path):
                import json
                with open(k8s_path, 'r') as f:
                    k_events = json.load(f)
                    for k in k_events:
                        ts = datetime.fromisoformat(k['timestamp'].replace('Z', '+00:00'))
                        is_priv = k.get('object', {}).get('spec', {}).get('containers', [{}])[0].get('securityContext', {}).get('privileged', False)
                        msg = k['message']
                        if is_priv:
                            msg += " [PRIVILEGED]"
                        
                        self.events.append(PipelineEvent(
                            timestamp=ts,
                            source=f'Kubernetes ({scenario})',
                            event_type=k['reason'],
                            details=msg
                        ))

    def _load_attack1(self):
        # Pipeline Injection
        path = os.path.join(self.simulation_dir, 'attack1')
        if not os.path.exists(path): return

        # Load logs
        log_path = os.path.join(path, 'runner_logs.txt')
        if os.path.exists(log_path):
            with open(log_path, 'r') as f:
                for line in f:
                    if 'Executing:' in line and 'curl' in line:
                         # [2026-02-05T14:30:17Z] Executing: curl ...
                         parts = line.split(']')
                         ts_str = parts[0].strip('[')
                         ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                         self.events.append(PipelineEvent(
                             timestamp=ts,
                             source='CI Runner',
                             event_type='Step Execution',
                             details=f'Suspicious Curl Command: {line.split("Executing:")[1].strip()}'
                         ))

    def _load_attack2(self):
        # Credential Theft (Git Log)
        path = os.path.join(self.simulation_dir, 'attack2', 'git_log.txt')
        if os.path.exists(path):
            with open(path, 'r') as f:
                content = f.read()
                # Simple parse of "commit ... Date: ... timestamp"
                # For simulation, we'll hardcode the known malicious commit date for simplicity
                # Real implementation would use GitPython
                from datetime import timezone
                self.events.append(PipelineEvent(
                    timestamp=datetime(2026, 2, 5, 15, 0, 0, tzinfo=timezone.utc),
                    source='Git',
                    event_type='Commit',
                    details='Author: mallory, Message: fix: update health check logging'
                ))

    def _load_attack3(self):
        # Dependency Confusion
        path = os.path.join(self.simulation_dir, 'attack3', 'npm_install_log.txt')
        if os.path.exists(path):
             from datetime import timezone
             self.events.append(PipelineEvent(
                timestamp=datetime(2026, 2, 5, 15, 5, 0, tzinfo=timezone.utc), # Estimated from log context
                source='CI Build',
                event_type='NPM Install',
                details='Installed internal-utils@99.9.9 from public registry'
            ))

    def _load_attack4(self):
        # Artifact Tampering
        path = os.path.join(self.simulation_dir, 'attack4', 'registry_audit.json')
        if os.path.exists(path):
            with open(path, 'r') as f:
                data = json.load(f)
                from datetime import timezone
                for entry in data:
                    ts = datetime.fromtimestamp(int(entry['op_time']), tz=timezone.utc)
                    self.events.append(PipelineEvent(
                        timestamp=ts,
                        source='Harbor',
                        event_type=f"Image {entry['operation'].capitalize()}",
                        details=f"User: {entry['username']}, Digest: {entry['digest']}"
                    ))
