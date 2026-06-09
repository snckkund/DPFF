"""
Tests for the DPFF Database Module.
"""
import sys
import os
import tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from datetime import datetime, timezone
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.integrity import hash_events
from src.database import ForensicDatabase


@pytest.fixture
def db():
    """Create a temporary database for each test."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, 'test.db')
        yield ForensicDatabase(db_path)


def make_events(n=5):
    events = []
    for i in range(n):
        events.append(PipelineEvent(
            timestamp=datetime(2026, 2, 5, 14, 30+i, 0, tzinfo=timezone.utc),
            source=f"Source-{i}",
            event_type="Test Event",
            details=f"Test details {i}",
        ))
    hash_events(events)
    return events


def make_findings(events):
    return [
        CorrelationResult(
            is_compromised=True,
            root_cause="Test Incident: Suspicious activity detected",
            timeline=[events[0], events[1]],
            severity="CRITICAL"
        ),
        CorrelationResult(
            is_compromised=True,
            root_cause="Test Incident: Unauthorized access",
            timeline=[events[2]],
            severity="HIGH"
        )
    ]


class TestSaveAndLoad:
    def test_save_returns_id(self, db):
        events = make_events(3)
        findings = make_findings(events)
        inv_id = db.save_investigation("simulate", events, findings)
        assert inv_id is not None
        assert len(inv_id) == 8

    def test_round_trip(self, db):
        events = make_events(5)
        findings = make_findings(events)
        inv_id = db.save_investigation("simulate", events, findings, root_hash="abc123")
        
        loaded = db.load_investigation(inv_id)
        assert loaded is not None
        assert loaded['mode'] == 'simulate'
        assert loaded['event_count'] == 5
        assert loaded['finding_count'] == 2
        assert len(loaded['events']) == 5
        assert len(loaded['findings']) == 2

    def test_event_data_preserved(self, db):
        events = make_events(1)
        inv_id = db.save_investigation("test", events, [])
        
        loaded = db.load_investigation(inv_id)
        loaded_event = loaded['events'][0]
        original_event = events[0]
        
        assert loaded_event.source == original_event.source
        assert loaded_event.event_type == original_event.event_type
        assert loaded_event.details == original_event.details
        assert loaded_event.evidence_hash == original_event.evidence_hash

    def test_finding_severity_preserved(self, db):
        events = make_events(3)
        findings = make_findings(events)
        inv_id = db.save_investigation("test", events, findings)
        
        loaded = db.load_investigation(inv_id)
        assert loaded['findings'][0].severity == "CRITICAL"
        assert loaded['findings'][1].severity == "HIGH"


class TestListInvestigations:
    def test_empty_list(self, db):
        result = db.list_investigations()
        assert result == []

    def test_list_multiple(self, db):
        events = make_events(2)
        db.save_investigation("simulate", events, [])
        db.save_investigation("analyze", events, [])
        
        result = db.list_investigations()
        assert len(result) == 2

    def test_list_contains_metadata(self, db):
        events = make_events(3)
        findings = make_findings(events)
        db.save_investigation("simulate", events, findings, root_hash="test_hash")
        
        result = db.list_investigations()
        assert result[0]['mode'] == 'simulate'
        assert result[0]['event_count'] == 3
        assert result[0]['finding_count'] == 2


class TestDeleteInvestigation:
    def test_delete_existing(self, db):
        events = make_events(2)
        inv_id = db.save_investigation("test", events, [])
        
        assert db.delete_investigation(inv_id) is True
        assert db.load_investigation(inv_id) is None

    def test_delete_nonexistent(self, db):
        assert db.delete_investigation("nonexistent") is False


class TestLoadNonexistent:
    def test_returns_none(self, db):
        assert db.load_investigation("fake_id") is None
