"""
Tests for the DPFF Evidence Integrity Module.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from datetime import datetime, timezone
from src.correlation_engine.models import PipelineEvent
from src.integrity import compute_hash, hash_event, hash_events, verify_event, verify_all, generate_chain_of_custody


def make_event(source="CI Runner", event_type="Step Execution", details="npm test"):
    return PipelineEvent(
        timestamp=datetime(2026, 2, 5, 14, 30, 0, tzinfo=timezone.utc),
        source=source,
        event_type=event_type,
        details=details,
    )


class TestComputeHash:
    def test_deterministic(self):
        """Same event should always produce the same hash."""
        e1 = make_event()
        e2 = make_event()
        assert compute_hash(e1) == compute_hash(e2)

    def test_different_details(self):
        """Changing details should change the hash."""
        e1 = make_event(details="npm test")
        e2 = make_event(details="npm install malware")
        assert compute_hash(e1) != compute_hash(e2)

    def test_different_source(self):
        """Changing source should change the hash."""
        e1 = make_event(source="CI Runner")
        e2 = make_event(source="Attacker")
        assert compute_hash(e1) != compute_hash(e2)

    def test_hash_length(self):
        """SHA-256 should produce a 64-char hex string."""
        h = compute_hash(make_event())
        assert len(h) == 64
        assert all(c in '0123456789abcdef' for c in h)


class TestHashEvent:
    def test_attaches_hash(self):
        e = make_event()
        assert e.evidence_hash == ""
        hash_event(e)
        assert e.evidence_hash != ""
        assert len(e.evidence_hash) == 64

    def test_sets_collected_at(self):
        e = make_event()
        assert e.collected_at is None
        hash_event(e)
        assert e.collected_at is not None


class TestVerifyEvent:
    def test_valid_event(self):
        e = make_event()
        hash_event(e)
        assert verify_event(e) is True

    def test_tampered_event(self):
        e = make_event()
        hash_event(e)
        e.details = "TAMPERED DATA"
        assert verify_event(e) is False

    def test_no_hash(self):
        e = make_event()
        assert verify_event(e) is False


class TestVerifyAll:
    def test_all_valid(self):
        events = [make_event(details=f"event-{i}") for i in range(5)]
        hash_events(events)
        result = verify_all(events)
        assert result['integrity_intact'] is True
        assert result['valid'] == 5
        assert result['invalid'] == 0

    def test_one_tampered(self):
        events = [make_event(details=f"event-{i}") for i in range(5)]
        hash_events(events)
        events[2].details = "TAMPERED"
        result = verify_all(events)
        assert result['integrity_intact'] is False
        assert result['invalid'] == 1


class TestChainOfCustody:
    def test_manifest_structure(self):
        events = [make_event(details=f"event-{i}") for i in range(3)]
        hash_events(events)
        manifest = generate_chain_of_custody(events)
        
        assert 'root_hash' in manifest
        assert manifest['total_evidence_items'] == 3
        assert len(manifest['evidence_hashes']) == 3
        assert 'CI Runner' in manifest['sources']
        assert manifest['time_range']['earliest'] is not None

    def test_root_hash_deterministic(self):
        events = [make_event(details=f"event-{i}") for i in range(3)]
        hash_events(events)
        m1 = generate_chain_of_custody(events)
        m2 = generate_chain_of_custody(events)
        assert m1['root_hash'] == m2['root_hash']
