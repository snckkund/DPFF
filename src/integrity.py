"""
DPFF Evidence Integrity Module
SHA-256 hashing and chain-of-custody for forensic evidence.
"""

import hashlib
import json
from datetime import datetime
from typing import List
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger

logger = get_logger('integrity')


def compute_hash(event: PipelineEvent) -> str:
    """
    Compute a SHA-256 hash of a PipelineEvent's core fields.
    This creates a tamper-evident fingerprint for each piece of evidence.
    """
    # Canonical string: deterministic representation of the event
    canonical = json.dumps({
        'timestamp': event.timestamp.isoformat(),
        'source': event.source,
        'event_type': event.event_type,
        'details': event.details
    }, sort_keys=True)
    
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def hash_event(event: PipelineEvent) -> PipelineEvent:
    """
    Compute and attach a SHA-256 hash to a PipelineEvent.
    Also sets collected_at timestamp if not already set.
    Returns the same event (mutated in place).
    """
    event.evidence_hash = compute_hash(event)
    if not event.collected_at:
        event.collected_at = datetime.now()
    return event


def hash_events(events: List[PipelineEvent]) -> List[PipelineEvent]:
    """Hash all events in a list. Returns the same list."""
    for event in events:
        hash_event(event)
    logger.info(f"Hashed {len(events)} evidence items")
    return events


def verify_event(event: PipelineEvent) -> bool:
    """
    Verify the integrity of a PipelineEvent by recomputing its hash.
    Returns True if the hash matches, False if evidence has been tampered with.
    """
    if not event.evidence_hash:
        logger.warning(f"Event has no hash — cannot verify integrity: {event.source}/{event.event_type}")
        return False
    
    expected = compute_hash(event)
    is_valid = event.evidence_hash == expected
    
    if not is_valid:
        logger.error(
            f"INTEGRITY VIOLATION: Event hash mismatch! "
            f"source={event.source}, type={event.event_type}, "
            f"stored={event.evidence_hash[:16]}..., computed={expected[:16]}..."
        )
    
    return is_valid


def verify_all(events: List[PipelineEvent]) -> dict:
    """
    Verify integrity of all events. Returns a summary dict.
    """
    total = len(events)
    valid = sum(1 for e in events if verify_event(e))
    invalid = total - valid
    
    summary = {
        'total_events': total,
        'valid': valid,
        'invalid': invalid,
        'integrity_intact': invalid == 0,
        'verified_at': datetime.now().isoformat()
    }
    
    if invalid > 0:
        logger.error(f"INTEGRITY CHECK FAILED: {invalid}/{total} events have mismatched hashes!")
    else:
        logger.info(f"Integrity check passed: all {total} events verified")
    
    return summary


def generate_chain_of_custody(events: List[PipelineEvent]) -> dict:
    """
    Generate a chain-of-custody manifest for a set of evidence.
    This provides an auditable record of all collected evidence.
    """
    manifest = {
        'generated_at': datetime.now().isoformat(),
        'total_evidence_items': len(events),
        'sources': list(set(e.source for e in events)),
        'time_range': {
            'earliest': min(e.timestamp for e in events).isoformat() if events else None,
            'latest': max(e.timestamp for e in events).isoformat() if events else None,
        },
        'evidence_hashes': [
            {
                'hash': e.evidence_hash,
                'source': e.source,
                'type': e.event_type,
                'timestamp': e.timestamp.isoformat(),
                'collected_at': e.collected_at.isoformat() if e.collected_at else None
            }
            for e in events
        ]
    }
    
    # Compute a master hash of all evidence hashes (the "root hash")
    all_hashes = ''.join(e.evidence_hash for e in events if e.evidence_hash)
    manifest['root_hash'] = hashlib.sha256(all_hashes.encode('utf-8')).hexdigest()
    
    logger.info(f"Chain of custody generated: {len(events)} items, root_hash={manifest['root_hash'][:16]}...")
    
    return manifest
