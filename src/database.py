"""
DPFF Database Module
SQLite persistence layer for investigations, events, and findings.
"""

import sqlite3
import os
import sys
import uuid
import json
from datetime import datetime
from typing import List, Optional, Tuple
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.forensic_logger import get_logger

logger = get_logger('database')


def _get_output_dir():
    """Return the directory for writable outputs."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Default DB path
DATA_DIR = os.path.join(_get_output_dir(), 'data')
DB_PATH = os.path.join(DATA_DIR, 'dpff.db')


class ForensicDatabase:
    """SQLite storage for DPFF investigations."""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()
    
    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    
    def _init_db(self):
        """Create tables if they don't exist."""
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    event_count INTEGER DEFAULT 0,
                    finding_count INTEGER DEFAULT 0,
                    root_hash TEXT,
                    duration_seconds REAL
                );
                
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    evidence_hash TEXT,
                    collected_at TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                );
                
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    is_compromised BOOLEAN NOT NULL,
                    root_cause TEXT NOT NULL,
                    severity TEXT DEFAULT 'HIGH',
                    evidence_event_hashes TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_events_investigation 
                    ON events(investigation_id);
                CREATE INDEX IF NOT EXISTS idx_findings_investigation 
                    ON findings(investigation_id);
            """)
            conn.commit()
            logger.debug(f"Database initialized at {self.db_path}")
        finally:
            conn.close()
    
    def save_investigation(
        self,
        mode: str,
        events: List[PipelineEvent],
        findings: List[CorrelationResult],
        root_hash: str = "",
        duration_seconds: float = 0.0
    ) -> str:
        """
        Save a complete investigation (events + findings) to the database.
        Returns the investigation ID.
        """
        investigation_id = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()
        
        conn = self._get_conn()
        try:
            # Save investigation metadata
            conn.execute(
                """INSERT INTO investigations 
                   (id, timestamp, mode, event_count, finding_count, root_hash, duration_seconds) 
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (investigation_id, now, mode, len(events), len(findings), root_hash, duration_seconds)
            )
            
            # Save events
            for event in events:
                conn.execute(
                    """INSERT INTO events 
                       (investigation_id, timestamp, source, event_type, details, evidence_hash, collected_at) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        investigation_id,
                        event.timestamp.isoformat(),
                        event.source,
                        event.event_type,
                        event.details,
                        event.evidence_hash,
                        event.collected_at.isoformat() if event.collected_at else None
                    )
                )
            
            # Save findings
            for finding in findings:
                # Store the hashes of evidence events as JSON array
                evidence_hashes = json.dumps([
                    e.evidence_hash for e in finding.timeline if e.evidence_hash
                ])
                conn.execute(
                    """INSERT INTO findings 
                       (investigation_id, is_compromised, root_cause, severity, evidence_event_hashes) 
                       VALUES (?, ?, ?, ?, ?)""",
                    (
                        investigation_id,
                        finding.is_compromised,
                        finding.root_cause,
                        finding.severity,
                        evidence_hashes
                    )
                )
            
            conn.commit()
            logger.info(f"Investigation {investigation_id} saved: {len(events)} events, {len(findings)} findings")
            return investigation_id
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to save investigation: {e}")
            raise
        finally:
            conn.close()
    
    def load_investigation(self, investigation_id: str) -> Optional[dict]:
        """Load a complete investigation by ID."""
        conn = self._get_conn()
        try:
            # Load metadata
            row = conn.execute(
                "SELECT * FROM investigations WHERE id = ?", 
                (investigation_id,)
            ).fetchone()
            
            if not row:
                logger.warning(f"Investigation {investigation_id} not found")
                return None
            
            # Load events
            event_rows = conn.execute(
                "SELECT * FROM events WHERE investigation_id = ? ORDER BY timestamp",
                (investigation_id,)
            ).fetchall()
            
            events = []
            for er in event_rows:
                events.append(PipelineEvent(
                    timestamp=datetime.fromisoformat(er['timestamp']),
                    source=er['source'],
                    event_type=er['event_type'],
                    details=er['details'],
                    evidence_hash=er['evidence_hash'] or "",
                    collected_at=datetime.fromisoformat(er['collected_at']) if er['collected_at'] else None
                ))
            
            # Load findings
            finding_rows = conn.execute(
                "SELECT * FROM findings WHERE investigation_id = ?",
                (investigation_id,)
            ).fetchall()
            
            findings = []
            for fr in finding_rows:
                # Reconstruct timeline from evidence hashes
                evidence_hashes = json.loads(fr['evidence_event_hashes']) if fr['evidence_event_hashes'] else []
                timeline = [e for e in events if e.evidence_hash in evidence_hashes]
                
                findings.append(CorrelationResult(
                    is_compromised=bool(fr['is_compromised']),
                    root_cause=fr['root_cause'],
                    timeline=timeline,
                    severity=fr['severity'] or 'HIGH'
                ))
            
            result = {
                'id': row['id'],
                'timestamp': row['timestamp'],
                'mode': row['mode'],
                'event_count': row['event_count'],
                'finding_count': row['finding_count'],
                'root_hash': row['root_hash'],
                'duration_seconds': row['duration_seconds'],
                'events': events,
                'findings': findings
            }
            
            logger.info(f"Loaded investigation {investigation_id}: {len(events)} events, {len(findings)} findings")
            return result
            
        finally:
            conn.close()
    
    def list_investigations(self) -> List[dict]:
        """List all past investigations (metadata only)."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM investigations ORDER BY timestamp DESC"
            ).fetchall()
            
            results = []
            for row in rows:
                results.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'mode': row['mode'],
                    'event_count': row['event_count'],
                    'finding_count': row['finding_count'],
                    'root_hash': row['root_hash']
                })
            
            return results
            
        finally:
            conn.close()
    
    def delete_investigation(self, investigation_id: str) -> bool:
        """Delete an investigation and all its events/findings."""
        conn = self._get_conn()
        try:
            conn.execute("DELETE FROM events WHERE investigation_id = ?", (investigation_id,))
            conn.execute("DELETE FROM findings WHERE investigation_id = ?", (investigation_id,))
            result = conn.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))
            conn.commit()
            
            deleted = result.rowcount > 0
            if deleted:
                logger.info(f"Deleted investigation {investigation_id}")
            return deleted
        finally:
            conn.close()
