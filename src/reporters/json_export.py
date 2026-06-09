"""
DPFF JSON Forensic Export
Exports investigation results as a structured JSON file.
"""
import json
from typing import List, Optional, Dict, Any
from datetime import datetime
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.forensic_logger import get_logger

logger = get_logger('reporter.json')


class JsonExporter:
    def __init__(self, output_path: str = "forensic_export.json"):
        self.output_path = output_path

    def export(
        self,
        events: List[PipelineEvent],
        findings: List[CorrelationResult],
        investigation_id: str = "",
        mode: str = "",
        duration: float = 0.0,
        integrity: Optional[Dict] = None,
        custody: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Export investigation results as structured JSON."""
        logger.info(f"Generating JSON export with {len(events)} events and {len(findings)} findings...")

        export_data = {
            "dpff_version": "2.0.0",
            "export_format": "DPFF-JSON",
            "exported_at": datetime.now().isoformat(),
            "investigation": {
                "id": investigation_id,
                "mode": mode,
                "duration_seconds": round(duration, 2),
                "event_count": len(events),
                "finding_count": len(findings),
            },
            "integrity": {
                "status": "INTACT" if (integrity or {}).get('integrity_intact', True) else "COMPROMISED",
                "verified_count": (integrity or {}).get('verified_count', 0),
                "failed_count": (integrity or {}).get('failed_count', 0),
            },
            "chain_of_custody": {
                "root_hash": (custody or {}).get('root_hash', ''),
                "algorithm": "SHA-256",
                "event_hashes": (custody or {}).get('event_hashes', []),
            },
            "findings": [self._serialize_finding(f, i) for i, f in enumerate(findings, 1)],
            "events": [self._serialize_event(e) for e in events],
        }

        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, default=str)

        logger.info(f"JSON export saved to: {self.output_path}")
        return export_data

    def _serialize_event(self, event: PipelineEvent) -> Dict[str, Any]:
        return {
            "timestamp": event.timestamp.isoformat() if hasattr(event.timestamp, 'isoformat') else str(event.timestamp),
            "source": event.source,
            "event_type": event.event_type,
            "details": event.details,
            "evidence_hash": event.evidence_hash,
            "collected_at": event.collected_at.isoformat() if event.collected_at else None,
        }

    def _serialize_finding(self, finding: CorrelationResult, index: int) -> Dict[str, Any]:
        return {
            "incident_number": index,
            "rule_id": finding.rule_id,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "mitre_attack_id": finding.mitre_id,
            "root_cause": finding.root_cause,
            "is_compromised": finding.is_compromised,
            "evidence_timeline": [self._serialize_event(e) for e in finding.timeline],
        }
