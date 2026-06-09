"""
DPFF STIX 2.1 Export
Exports investigation findings as a STIX 2.1 Bundle for threat intelligence sharing.
Uses only Python stdlib — no stix2 library required.

STIX 2.1 objects generated:
- Identity (DPFF tool)
- Indicator (per detection rule match)
- Observed-Data (per event)
- Malware / Attack-Pattern (per MITRE technique)
- Relationship (links indicators to attack patterns)
- Report (wraps the full investigation)
"""
import json
import uuid
import hashlib
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.forensic_logger import get_logger

logger = get_logger('reporter.stix')

# STIX 2.1 spec version
STIX_SPEC = "2.1"

# MITRE ATT&CK to STIX Attack-Pattern mapping
MITRE_MAP = {
    "T1059.004": {
        "name": "Command and Scripting Interpreter: Unix Shell",
        "description": "Adversaries may abuse Unix shell commands and scripts for execution.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "description": "Adversaries may obtain and abuse credentials of existing accounts.",
    },
    "T1195.002": {
        "name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "description": "Adversaries may manipulate software dependencies delivered to targets.",
    },
    "T1525": {
        "name": "Implant Internal Image",
        "description": "Adversaries may implant container images with malicious code.",
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "description": "Adversaries may attempt to make payloads difficult to discover or analyze.",
    },
    "T1611": {
        "name": "Escape to Host",
        "description": "Adversaries may break out of a container to gain access to the host.",
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "description": "Adversaries may manipulate the supply chain to compromise targets.",
    },
}


def _deterministic_uuid(namespace: str, *args) -> str:
    """Generate a deterministic UUID v5 from namespace and arguments."""
    seed = f"{namespace}:{'|'.join(str(a) for a in args)}"
    return str(uuid.uuid5(uuid.NAMESPACE_URL, seed))


class StixExporter:
    def __init__(self, output_path: str = "forensic_export_stix.json"):
        self.output_path = output_path

    def export(
        self,
        events: List[PipelineEvent],
        findings: List[CorrelationResult],
        investigation_id: str = "",
    ) -> Dict[str, Any]:
        """Export as a STIX 2.1 Bundle."""
        logger.info(f"Generating STIX 2.1 bundle with {len(findings)} indicators...")

        objects = []

        # 1. Identity — DPFF Tool
        identity_id = f"identity--{_deterministic_uuid('dpff', 'identity')}"
        identity = {
            "type": "identity",
            "spec_version": STIX_SPEC,
            "id": identity_id,
            "created": datetime.now(tz=timezone.utc).isoformat(),
            "modified": datetime.now(tz=timezone.utc).isoformat(),
            "name": "DPFF - DevSecOps Pipeline Forensics Framework",
            "identity_class": "system",
            "description": "Automated forensic analysis tool for CI/CD pipeline security.",
        }
        objects.append(identity)

        # 2. Attack Patterns (from MITRE IDs in findings)
        attack_pattern_ids = {}
        seen_mitre = set()
        for f in findings:
            if f.mitre_id and f.mitre_id not in seen_mitre:
                seen_mitre.add(f.mitre_id)
                ap_id = f"attack-pattern--{_deterministic_uuid('mitre', f.mitre_id)}"
                mitre_info = MITRE_MAP.get(f.mitre_id, {"name": f.mitre_id, "description": ""})
                ap = {
                    "type": "attack-pattern",
                    "spec_version": STIX_SPEC,
                    "id": ap_id,
                    "created": datetime.now(tz=timezone.utc).isoformat(),
                    "modified": datetime.now(tz=timezone.utc).isoformat(),
                    "name": mitre_info["name"],
                    "description": mitre_info["description"],
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": f.mitre_id,
                            "url": f"https://attack.mitre.org/techniques/{f.mitre_id.replace('.', '/')}",
                        }
                    ],
                }
                objects.append(ap)
                attack_pattern_ids[f.mitre_id] = ap_id

        # 3. Indicators (per finding)
        indicator_ids = []
        for i, f in enumerate(findings, 1):
            ind_id = f"indicator--{_deterministic_uuid('finding', investigation_id, i)}"
            indicator_ids.append(ind_id)

            # Build STIX pattern from event details
            pattern_parts = []
            for e in f.timeline:
                escaped = e.details.replace("'", "\\'")
                pattern_parts.append(f"[artifact:payload_bin = '{escaped}']")
            pattern = " OR ".join(pattern_parts) if pattern_parts else "[artifact:payload_bin = 'unknown']"

            indicator = {
                "type": "indicator",
                "spec_version": STIX_SPEC,
                "id": ind_id,
                "created": datetime.now(tz=timezone.utc).isoformat(),
                "modified": datetime.now(tz=timezone.utc).isoformat(),
                "created_by_ref": identity_id,
                "name": f"DPFF {f.rule_id}: {f.root_cause[:80]}",
                "description": f.root_cause,
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": datetime.now(tz=timezone.utc).isoformat(),
                "confidence": int(f.confidence * 100),
                "labels": [f.severity.lower(), f.rule_id.lower()],
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": f.mitre_id,
                    }
                ] if f.mitre_id else [],
            }
            objects.append(indicator)

            # 4. Relationship: indicator → attack-pattern
            if f.mitre_id and f.mitre_id in attack_pattern_ids:
                rel_id = f"relationship--{_deterministic_uuid('rel', ind_id, attack_pattern_ids[f.mitre_id])}"
                rel = {
                    "type": "relationship",
                    "spec_version": STIX_SPEC,
                    "id": rel_id,
                    "created": datetime.now(tz=timezone.utc).isoformat(),
                    "modified": datetime.now(tz=timezone.utc).isoformat(),
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": attack_pattern_ids[f.mitre_id],
                    "confidence": int(f.confidence * 100),
                }
                objects.append(rel)

        # 5. Observed-Data (per event)
        observed_ids = []
        for i, e in enumerate(events):
            obs_id = f"observed-data--{_deterministic_uuid('event', investigation_id, i)}"
            observed_ids.append(obs_id)
            obs = {
                "type": "observed-data",
                "spec_version": STIX_SPEC,
                "id": obs_id,
                "created": datetime.now(tz=timezone.utc).isoformat(),
                "modified": datetime.now(tz=timezone.utc).isoformat(),
                "created_by_ref": identity_id,
                "first_observed": e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp),
                "last_observed": e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp),
                "number_observed": 1,
                "object_refs": [],
            }
            objects.append(obs)

        # 6. Report — wraps everything
        report_id = f"report--{_deterministic_uuid('report', investigation_id)}"
        report = {
            "type": "report",
            "spec_version": STIX_SPEC,
            "id": report_id,
            "created": datetime.now(tz=timezone.utc).isoformat(),
            "modified": datetime.now(tz=timezone.utc).isoformat(),
            "created_by_ref": identity_id,
            "name": f"DPFF Investigation {investigation_id}",
            "description": (
                f"Automated forensic analysis of CI/CD pipeline. "
                f"Analyzed {len(events)} events, detected {len(findings)} security incidents."
            ),
            "report_types": ["threat-report"],
            "published": datetime.now(tz=timezone.utc).isoformat(),
            "object_refs": [identity_id] + indicator_ids + list(attack_pattern_ids.values()) + observed_ids[:50],
        }
        objects.append(report)

        # Build the Bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{_deterministic_uuid('bundle', investigation_id)}",
            "objects": objects,
        }

        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(bundle, f, indent=2, default=str)

        logger.info(f"STIX 2.1 bundle saved to: {self.output_path} ({len(objects)} objects)")
        return bundle
