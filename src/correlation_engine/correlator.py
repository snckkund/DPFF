import re
from typing import List, Dict, Optional
from datetime import timedelta
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.forensic_logger import get_logger

logger = get_logger('correlator')


# ── Indicator patterns ──────────────────────────────────────────────────────

# Pipeline injection: data exfiltration commands
EXFIL_PATTERNS = [
    re.compile(r'\bcurl\b.*(-d|--data|--upload-file|\|)', re.IGNORECASE),
    re.compile(r'\bcurl\b.*https?://(?!github\.com|registry|harbor|jenkins)', re.IGNORECASE),
    re.compile(r'\bwget\b.*-O\s*-.*\|', re.IGNORECASE),
    re.compile(r'\bnc(at)?\b.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE),
    re.compile(r'\bcurl\b.*\$\{?\w*(SECRET|TOKEN|KEY|PASS|CRED)', re.IGNORECASE),
    re.compile(r'curl.*attacker', re.IGNORECASE),
]

# Obfuscation: encoded/eval commands  
OBFUSCATION_PATTERNS = [
    re.compile(r'\bbase64\s+(-d|--decode)\b', re.IGNORECASE),
    re.compile(r'\bbase64\b.*\|.*\b(sh|bash|python|eval)\b', re.IGNORECASE),
    re.compile(r'\beval\b\s*\(', re.IGNORECASE),
    re.compile(r'\bexec\b\s*\(', re.IGNORECASE),
    re.compile(r'python\s+-c\s+["\'].*(__import__|exec|eval)', re.IGNORECASE),
    re.compile(r'powershell.*-[eE]nc', re.IGNORECASE),
    re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'),  # hex-encoded strings
    re.compile(r'\$\(echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64', re.IGNORECASE),
]

# Credential theft: suspicious commit indicators
SUSPICIOUS_AUTHOR_PATTERNS = [
    re.compile(r'\b(mallory|attacker|evil|hacker|admin-temp|test-admin)\b', re.IGNORECASE),
]

SENSITIVE_FILE_PATTERNS = [
    re.compile(r'\.(env|pem|key|p12|pfx|jks|keystore)\b', re.IGNORECASE),
    re.compile(r'(credentials|secrets|passwords|tokens|\.aws/|\.ssh/|id_rsa)', re.IGNORECASE),
    re.compile(r'(Jenkinsfile|\.github/workflows/|\.gitlab-ci)', re.IGNORECASE),
]

# Dependency confusion indicators
DEPENDENCY_CONFUSION_PATTERNS = [
    re.compile(r'@(9\d\.\d|[1-9]\d{2,}\.\d)', re.IGNORECASE),  # abnormally high versions (>=90.x or >=100.x)
    re.compile(r'internal[-_].*@.*\bpublic\b', re.IGNORECASE),
    re.compile(r'(npm\s+warn|npm\s+ERR!).*registry\.npmjs\.org.*internal', re.IGNORECASE),
    re.compile(r'internal-utils.*99\.', re.IGNORECASE),
]

# Privileged / dangerous container patterns
PRIVILEGED_PATTERNS = [
    re.compile(r'\[PRIVILEGED\]', re.IGNORECASE),
    re.compile(r'privileged\s*[:=]\s*true', re.IGNORECASE),
    re.compile(r'hostNetwork\s*[:=]\s*true', re.IGNORECASE),
    re.compile(r'hostPID\s*[:=]\s*true', re.IGNORECASE),
    re.compile(r'hostIPC\s*[:=]\s*true', re.IGNORECASE),
    re.compile(r'CAP_SYS_ADMIN', re.IGNORECASE),
    re.compile(r'allowPrivilegeEscalation\s*[:=]\s*true', re.IGNORECASE),
]

# Artifact tampering: unauthorized pushers
UNAUTHORIZED_PUSHER_PATTERNS = [
    re.compile(r'User:\s*(attacker|unknown|anonymous|external)', re.IGNORECASE),
]


class EventCorrelator:
    """
    Correlation engine that applies pattern-based detection rules
    with confidence scoring and MITRE ATT&CK mapping.
    """

    CORRELATION_WINDOW = timedelta(minutes=30)

    def __init__(self, events: List[PipelineEvent]):
        self.events = sorted(events, key=lambda e: e.timestamp)

    def analyze(self) -> List[CorrelationResult]:
        logger.info(f"Starting correlation analysis on {len(self.events)} events...")
        findings: List[CorrelationResult] = []
        findings.extend(self._detect_pipeline_injection())
        findings.extend(self._detect_credential_theft())
        findings.extend(self._detect_dependency_confusion())
        findings.extend(self._detect_artifact_tampering())
        findings.extend(self._detect_obfuscation())
        findings.extend(self._detect_privileged_container())
        findings.extend(self._detect_cross_event_chains())
        logger.info(f"Correlation complete: {len(findings)} incidents detected")
        return findings

    # ── Helper ──────────────────────────────────────────────────────────────

    @staticmethod
    def _match_any(text: str, patterns: list) -> List[re.Pattern]:
        """Return all patterns that match the text."""
        return [p for p in patterns if p.search(text)]

    @staticmethod
    def _confidence_from_matches(match_count: int, max_indicators: int = 3) -> float:
        """Scale confidence: 1 match → 0.6, 2 → 0.8, 3+ → 0.95."""
        if match_count <= 0:
            return 0.0
        if match_count == 1:
            return 0.6
        if match_count == 2:
            return 0.8
        return 0.95

    # ── Detection Rules ─────────────────────────────────────────────────────

    def _detect_pipeline_injection(self) -> List[CorrelationResult]:
        """
        RULE-001: Pipeline Injection / Data Exfiltration
        MITRE: T1059.004 (Command and Scripting Interpreter: Unix Shell)
        """
        results = []
        for event in self.events:
            hits = self._match_any(event.details, EXFIL_PATTERNS)
            if hits:
                confidence = self._confidence_from_matches(len(hits))
                matched = ', '.join(h.pattern[:40] for h in hits)
                logger.warning(
                    f"[RULE-001] Pipeline injection detected | source={event.source} | "
                    f"confidence={confidence} | matched_patterns={len(hits)}"
                )
                results.append(CorrelationResult(
                    is_compromised=True,
                    root_cause=(
                        f"Pipeline Injection Detected: Suspicious command found in build logs "
                        f"matching {len(hits)} exfiltration indicator(s)."
                    ),
                    timeline=[event],
                    severity="CRITICAL",
                    confidence=confidence,
                    mitre_id="T1059.004",
                    rule_id="RULE-001",
                ))
        return results

    def _detect_credential_theft(self) -> List[CorrelationResult]:
        """
        RULE-002: Credential Theft / Unauthorized Access
        MITRE: T1078 (Valid Accounts) + T1552 (Unsecured Credentials)
        """
        results = []
        for event in self.events:
            indicators = 0
            reasons = []

            # Check suspicious authors
            if self._match_any(event.details, SUSPICIOUS_AUTHOR_PATTERNS):
                indicators += 1
                reasons.append("flagged author")

            # Check sensitive file access in commits
            if event.event_type in ('Commit', 'Push', 'Pull Request') and \
               self._match_any(event.details, SENSITIVE_FILE_PATTERNS):
                indicators += 1
                reasons.append("sensitive file modification")

            # Check force push
            if 'force' in event.details.lower() and 'push' in event.event_type.lower():
                indicators += 1
                reasons.append("force push")

            if indicators > 0:
                confidence = self._confidence_from_matches(indicators)
                logger.warning(
                    f"[RULE-002] Credential theft suspected | source={event.source} | "
                    f"indicators={', '.join(reasons)} | confidence={confidence}"
                )
                results.append(CorrelationResult(
                    is_compromised=True,
                    root_cause=(
                        f"Credential Theft Suspected: {', '.join(reasons).capitalize()} "
                        f"detected in {event.source}."
                    ),
                    timeline=[event],
                    severity="HIGH",
                    confidence=confidence,
                    mitre_id="T1078",
                    rule_id="RULE-002",
                ))
        return results

    def _detect_dependency_confusion(self) -> List[CorrelationResult]:
        """
        RULE-003: Dependency Confusion / Supply Chain Attack
        MITRE: T1195.002 (Supply Chain Compromise: Compromise Software Supply Chain)
        """
        results = []
        for event in self.events:
            hits = self._match_any(event.details, DEPENDENCY_CONFUSION_PATTERNS)
            if hits:
                confidence = self._confidence_from_matches(len(hits))
                logger.warning(
                    f"[RULE-003] Dependency confusion detected | source={event.source} | "
                    f"confidence={confidence}"
                )
                results.append(CorrelationResult(
                    is_compromised=True,
                    root_cause=(
                        f"Dependency Confusion Detected: Internal package pulled from "
                        f"public registry with suspicious version pattern."
                    ),
                    timeline=[event],
                    severity="CRITICAL",
                    confidence=confidence,
                    mitre_id="T1195.002",
                    rule_id="RULE-003",
                ))
        return results

    def _detect_artifact_tampering(self) -> List[CorrelationResult]:
        """
        RULE-004: Artifact Tampering / Image Replacement
        MITRE: T1525 (Implant Internal Image)
        """
        results = []

        # Strategy 1: Detect unauthorized pushers
        for event in self.events:
            if 'Push' in event.event_type or 'push' in event.event_type.lower():
                if self._match_any(event.details, UNAUTHORIZED_PUSHER_PATTERNS):
                    logger.warning(
                        f"[RULE-004] Artifact tampering detected | source={event.source} | "
                        f"unauthorized pusher found"
                    )
                    results.append(CorrelationResult(
                        is_compromised=True,
                        root_cause=(
                            f"Artifact Tampering Detected: Unauthorized image push "
                            f"by suspicious user overwriting existing tag."
                        ),
                        timeline=[event],
                        severity="CRITICAL",
                        confidence=0.85,
                        mitre_id="T1525",
                        rule_id="RULE-004",
                    ))

        # Strategy 2: Detect digest mismatch (multiple pushes for same tag)
        push_events = [e for e in self.events if 'push' in e.event_type.lower()]
        digest_map: Dict[str, List[PipelineEvent]] = {}
        for pe in push_events:
            # Extract tag from details if present
            tag_match = re.search(r'Tag:\s*(\S+)', pe.details)
            if tag_match:
                tag = tag_match.group(1)
                digest_map.setdefault(tag, []).append(pe)

        for tag, events in digest_map.items():
            if len(events) > 1:
                # Multiple pushes for same tag — check digests
                digests = set()
                has_digest = False
                for e in events:
                    d_match = re.search(r'Digest:\s*(\S+)', e.details)
                    if d_match:
                        digests.add(d_match.group(1))
                        has_digest = True
                
                if has_digest and len(digests) > 1:
                    logger.warning(
                        f"[RULE-004] Digest mismatch for tag {tag}: "
                        f"{len(digests)} different digests across {len(events)} pushes"
                    )
                    results.append(CorrelationResult(
                        is_compromised=True,
                        root_cause=(
                            f"Artifact Tampering Detected: Tag '{tag}' was pushed "
                            f"{len(events)} times with {len(digests)} different digests."
                        ),
                        timeline=events,
                        severity="CRITICAL",
                        confidence=0.9,
                        mitre_id="T1525",
                        rule_id="RULE-004",
                    ))
                elif not has_digest:
                     # No digests found (e.g. local registry), but tag was overwritten
                     logger.warning(
                        f"[RULE-004] Potential tampering for tag {tag}: "
                        f"Overwritten {len(events)} times (digests unavailable)."
                    )
                     results.append(CorrelationResult(
                        is_compromised=True,
                        root_cause=(
                            f"Artifact Tampering Suspected: Tag '{tag}' was overwritten "
                            f"{len(events)} times. (Registry did not provide digests)."
                        ),
                        timeline=events,
                        severity="HIGH",
                        confidence=0.7,
                        mitre_id="T1525",
                        rule_id="RULE-004",
                    ))
        return results

    def _detect_obfuscation(self) -> List[CorrelationResult]:
        """
        RULE-005: Obfuscated / Encoded Commands
        MITRE: T1027 (Obfuscated Files or Information)
        """
        results = []
        for event in self.events:
            hits = self._match_any(event.details, OBFUSCATION_PATTERNS)
            if hits:
                confidence = self._confidence_from_matches(len(hits))
                logger.warning(
                    f"[RULE-005] Obfuscated command detected | source={event.source} | "
                    f"matched_patterns={len(hits)} | confidence={confidence}"
                )
                results.append(CorrelationResult(
                    is_compromised=True,
                    root_cause=(
                        f"Obfuscated Command Detected: {len(hits)} encoding/evasion "
                        f"indicator(s) found in pipeline step."
                    ),
                    timeline=[event],
                    severity="HIGH",
                    confidence=confidence,
                    mitre_id="T1027",
                    rule_id="RULE-005",
                ))
        return results

    def _detect_privileged_container(self) -> List[CorrelationResult]:
        """
        RULE-006: Privileged / Dangerous Container Configuration
        MITRE: T1611 (Escape to Host)
        """
        results = []
        for event in self.events:
            hits = self._match_any(event.details, PRIVILEGED_PATTERNS)
            if hits:
                confidence = self._confidence_from_matches(len(hits))
                matched_names = []
                for h in hits:
                    if 'PRIVILEGED' in h.pattern or 'privileged' in h.pattern:
                        matched_names.append('privileged')
                    elif 'hostNetwork' in h.pattern:
                        matched_names.append('hostNetwork')
                    elif 'hostPID' in h.pattern:
                        matched_names.append('hostPID')
                    elif 'CAP_SYS_ADMIN' in h.pattern:
                        matched_names.append('CAP_SYS_ADMIN')
                    else:
                        matched_names.append('dangerous config')

                logger.warning(
                    f"[RULE-006] Privileged container detected | source={event.source} | "
                    f"flags={', '.join(matched_names)} | confidence={confidence}"
                )
                results.append(CorrelationResult(
                    is_compromised=True,
                    root_cause=(
                        f"Privileged Container Detected: Pod deployed with dangerous "
                        f"security config ({', '.join(matched_names)})."
                    ),
                    timeline=[event],
                    severity="CRITICAL",
                    confidence=confidence,
                    mitre_id="T1611",
                    rule_id="RULE-006",
                ))
        return results

    # ── Cross-Event Correlation ─────────────────────────────────────────────

    def _detect_cross_event_chains(self) -> List[CorrelationResult]:
        """
        RULE-007: Multi-Stage Attack Chain Detection
        MITRE: T1195 (Supply Chain Compromise)

        Links events that occur within a 30-minute window:
          suspicious commit → abnormal build → unauthorized push
        """
        results = []

        # Find suspicious commits
        suspicious_commits = [
            e for e in self.events
            if e.event_type in ('Commit', 'Push', 'git.push')
            and self._match_any(e.details, SUSPICIOUS_AUTHOR_PATTERNS)
        ]

        for commit in suspicious_commits:
            window_start = commit.timestamp
            window_end = commit.timestamp + self.CORRELATION_WINDOW

            # Find build events in the window
            related_builds = [
                e for e in self.events
                if e.event_type in ('Step Execution', 'Build', 'NPM Install')
                and window_start <= e.timestamp <= window_end
                and e != commit
            ]

            # Find push/deploy events in the window
            related_deploys = [
                e for e in self.events
                if e.event_type in ('Image Push', 'Image push', 'Image pull', 'Deployment', 'Scheduled')
                and window_start <= e.timestamp <= window_end
                and e != commit
            ]

            chain = [commit] + related_builds[:2] + related_deploys[:2]

            if len(chain) >= 3:
                stages = len(chain)
                confidence = min(0.95, 0.5 + (stages * 0.1))
                logger.warning(
                    f"[RULE-007] Multi-stage attack chain detected | "
                    f"stages={stages} | window=30min | confidence={confidence:.2f}"
                )
                results.append(CorrelationResult(
                    is_compromised=True,
                    root_cause=(
                        f"Multi-Stage Attack Chain: {stages} correlated events detected "
                        f"within a 30-minute window starting from suspicious commit."
                    ),
                    timeline=chain,
                    severity="CRITICAL",
                    confidence=confidence,
                    mitre_id="T1195",
                    rule_id="RULE-007",
                ))

        return results
