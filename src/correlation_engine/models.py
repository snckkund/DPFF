from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

@dataclass
class PipelineEvent:
    timestamp: datetime
    source: str
    event_type: str
    details: str
    evidence_hash: str = ""
    collected_at: Optional[datetime] = None
    
@dataclass
class GitCommit:
    sha: str
    author: str
    timestamp: datetime
    message: str

@dataclass
class BuildInfo:
    build_id: str
    commit_sha: str
    timestamp: datetime
    status: str
    logs: str = ""

@dataclass
class RegistryImage:
    digest: str
    tag: str
    pusher: str
    timestamp: datetime
    
@dataclass
class Deployment:
    image_digest: str
    deployer: str
    timestamp: datetime
    
@dataclass
class CorrelationResult:
    is_compromised: bool
    root_cause: str
    timeline: List[PipelineEvent]
    severity: str = "HIGH"
    confidence: float = 0.8
    mitre_id: str = ""
    rule_id: str = ""
