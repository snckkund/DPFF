import sys
import os
import argparse
import yaml
import time
from datetime import datetime

# Ensure project root is on path for direct script execution
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)


def get_base_dir():
    """Return the base directory — handles both script and PyInstaller exe."""
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS  # PyInstaller temp directory with bundled data
    return _PROJECT_ROOT

from src.collectors.loader import SimulationLoader
from src.collectors.github import GitHubCollector
from src.collectors.harbor import HarborCollector
from src.collectors.jenkins import JenkinsCollector
from src.collectors.kubernetes import KubernetesCollector
from src.collectors.docker_collector import DockerCollector
from src.correlation_engine.correlator import EventCorrelator
from src.reporters.html import HtmlReporter
from src.reporters.timeline import TimelineReporter
from src.reporters.json_export import JsonExporter
from src.reporters.stix_export import StixExporter
from src.forensic_logger import get_logger
from src.integrity import hash_events, verify_all, generate_chain_of_custody
from src.database import ForensicDatabase
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

logger = get_logger('main')

def load_config(path):
    with open(path, 'r') as f:
        return yaml.safe_load(f)

def run_simulation(args):
    logger.info("Running in SIMULATION mode...")
    sim_dir = os.path.join(get_base_dir(), 'simulation')
    loader = SimulationLoader(sim_dir)
    events = loader.load_all()
    
    # Hash all evidence
    hash_events(events)
    logger.info(f"Simulation loaded: {len(events)} events collected and hashed")
    return events

def run_analysis(args, config_override=None):
    logger.info("Running in ANALYSIS mode...")
    
    if config_override:
        config = config_override
    elif os.path.exists(args.config):
        config = load_config(args.config)
    else:
        logger.error(f"Config file {args.config} not found.")
        return []

    events = []
    
    # 1. GitHub Collection
    gh_collector = GitHubCollector(config.get('collector_settings', {}))
    events.extend(gh_collector.collect())
    
    # 2. Jenkins Collection
    jenkins_collector = JenkinsCollector(config.get('collector_settings', {}))
    events.extend(jenkins_collector.collect())
    
    # 3. Harbor Collection
    harbor_collector = HarborCollector(config.get('collector_settings', {}))
    events.extend(harbor_collector.collect())

    # 4. Kubernetes Collection
    k8s_collector = KubernetesCollector(config.get('collector_settings', {}))
    events.extend(k8s_collector.collect())

    # 5. Docker Collection
    docker_collector = DockerCollector(config.get('collector_settings', {}))
    events.extend(docker_collector.collect())
    
    # Hash all evidence
    hash_events(events)
    logger.info(f"Analysis complete: {len(events)} events collected and hashed")
    return events

def analyze_events(events):
    logger.info("Correlating events...")
    correlator = EventCorrelator(events)
    findings = correlator.analyze()
    logger.info(f"Analysis complete: {len(findings)} security incidents found")
    return findings

def show_history(args):
    """Show past investigations from the database."""
    db = ForensicDatabase()
    investigations = db.list_investigations()
    
    if not investigations:
        print("\nNo past investigations found.\n")
        return
    
    print(f"\n{'='*80}")
    print(f"  DPFF Investigation History ({len(investigations)} records)")
    print(f"{'='*80}")
    print(f"  {'ID':<10} {'Date':<22} {'Mode':<14} {'Events':<10} {'Findings':<10}")
    print(f"  {'-'*10} {'-'*22} {'-'*14} {'-'*10} {'-'*10}")
    
    for inv in investigations:
        print(f"  {inv['id']:<10} {inv['timestamp'][:19]:<22} {inv['mode']:<14} {inv['event_count']:<10} {inv['finding_count']:<10}")
    
    print(f"{'='*80}\n")

def main():
    parser = argparse.ArgumentParser(description="DPFF Forensic Tool")
    subparsers = parser.add_subparsers(dest='command', help='Mode of operation')
    
    # Simulate Command
    parser_sim = subparsers.add_parser('simulate', help='Run forensic analysis on simulated ground-truth data')
    
    # Analyze Command
    parser_analyze = subparsers.add_parser('analyze', help='Run forensic analysis on real data sources')
    parser_analyze.add_argument('--config', default='config.yaml', help='Path to configuration file')
    
    # History Command
    parser_history = subparsers.add_parser('history', help='Show past investigation records')
    
    args = parser.parse_args()
    
    # Handle history command separately
    if args.command == 'history':
        show_history(args)
        return
    
    events = []
    mode = args.command or 'unknown'
    start_time = time.time()
    
    if args.command == 'simulate':
        events = run_simulation(args)
    elif args.command == 'analyze':
        events = run_analysis(args)
    else:
        parser.print_help()
        return

    logger.info(f"Loaded {len(events)} events")
    
    findings = analyze_events(events)
    
    duration = time.time() - start_time
    
    # Verify evidence integrity
    integrity_result = verify_all(events)
    
    # Generate chain of custody
    custody = generate_chain_of_custody(events) if events else {}
    
    # Save to database
    db = ForensicDatabase()
    investigation_id = db.save_investigation(
        mode=mode,
        events=events,
        findings=findings,
        root_hash=custody.get('root_hash', ''),
        duration_seconds=duration
    )
    
    # Console Report
    print(f"\n{'='*60}")
    print(f"  DPFF Investigation Complete")
    print(f"{'='*60}")
    print(f"  Investigation ID : {investigation_id}")
    print(f"  Mode             : {mode}")
    print(f"  Events Analyzed  : {len(events)}")
    print(f"  Incidents Found  : {len(findings)}")
    print(f"  Evidence Integrity: {'INTACT' if integrity_result['integrity_intact'] else 'COMPROMISED'}")
    print(f"  Duration         : {duration:.2f}s")
    if custody:
        print(f"  Root Hash        : {custody['root_hash'][:32]}...")
    print(f"{'='*60}\n")
    
    for i, finding in enumerate(findings, 1):
        print(f"  [{finding.severity}] [{finding.rule_id}] [{finding.mitre_id}] Incident #{i}: {finding.root_cause}")
        
    # Generate Reports
    # 1. HTML Report
    reporter = HtmlReporter("forensic_report.html")
    reporter.generate(findings)
    
    # 2. Interactive Timeline
    timeline = TimelineReporter("forensic_timeline.html")
    timeline.generate(events, findings)
    
    # 3. JSON Export
    json_exporter = JsonExporter("forensic_export.json")
    json_exporter.export(
        events=events, findings=findings,
        investigation_id=investigation_id, mode=mode,
        duration=duration, integrity=integrity_result, custody=custody,
    )
    
    # 4. STIX 2.1 Export
    stix_exporter = StixExporter("forensic_export_stix.json")
    stix_exporter.export(
        events=events, findings=findings,
        investigation_id=investigation_id,
    )
    
    print(f"\n  Reports generated:")
    print(f"    HTML Report    : forensic_report.html")
    print(f"    Timeline       : forensic_timeline.html")
    print(f"    JSON Export    : forensic_export.json")
    print(f"    STIX 2.1 Bundle: forensic_export_stix.json")
    
    logger.info(f"Investigation {investigation_id} completed in {duration:.2f}s")

if __name__ == "__main__":
    main()

