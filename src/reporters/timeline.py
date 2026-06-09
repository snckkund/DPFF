"""
DPFF Timeline Visualization
Generates an interactive HTML timeline of forensic events and incidents.
"""
import os
import json
from typing import List
from datetime import datetime
from src.correlation_engine.models import PipelineEvent, CorrelationResult
from src.forensic_logger import get_logger

logger = get_logger('reporter.timeline')

# Color map for sources
SOURCE_COLORS = {
    'Git': '#3498db',
    'GitHub': '#333333',
    'CI Runner': '#e67e22',
    'CI Build': '#e67e22',
    'CI Runner (benign)': '#27ae60',
    'CI Runner (malicious)': '#e74c3c',
    'Jenkins': '#d35400',
    'Harbor': '#1abc9c',
    'Kubernetes': '#326ce5',
    'Kubernetes (benign)': '#27ae60',
    'Kubernetes (malicious)': '#e74c3c',
    'Docker': '#2496ed',
}

SEVERITY_COLORS = {
    'CRITICAL': '#e74c3c',
    'HIGH': '#e67e22',
    'MEDIUM': '#f1c40f',
    'LOW': '#27ae60',
}


class TimelineReporter:
    def __init__(self, output_path: str = "forensic_timeline.html"):
        self.output_path = output_path

    def generate(self, events: List[PipelineEvent], findings: List[CorrelationResult]):
        logger.info(f"Generating timeline with {len(events)} events and {len(findings)} findings...")

        # Build event data for JS
        event_data = []
        for i, e in enumerate(events):
            ts_str = e.timestamp.isoformat() if hasattr(e.timestamp, 'isoformat') else str(e.timestamp)
            color = SOURCE_COLORS.get(e.source, '#95a5a6')

            # Check if this event appears in any finding
            is_malicious = False
            finding_info = None
            for f in findings:
                if e in f.timeline:
                    is_malicious = True
                    finding_info = {
                        'rule_id': f.rule_id,
                        'severity': f.severity,
                        'root_cause': f.root_cause,
                        'confidence': f.confidence,
                        'mitre_id': f.mitre_id,
                    }
                    color = SEVERITY_COLORS.get(f.severity, '#e74c3c')
                    break

            event_data.append({
                'id': i,
                'timestamp': ts_str,
                'source': e.source,
                'event_type': e.event_type,
                'details': e.details[:200],
                'hash': e.evidence_hash[:16] + '...' if e.evidence_hash else '',
                'color': color,
                'is_malicious': is_malicious,
                'finding': finding_info,
            })

        # Build findings summary for sidebar
        findings_data = []
        for i, f in enumerate(findings, 1):
            findings_data.append({
                'id': i,
                'rule_id': f.rule_id,
                'severity': f.severity,
                'root_cause': f.root_cause,
                'confidence': f.confidence,
                'mitre_id': f.mitre_id,
                'event_count': len(f.timeline),
            })

        events_json = json.dumps(event_data, default=str)
        findings_json = json.dumps(findings_data, default=str)

        html = self._render_html(events_json, findings_json, len(events), len(findings))

        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        logger.info(f"Timeline generated at: {self.output_path}")

    def _render_html(self, events_json: str, findings_json: str, 
                     event_count: int, finding_count: int) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DPFF Forensic Timeline</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; }}
        
        .header {{
            background: linear-gradient(135deg, #1a1f2e 0%, #0d1117 100%);
            padding: 20px 30px;
            border-bottom: 1px solid #21262d;
            display: flex; align-items: center; justify-content: space-between;
        }}
        .header h1 {{ color: #58a6ff; font-size: 22px; }}
        .header .stats {{ display: flex; gap: 20px; }}
        .stat-badge {{
            background: #161b22; border: 1px solid #30363d; border-radius: 6px;
            padding: 6px 14px; font-size: 13px;
        }}
        .stat-badge .num {{ color: #58a6ff; font-weight: 700; }}
        
        .container {{ display: flex; height: calc(100vh - 70px); }}
        
        /* Sidebar */
        .sidebar {{
            width: 320px; min-width: 320px; background: #0d1117;
            border-right: 1px solid #21262d; overflow-y: auto; padding: 15px;
        }}
        .sidebar h3 {{ color: #8b949e; font-size: 12px; text-transform: uppercase; margin-bottom: 10px; letter-spacing: 1px; }}
        
        .finding-card {{
            background: #161b22; border: 1px solid #21262d; border-radius: 8px;
            padding: 12px; margin-bottom: 10px; cursor: pointer; transition: all 0.2s;
            border-left: 3px solid transparent;
        }}
        .finding-card:hover {{ border-color: #30363d; transform: translateX(3px); }}
        .finding-card.active {{ border-left-color: #58a6ff; background: #1c2333; }}
        .finding-card .rule {{ font-size: 11px; color: #8b949e; }}
        .finding-card .cause {{ font-size: 13px; margin: 4px 0; line-height: 1.4; }}
        .finding-card .meta {{ display: flex; gap: 8px; align-items: center; margin-top: 6px; }}
        
        .sev-badge {{
            padding: 2px 6px; border-radius: 3px; font-size: 10px;
            font-weight: 700; text-transform: uppercase;
        }}
        .sev-CRITICAL {{ background: #e74c3c22; color: #e74c3c; border: 1px solid #e74c3c44; }}
        .sev-HIGH {{ background: #e67e2222; color: #e67e22; border: 1px solid #e67e2244; }}
        .sev-MEDIUM {{ background: #f1c40f22; color: #f1c40f; border: 1px solid #f1c40f44; }}
        .sev-LOW {{ background: #27ae6022; color: #27ae60; border: 1px solid #27ae6044; }}
        
        .mitre {{ font-size: 11px; color: #58a6ff; font-family: monospace; }}
        .conf {{ font-size: 11px; color: #8b949e; }}
        
        /* Filter buttons */
        .filters {{ margin-bottom: 15px; display: flex; flex-wrap: wrap; gap: 6px; }}
        .filter-btn {{
            background: #161b22; border: 1px solid #30363d; border-radius: 20px;
            padding: 4px 12px; font-size: 11px; color: #8b949e; cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{ background: #1f6feb22; color: #58a6ff; border-color: #1f6feb; }}
        
        /* Timeline */
        .timeline-area {{ flex: 1; overflow-y: auto; padding: 20px 30px; }}
        
        .timeline {{
            position: relative; padding-left: 40px;
        }}
        .timeline::before {{
            content: ''; position: absolute; left: 18px; top: 0; bottom: 0;
            width: 2px; background: #21262d;
        }}
        
        .event {{
            position: relative; margin-bottom: 12px; padding: 12px 16px;
            background: #161b22; border: 1px solid #21262d; border-radius: 8px;
            transition: all 0.2s; cursor: pointer;
        }}
        .event:hover {{ border-color: #30363d; }}
        .event.malicious {{ border-left: 3px solid #e74c3c; }}
        .event.highlighted {{ background: #1c2333; border-color: #58a6ff; box-shadow: 0 0 10px #58a6ff22; }}
        
        .event::before {{
            content: ''; position: absolute; left: -30px; top: 16px;
            width: 12px; height: 12px; border-radius: 50%;
            border: 2px solid #21262d; background: #161b22;
        }}
        .event.malicious::before {{ background: #e74c3c; border-color: #e74c3c; }}
        
        .event .ts {{ font-size: 11px; color: #8b949e; font-family: monospace; }}
        .event .source-badge {{
            display: inline-block; padding: 1px 8px; border-radius: 10px;
            font-size: 11px; font-weight: 600; margin-left: 8px;
        }}
        .event .type {{ font-size: 13px; color: #c9d1d9; margin: 4px 0; font-weight: 500; }}
        .event .details {{ font-size: 12px; color: #8b949e; word-break: break-word; }}
        .event .hash-tag {{ font-size: 10px; color: #484f58; font-family: monospace; margin-top: 4px; }}
        .event .finding-tag {{
            display: inline-block; margin-top: 6px; padding: 2px 8px;
            background: #e74c3c18; border: 1px solid #e74c3c44; border-radius: 4px;
            font-size: 11px; color: #e74c3c;
        }}
        
        /* Detail panel */
        .detail-panel {{
            display: none; position: fixed; right: 0; top: 70px; bottom: 0;
            width: 400px; background: #0d1117; border-left: 1px solid #21262d;
            padding: 20px; overflow-y: auto; z-index: 10;
        }}
        .detail-panel.open {{ display: block; }}
        .detail-panel h3 {{ color: #58a6ff; margin-bottom: 15px; }}
        .detail-panel .field {{ margin-bottom: 10px; }}
        .detail-panel .field label {{ font-size: 11px; color: #8b949e; text-transform: uppercase; display: block; }}
        .detail-panel .field .value {{ font-size: 13px; color: #c9d1d9; margin-top: 2px; }}
        .detail-panel .close-btn {{
            position: absolute; top: 15px; right: 15px; background: none;
            border: none; color: #8b949e; font-size: 18px; cursor: pointer;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🕵️ DPFF Forensic Timeline</h1>
        <div class="stats">
            <div class="stat-badge">Events: <span class="num">{event_count}</span></div>
            <div class="stat-badge">Incidents: <span class="num">{finding_count}</span></div>
            <div class="stat-badge">Generated: <span class="num">{datetime.now().strftime('%Y-%m-%d %H:%M')}</span></div>
        </div>
    </div>
    
    <div class="container">
        <div class="sidebar">
            <h3>Filters</h3>
            <div class="filters">
                <button class="filter-btn active" onclick="filterAll()">All</button>
                <button class="filter-btn" onclick="filterMalicious()">🔴 Malicious</button>
                <button class="filter-btn" onclick="filterBenign()">🟢 Benign</button>
            </div>
            
            <h3>Detected Incidents</h3>
            <div id="findings-list"></div>
        </div>
        
        <div class="timeline-area">
            <div class="timeline" id="timeline"></div>
        </div>
        
        <div class="detail-panel" id="detail-panel">
            <button class="close-btn" onclick="closeDetail()">✕</button>
            <div id="detail-content"></div>
        </div>
    </div>

    <script>
        const events = {events_json};
        const findings = {findings_json};
        
        function renderTimeline(filter) {{
            const container = document.getElementById('timeline');
            container.innerHTML = '';
            
            let filtered = events;
            if (filter === 'malicious') filtered = events.filter(e => e.is_malicious);
            if (filter === 'benign') filtered = events.filter(e => !e.is_malicious);
            
            filtered.forEach(e => {{
                const div = document.createElement('div');
                div.className = 'event' + (e.is_malicious ? ' malicious' : '');
                div.id = 'event-' + e.id;
                div.onclick = () => showDetail(e);
                
                let findingTag = '';
                if (e.finding) {{
                    findingTag = `<div class="finding-tag">${{e.finding.rule_id}} | ${{e.finding.severity}} | ${{e.finding.mitre_id}}</div>`;
                }}
                
                div.innerHTML = `
                    <div class="ts">${{e.timestamp}}<span class="source-badge" style="background:${{e.color}}22;color:${{e.color}};border:1px solid ${{e.color}}44">${{e.source}}</span></div>
                    <div class="type">${{e.event_type}}</div>
                    <div class="details">${{e.details}}</div>
                    ${{e.hash ? `<div class="hash-tag">SHA256: ${{e.hash}}</div>` : ''}}
                    ${{findingTag}}
                `;
                container.appendChild(div);
            }});
        }}
        
        function renderFindings() {{
            const container = document.getElementById('findings-list');
            container.innerHTML = '';
            
            findings.forEach((f, i) => {{
                const div = document.createElement('div');
                div.className = 'finding-card';
                div.onclick = () => highlightFinding(f, div);
                div.innerHTML = `
                    <div class="rule">${{f.rule_id}}</div>
                    <div class="cause">${{f.root_cause.substring(0, 100)}}...</div>
                    <div class="meta">
                        <span class="sev-badge sev-${{f.severity}}">${{f.severity}}</span>
                        <span class="mitre">${{f.mitre_id}}</span>
                        <span class="conf">${{(f.confidence * 100).toFixed(0)}}%</span>
                    </div>
                `;
                container.appendChild(div);
            }});
        }}
        
        function highlightFinding(finding, card) {{
            // Clear previous highlights
            document.querySelectorAll('.event').forEach(e => e.classList.remove('highlighted'));
            document.querySelectorAll('.finding-card').forEach(c => c.classList.remove('active'));
            card.classList.add('active');
            
            // Find and highlight matching events
            events.forEach(e => {{
                if (e.finding && e.finding.rule_id === finding.rule_id) {{
                    const el = document.getElementById('event-' + e.id);
                    if (el) {{
                        el.classList.add('highlighted');
                        el.scrollIntoView({{ behavior: 'smooth', block: 'center' }});
                    }}
                }}
            }});
        }}
        
        function showDetail(event) {{
            const panel = document.getElementById('detail-panel');
            const content = document.getElementById('detail-content');
            
            let html = `<h3>Event Details</h3>`;
            html += `<div class="field"><label>Timestamp</label><div class="value">${{event.timestamp}}</div></div>`;
            html += `<div class="field"><label>Source</label><div class="value">${{event.source}}</div></div>`;
            html += `<div class="field"><label>Type</label><div class="value">${{event.event_type}}</div></div>`;
            html += `<div class="field"><label>Details</label><div class="value">${{event.details}}</div></div>`;
            if (event.hash) html += `<div class="field"><label>Evidence Hash</label><div class="value" style="font-family:monospace;font-size:11px">${{event.hash}}</div></div>`;
            
            if (event.finding) {{
                html += `<h3 style="margin-top:20px;color:#e74c3c">⚠ Security Finding</h3>`;
                html += `<div class="field"><label>Rule</label><div class="value">${{event.finding.rule_id}}</div></div>`;
                html += `<div class="field"><label>Severity</label><div class="value"><span class="sev-badge sev-${{event.finding.severity}}">${{event.finding.severity}}</span></div></div>`;
                html += `<div class="field"><label>MITRE ATT&CK</label><div class="value">${{event.finding.mitre_id}}</div></div>`;
                html += `<div class="field"><label>Confidence</label><div class="value">${{(event.finding.confidence * 100).toFixed(0)}}%</div></div>`;
                html += `<div class="field"><label>Root Cause</label><div class="value">${{event.finding.root_cause}}</div></div>`;
            }}
            
            content.innerHTML = html;
            panel.classList.add('open');
        }}
        
        function closeDetail() {{ document.getElementById('detail-panel').classList.remove('open'); }}
        
        function filterAll() {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            renderTimeline('all');
        }}
        function filterMalicious() {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            renderTimeline('malicious');
        }}
        function filterBenign() {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');
            renderTimeline('benign');
        }}
        
        // Init
        renderTimeline('all');
        renderFindings();
    </script>
</body>
</html>"""
