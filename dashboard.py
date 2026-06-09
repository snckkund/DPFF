import sys
import os

# Ensure project root is on path for direct script execution
_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import streamlit as st
import pandas as pd

from src.main import run_simulation, run_analysis, analyze_events
from src.collectors.loader import SimulationLoader
from src.integrity import verify_all, generate_chain_of_custody
from src.database import ForensicDatabase
from src.reporters.timeline import TimelineReporter
from src.reporters.json_export import JsonExporter
from src.reporters.stix_export import StixExporter

st.set_page_config(page_title="DPFF Forensic Dashboard", layout="wide")

st.title("🕵️ DevSecOps Pipeline Forensics Framework")
st.markdown("### Automated Incident Investigation Dashboard")

# Sidebar for controls
st.sidebar.header("Investigation Controls")
mode = st.sidebar.radio("Select Mode", ["Simulation (Demo)", "Live Analysis", "Investigation History"])

if mode == "Simulation (Demo)":
    st.sidebar.info("Running against ground-truth dataset in `simulation/`.")
    if st.sidebar.button("Run Simulation"):
        with st.spinner("Loading simulation data..."):
            # Mock args
            class Args: pass
            args = Args()
            
            events = run_simulation(args)
            findings = analyze_events(events)
            integrity = verify_all(events)
            custody = generate_chain_of_custody(events) if events else {}
            
            # Save to DB
            db = ForensicDatabase()
            inv_id = db.save_investigation("simulate", events, findings, 
                                           root_hash=custody.get('root_hash', ''))
            
            # Auto-generate exports
            TimelineReporter("forensic_timeline.html").generate(events, findings)
            JsonExporter("forensic_export.json").export(
                events=events, findings=findings, investigation_id=inv_id,
                mode="simulate", integrity=integrity, custody=custody,
            )
            StixExporter("forensic_export_stix.json").export(
                events=events, findings=findings, investigation_id=inv_id,
            )
            
            st.session_state['events'] = events
            st.session_state['findings'] = findings
            st.session_state['integrity'] = integrity
            st.session_state['custody'] = custody
            st.session_state['inv_id'] = inv_id
            st.success(f"✅ Investigation {inv_id}: loaded {len(events)} events")

elif mode == "Live Analysis":
    st.sidebar.info("Connecting to configured CI/CD tools.")
    config_path = st.sidebar.text_input("Config Path", "config.yaml")
    if st.sidebar.button("Run Analysis"):
        with st.spinner("Fetching logs from APIs..."):
            class Args:
                config = config_path
            args = Args()
            
            events = run_analysis(args)
            findings = analyze_events(events)
            integrity = verify_all(events)
            custody = generate_chain_of_custody(events) if events else {}
            
            db = ForensicDatabase()
            inv_id = db.save_investigation("analyze", events, findings,
                                           root_hash=custody.get('root_hash', ''))
            
            # Auto-generate exports
            TimelineReporter("forensic_timeline.html").generate(events, findings)
            JsonExporter("forensic_export.json").export(
                events=events, findings=findings, investigation_id=inv_id,
                mode="analyze", integrity=integrity, custody=custody,
            )
            StixExporter("forensic_export_stix.json").export(
                events=events, findings=findings, investigation_id=inv_id,
            )
            
            st.session_state['events'] = events
            st.session_state['findings'] = findings
            st.session_state['integrity'] = integrity
            st.session_state['custody'] = custody
            st.session_state['inv_id'] = inv_id
            st.success(f"✅ Investigation {inv_id}: loaded {len(events)} events")

elif mode == "Investigation History":
    st.subheader("📜 Past Investigations")
    db = ForensicDatabase()
    investigations = db.list_investigations()
    
    if not investigations:
        st.info("No past investigations found. Run a simulation or analysis first.")
    else:
        history_df = pd.DataFrame(investigations)
        history_df.columns = ['ID', 'Timestamp', 'Mode', 'Events', 'Findings', 'Root Hash']
        st.dataframe(history_df, use_container_width=True)
        
        # Allow loading a past investigation
        selected_id = st.selectbox("Load Investigation", 
                                   options=[inv['id'] for inv in investigations],
                                   format_func=lambda x: f"{x} — {next(i['mode'] for i in investigations if i['id']==x)} ({next(i['timestamp'][:19] for i in investigations if i['id']==x)})")
        
        if st.button("Load Selected"):
            loaded = db.load_investigation(selected_id)
            if loaded:
                st.session_state['events'] = loaded['events']
                st.session_state['findings'] = loaded['findings']
                st.session_state['integrity'] = verify_all(loaded['events'])
                st.session_state['inv_id'] = selected_id
                st.success(f"Loaded investigation {selected_id}")

# Display Results
if 'findings' in st.session_state:
    findings = st.session_state['findings']
    events = st.session_state['events']
    
    # KPIs
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric("Total Events Analyzed", len(events))
    kpi2.metric("Security Incidents", len(findings), delta_color="inverse")
    kpi3.metric("Evidence Sources", len(set(e.source for e in events)))
    
    # Integrity status
    integrity = st.session_state.get('integrity', {})
    integrity_status = "✅ INTACT" if integrity.get('integrity_intact', False) else "❌ COMPROMISED"
    kpi4.metric("Evidence Integrity", integrity_status)
    
    st.divider()
    
    # Incident Table with MITRE, Rule ID, Confidence
    st.subheader("🚨 Detected Incidents")
    
    if findings:
        data = []
        for f in findings:
            data.append({
                "Rule": f.rule_id,
                "Severity": f.severity,
                "MITRE ATT&CK": f.mitre_id,
                "Confidence": f"{f.confidence * 100:.0f}%",
                "Root Cause": f.root_cause[:100],
                "Evidence": len(f.timeline),
            })
        st.table(data)
        
        # Detailed Drilldown
        st.subheader("🔬 Evidence Drilldown")
        selected_incident = st.selectbox("Select Incident to Investigate", 
                                       options=range(len(findings)), 
                                       format_func=lambda x: f"[{findings[x].rule_id}] [{findings[x].severity}] {findings[x].root_cause[:80]}")
        
        incident = findings[selected_incident]
        
        # Incident metadata
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Rule", incident.rule_id)
        col2.metric("MITRE ID", incident.mitre_id)
        col3.metric("Confidence", f"{incident.confidence * 100:.0f}%")
        col4.metric("Severity", incident.severity)
        
        # Timeline
        timeline_data = []
        for e in incident.timeline:
            timeline_data.append({
                "Timestamp": e.timestamp,
                "Source": e.source,
                "Type": e.event_type,
                "Details": e.details,
                "Evidence Hash": e.evidence_hash[:16] + '...' if e.evidence_hash else 'N/A'
            })
        
        df = pd.DataFrame(timeline_data)
        st.dataframe(df, use_container_width=True)
        
    else:
        st.success("No security incidents detected. Pipeline is clean.")

    # Export section
    st.divider()
    st.subheader("📦 Export Forensic Reports")
    
    exp1, exp2, exp3 = st.columns(3)
    
    if os.path.exists("forensic_timeline.html"):
        with open("forensic_timeline.html", "r", encoding="utf-8") as f:
            exp1.download_button("⬇ Timeline (HTML)", f.read(), "forensic_timeline.html", mime="text/html")
    
    if os.path.exists("forensic_export.json"):
        with open("forensic_export.json", "r", encoding="utf-8") as f:
            exp2.download_button("⬇ JSON Export", f.read(), "forensic_export.json", mime="application/json")
    
    if os.path.exists("forensic_export_stix.json"):
        with open("forensic_export_stix.json", "r", encoding="utf-8") as f:
            exp3.download_button("⬇ STIX 2.1 Bundle", f.read(), "forensic_export_stix.json", mime="application/json")

    # Chain of Custody section
    custody = st.session_state.get('custody')
    if custody:
        with st.expander("🔗 Chain of Custody Manifest"):
            st.json(custody)

else:
    st.info("👈 Select a mode and click 'Run' to start investigation.")
