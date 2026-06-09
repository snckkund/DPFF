import os
from typing import List
from datetime import datetime
from src.correlation_engine.models import CorrelationResult
from src.forensic_logger import get_logger

logger = get_logger('reporter.html')

class HtmlReporter:
    def __init__(self, output_path: str):
        self.output_path = output_path

    def generate(self, findings: List[CorrelationResult]):
        logger.info(f"Generating HTML report with {len(findings)} findings...")
        
        html_content = f"""
        <html>
        <head>
            <title>DPFF Forensic Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #2c3e50; }}
                .incident {{ border: 1px solid #e74c3c; padding: 15px; margin-bottom: 20px; border-radius: 5px; }}
                .incident h3 {{ margin-top: 0; color: #c0392b; }}
                .severity {{ display: inline-block; padding: 2px 8px; border-radius: 3px; color: white; font-size: 12px; }}
                .severity-CRITICAL {{ background-color: #e74c3c; }}
                .severity-HIGH {{ background-color: #e67e22; }}
                .severity-MEDIUM {{ background-color: #f1c40f; color: #333; }}
                .severity-LOW {{ background-color: #27ae60; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .hash {{ font-family: monospace; font-size: 11px; color: #7f8c8d; }}
            </style>
        </head>
        <body>
            <h1>DPFF Forensic Investigation Report</h1>
            <p>Generated on: {datetime.now().isoformat()}</p>
            <h2>Findings ({len(findings)} Incidents Detected)</h2>
        """

        if not findings:
            html_content += "<p>No security incidents detected.</p>"

        for idx, finding in enumerate(findings, 1):
            html_content += f"""
            <div class="incident">
                <h3>Incident #{idx}: {finding.root_cause}</h3>
                <p><span class="severity severity-{finding.severity}">{finding.severity}</span></p>
                <h4>Evidence Timeline:</h4>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>Source</th>
                        <th>Event</th>
                        <th>Details</th>
                        <th>Evidence Hash</th>
                    </tr>
            """
            for event in finding.timeline:
                hash_display = event.evidence_hash[:16] + '...' if event.evidence_hash else 'N/A'
                html_content += f"""
                    <tr>
                        <td>{event.timestamp}</td>
                        <td>{event.source}</td>
                        <td>{event.event_type}</td>
                        <td>{event.details}</td>
                        <td class="hash">{hash_display}</td>
                    </tr>
                """
            html_content += """
                </table>
            </div>
            """

        html_content += """
        </body>
        </html>
        """

        with open(self.output_path, "w") as f:
            f.write(html_content)
        
        logger.info(f"Report generated at: {self.output_path}")

