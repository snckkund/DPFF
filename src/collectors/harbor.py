import os
from typing import List
from datetime import datetime
from src.collectors.base import BaseCollector
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger

logger = get_logger('collector.harbor')


class HarborCollector(BaseCollector):
    def collect(self, lookback_days: int = 7) -> List[PipelineEvent]:
        events = []
        
        # Validate config
        section = self._validate_config('harbor', ['url'])
        if not section:
            return events

        base_url = section['url'].rstrip('/')
        user = os.getenv('HARBOR_USER')
        password = os.getenv('HARBOR_PASS')
        
        if not user or not password:
            logger.warning("HARBOR_USER/PASS not set. Skipping Harbor collection.")
            self._collection_stats['errors'].append("HARBOR_USER/PASS not set")
            return events

        logger.info(f"Collecting Harbor audit logs from {base_url}...")
        
        auth = (user, password)

        # Step 1: List projects
        projects_url = f'{base_url}/api/v2.0/projects'
        resp = self._safe_request('GET', projects_url, auth=auth, params={'page_size': 50})
        
        if resp is None:
            logger.warning("Harbor API call failed after retries. Returning partial results.")
            return events

        try:
            projects = resp.json()
            if not isinstance(projects, list):
                projects = []
        except ValueError as e:
            logger.error(f"Failed to parse Harbor projects response: {e}")
            self._collection_stats['errors'].append(f"JSON parse error: {e}")
            return events

        logger.info(f"Found {len(projects)} Harbor projects")

        # Step 2: Fetch audit logs for each project
        for project in projects[:10]:  # Limit for safety
            project_name = project.get('name', 'unknown')
            logs_url = f'{base_url}/api/v2.0/audit-logs'
            params = {
                'q': f'resource_type=artifact,project_name={project_name}',
                'page_size': 100,
            }
            
            logs_resp = self._safe_request('GET', logs_url, auth=auth, params=params)
            
            if logs_resp is None:
                logger.debug(f"Failed to fetch logs for project '{project_name}'. Continuing...")
                continue  # Graceful degradation

            try:
                logs = logs_resp.json()
                if not isinstance(logs, list):
                    logs = []
            except ValueError:
                logger.debug(f"Failed to parse logs for project '{project_name}'. Skipping.")
                continue

            for log_entry in logs:
                try:
                    ts_str = log_entry.get('op_time', '')
                    ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')) if ts_str else datetime.now()
                    
                    events.append(PipelineEvent(
                        timestamp=ts,
                        source='Harbor',
                        event_type=f"Image {log_entry.get('operation', 'unknown').capitalize()}",
                        details=(
                            f"User: {log_entry.get('username', 'unknown')}, "
                            f"Resource: {log_entry.get('resource', 'unknown')}, "
                            f"Digest: {log_entry.get('digest', 'N/A')}"
                        ),
                    ))
                except (KeyError, ValueError) as e:
                    logger.debug(f"Skipping malformed Harbor log entry: {e}")
                    continue

        logger.info(f"Harbor collection complete: {len(events)} events")
        return events
