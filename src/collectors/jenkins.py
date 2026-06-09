import os
from typing import List
from datetime import datetime
from src.collectors.base import BaseCollector
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger

logger = get_logger('collector.jenkins')


class JenkinsCollector(BaseCollector):
    def collect(self, lookback_days: int = 7) -> List[PipelineEvent]:
        events = []
        
        # Validate config
        section = self._validate_config('jenkins', ['url'])
        if not section:
            return events

        base_url = section['url'].rstrip('/')
        user = os.getenv('JENKINS_USER')
        token = os.getenv('JENKINS_TOKEN')
        
        if not user or not token:
            logger.warning("JENKINS_USER/TOKEN not set. Skipping Jenkins collection.")
            self._collection_stats['errors'].append("JENKINS_USER/TOKEN not set")
            return events

        logger.info(f"Collecting Jenkins build logs from {base_url}...")
        
        auth = (user, token)

        # Step 1: Fetch job list
        jobs_url = f'{base_url}/api/json'
        params = {'tree': 'jobs[name,url]'}
        
        resp = self._safe_request('GET', jobs_url, auth=auth, params=params)
        
        if resp is None:
            logger.warning("Jenkins API call failed after retries. Returning partial results.")
            return events

        try:
            jobs_data = resp.json()
            jobs = jobs_data.get('jobs', [])
        except ValueError as e:
            logger.error(f"Failed to parse Jenkins jobs response: {e}")
            self._collection_stats['errors'].append(f"JSON parse error: {e}")
            return events

        logger.info(f"Found {len(jobs)} Jenkins jobs")

        # Step 2: Fetch recent builds for each job
        for job in jobs[:20]:  # Limit to 20 jobs for safety
            job_name = job.get('name', 'unknown')
            builds_url = f"{base_url}/job/{job_name}/api/json"
            builds_params = {'tree': 'builds[number,timestamp,result,url]{0,10}'}
            
            builds_resp = self._safe_request('GET', builds_url, auth=auth, params=builds_params)
            
            if builds_resp is None:
                logger.debug(f"Failed to fetch builds for job '{job_name}'. Continuing...")
                continue  # Graceful degradation — skip this job, continue others

            try:
                builds_data = builds_resp.json()
                builds = builds_data.get('builds', [])
            except ValueError:
                logger.debug(f"Failed to parse builds for job '{job_name}'. Skipping.")
                continue

            for build in builds:
                try:
                    ts = datetime.fromtimestamp(build['timestamp'] / 1000)
                    events.append(PipelineEvent(
                        timestamp=ts,
                        source='Jenkins',
                        event_type='Build',
                        details=(
                            f"Job: {job_name}, Build: #{build.get('number', '?')}, "
                            f"Result: {build.get('result', 'UNKNOWN')}"
                        ),
                    ))
                except (KeyError, ValueError, TypeError) as e:
                    logger.debug(f"Skipping malformed Jenkins build entry: {e}")
                    continue

            # Step 3: Fetch console log for the latest build (for injection detection)
            if builds:
                latest = builds[0]
                console_url = f"{base_url}/job/{job_name}/{latest.get('number', 1)}/consoleText"
                console_resp = self._safe_request('GET', console_url, auth=auth)
                
                if console_resp and console_resp.text:
                    # Scan for suspicious commands in build logs
                    for line_num, line in enumerate(console_resp.text.split('\n'), 1):
                        if any(kw in line.lower() for kw in ['curl', 'wget', 'base64', 'nc ', 'eval']):
                            events.append(PipelineEvent(
                                timestamp=ts,
                                source='Jenkins',
                                event_type='Step Execution',
                                details=f"Job: {job_name}, Line {line_num}: {line.strip()[:200]}",
                            ))

        logger.info(f"Jenkins collection complete: {len(events)} events")
        return events
