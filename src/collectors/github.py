import os
import base64
from typing import List
from datetime import datetime
from src.collectors.base import BaseCollector
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger

logger = get_logger('collector.github')


class GitHubCollector(BaseCollector):
    def collect(self, lookback_days: int = 7) -> List[PipelineEvent]:
        events = []
        
        # Validate config
        section = self._validate_config('github', ['org'])
        if not section:
            return events

        org = section['org']
        base_url = section.get('base_url', 'https://api.github.com').rstrip('/')
        is_gitea = 'github.com' not in base_url

        # Auth: Gitea supports basic auth, GitHub uses token
        if is_gitea:
            gitea_user = os.getenv('GITEA_USER', 'dpff-admin')
            gitea_pass = os.getenv('GITEA_PASS', os.getenv('GITHUB_TOKEN', ''))
            if not gitea_pass:
                logger.warning("GITEA_PASS/GITHUB_TOKEN not set. Skipping Gitea collection.")
                self._collection_stats['errors'].append("GITEA_PASS/GITHUB_TOKEN not set")
                return events
            auth = (gitea_user, gitea_pass)
            headers = {'Accept': 'application/json'}
        else:
            token = os.getenv('GITHUB_TOKEN')
            if not token:
                logger.warning("GITHUB_TOKEN not set. Skipping GitHub collection.")
                self._collection_stats['errors'].append("GITHUB_TOKEN not set")
                return events
            auth = None
            headers = {
                'Authorization': f'token {token}',
                'Accept': 'application/vnd.github+json',
            }
        logger.info(f"Collecting GitHub audit logs for org '{org}' from {base_url}...")
        since = self.get_since_date(lookback_days)

        # Use different endpoints for GitHub vs Gitea
        if is_gitea:
            # Gitea: fetch org activity via repo events
            url = f'{base_url}/api/v1/orgs/{org}/repos'
            params = {'limit': 50}
        else:
            # GitHub: org audit-log (requires Enterprise)
            url = f'{base_url}/orgs/{org}/audit-log'
            params = {'phrase': f'created:>={since}', 'per_page': 100}

        resp = self._safe_request('GET', url, headers=headers, params=params, auth=auth)
        
        if resp is None:
            logger.warning("GitHub/Gitea API call failed after retries. Returning partial results.")
            return events

        try:
            data = resp.json()
            if not isinstance(data, list):
                logger.warning(f"Unexpected API response format: {type(data)}")
                data = []
        except ValueError as e:
            logger.error(f"Failed to parse API response: {e}")
            self._collection_stats['errors'].append(f"JSON parse error: {e}")
            return events

        if is_gitea:
            # Gitea: data is a list of repos — fetch commits from each
            for repo in data:
                repo_name = repo.get('full_name', repo.get('name', 'unknown'))
                commits_url = f'{base_url}/api/v1/repos/{repo_name}/commits'
                commits_resp = self._safe_request('GET', commits_url,
                    headers=headers, params={'limit': 20}, auth=auth)
                if commits_resp is None:
                    continue
                try:
                    commits = commits_resp.json()
                    if not isinstance(commits, list):
                        continue
                except ValueError:
                    continue

                for commit in commits:
                    try:
                        c = commit.get('commit', {})
                        author = c.get('author', {})
                        ts_str = author.get('date', '')
                        ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).replace(tzinfo=None) if ts_str else datetime.now()

                        # Get changed files from commit detail
                        files_str = ""
                        detail_url = f'{base_url}/api/v1/repos/{repo_name}/git/commits/{commit.get("sha", "")}'
                        detail_resp = self._safe_request('GET', detail_url, headers=headers, auth=auth)
                        if detail_resp and detail_resp.status_code == 200:
                            detail = detail_resp.json()
                            files = detail.get('files', [])
                            files_str = ', '.join(f.get('filename', '') for f in files[:5]) if files else ''

                            # Inspect content of sensitive files (RULE-003, RULE-002)
                            for f in files:
                                fname = f.get('filename', '')
                                if fname == 'package.json' or fname.endswith('.env'):
                                    # Fetch content
                                    content_url = f'{base_url}/api/v1/repos/{repo_name}/contents/{fname}?ref={commit.get("sha", "")}'
                                    content_resp = self._safe_request('GET', content_url, headers=headers, auth=auth)
                                    if content_resp and content_resp.status_code == 200:
                                        try:
                                            c_data = content_resp.json()
                                            decoded = base64.b64decode(c_data.get('content', '')).decode('utf-8')
                                            files_str += f"\n[Content of {fname}]:\n{decoded[:1000]}"
                                        except Exception:
                                            pass

                        events.append(PipelineEvent(
                            timestamp=ts,
                            source='GitHub',
                            event_type='git.push',
                            details=(
                                f"Actor: {author.get('name', 'unknown')}, "
                                f"Action: git.push, "
                                f"Repo: {repo_name}, "
                                f"Message: {c.get('message', '')[:100]}, "
                                f"Files: {files_str}"
                            ),
                        ))
                    except (KeyError, ValueError) as e:
                        logger.debug(f"Skipping malformed Gitea commit: {e}")
                        continue
        else:
            # GitHub: data is a list of audit-log entries
            for log_entry in data:
                try:
                    ts_str = log_entry.get('created_at', log_entry.get('@timestamp', ''))
                    ts = datetime.fromisoformat(ts_str.replace('Z', '+00:00')).replace(tzinfo=None) if ts_str else datetime.now()

                    events.append(PipelineEvent(
                        timestamp=ts,
                        source='GitHub',
                        event_type=log_entry.get('action', 'unknown'),
                        details=(
                            f"Actor: {log_entry.get('actor', 'unknown')}, "
                            f"Action: {log_entry.get('action', 'unknown')}, "
                            f"Repo: {log_entry.get('repo', 'unknown')}"
                        ),
                    ))
                except (KeyError, ValueError) as e:
                    logger.debug(f"Skipping malformed GitHub log entry: {e}")
                    continue

        logger.info(f"GitHub collection complete: {len(events)} events")
        return events
