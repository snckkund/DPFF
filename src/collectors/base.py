import time
import requests
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger
from src.integrity import hash_events

logger = get_logger('collector')


class CollectorError(Exception):
    """Raised when a collector encounters a non-recoverable error."""
    pass


class BaseCollector(ABC):
    """
    Abstract Base Class for all Log Collectors.
    
    Provides:
    - _safe_request(): HTTP requests with retries, timeouts, rate-limit handling
    - _validate_config(): Config key validation
    - collect_and_hash(): Auto-hashing wrapper
    - Collection metadata tracking
    """
    
    MAX_RETRIES = 3
    RETRY_BACKOFF = [1, 2, 4]  # seconds between retries
    DEFAULT_TIMEOUT = 30  # seconds
    
    def __init__(self, config: dict):
        self.config = config
        self._collection_stats: Dict[str, Any] = {
            'events_collected': 0,
            'api_calls': 0,
            'errors': [],
            'start_time': None,
            'duration_seconds': 0.0,
        }

    @abstractmethod
    def collect(self, lookback_days: int = 7) -> List[PipelineEvent]:
        """
        Collect logs from the source for the past N days 
        and return them as normalized PipelineEvents.
        """
        pass
    
    def collect_and_hash(self, lookback_days: int = 7) -> List[PipelineEvent]:
        """Collect events and automatically hash them for integrity."""
        self._collection_stats['start_time'] = time.time()
        events = self.collect(lookback_days)
        if events:
            hash_events(events)
        self._collection_stats['events_collected'] = len(events)
        self._collection_stats['duration_seconds'] = time.time() - self._collection_stats['start_time']
        return events
    
    def get_since_date(self, lookback_days: int) -> str:
        """Helper to get ISO date string for lookback"""
        return (datetime.now() - timedelta(days=lookback_days)).isoformat()

    def _validate_config(self, section: str, required_keys: List[str]) -> Optional[dict]:
        """
        Validate that a config section exists and has all required keys.
        Returns the section dict if valid, None otherwise.
        """
        section_config = self.config.get(section, {})
        if not section_config:
            logger.debug(f"Config section '{section}' not found or empty. Skipping.")
            return None
        
        if not section_config.get('enabled', False):
            logger.debug(f"Collector '{section}' is disabled in config.")
            return None
        
        missing = [k for k in required_keys if k not in section_config]
        if missing:
            logger.warning(
                f"Config section '{section}' missing required keys: {missing}. Skipping."
            )
            self._collection_stats['errors'].append(f"Missing config keys: {missing}")
            return None
        
        return section_config

    def _safe_request(
        self,
        method: str,
        url: str,
        headers: Optional[dict] = None,
        auth: Optional[tuple] = None,
        params: Optional[dict] = None,
        timeout: Optional[int] = None,
    ) -> Optional[requests.Response]:
        """
        Make an HTTP request with retries, timeouts, and rate-limit handling.
        
        - 3 retries with exponential backoff (1s, 2s, 4s)
        - Configurable timeout (default 30s)
        - HTTP 429 rate-limit handling (respects Retry-After header)
        - Specific exception handling for ConnectionError, Timeout, HTTPError
        
        Returns the Response object on success, None on failure.
        """
        timeout = timeout or self.DEFAULT_TIMEOUT
        last_error = None
        
        for attempt in range(self.MAX_RETRIES):
            self._collection_stats['api_calls'] += 1
            try:
                logger.debug(f"API {method.upper()} {url} (attempt {attempt + 1}/{self.MAX_RETRIES})")
                
                resp = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    auth=auth,
                    params=params,
                    timeout=timeout,
                )
                
                # Handle rate limiting
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get('Retry-After', self.RETRY_BACKOFF[attempt]))
                    logger.warning(
                        f"Rate limited (429) on {url}. Waiting {retry_after}s..."
                    )
                    time.sleep(retry_after)
                    continue
                
                # Handle server errors (5xx) with retry
                if resp.status_code >= 500:
                    logger.warning(
                        f"Server error ({resp.status_code}) on {url}. "
                        f"Retrying in {self.RETRY_BACKOFF[attempt]}s..."
                    )
                    time.sleep(self.RETRY_BACKOFF[attempt])
                    continue
                
                # Raise for client errors (4xx)
                resp.raise_for_status()
                return resp
                
            except requests.exceptions.ConnectionError as e:
                last_error = f"Connection failed: {url} — {e}"
                logger.warning(f"{last_error} (attempt {attempt + 1})")
                
            except requests.exceptions.Timeout as e:
                last_error = f"Request timed out after {timeout}s: {url}"
                logger.warning(f"{last_error} (attempt {attempt + 1})")
                
            except requests.exceptions.HTTPError as e:
                last_error = f"HTTP error {resp.status_code}: {url} — {e}"
                logger.error(last_error)
                self._collection_stats['errors'].append(last_error)
                return None  # Don't retry on 4xx client errors
                
            except requests.exceptions.RequestException as e:
                last_error = f"Request failed: {url} — {e}"
                logger.warning(f"{last_error} (attempt {attempt + 1})")
            
            # Backoff before retry
            if attempt < self.MAX_RETRIES - 1:
                time.sleep(self.RETRY_BACKOFF[attempt])
        
        # All retries exhausted
        logger.error(f"All {self.MAX_RETRIES} attempts failed for {url}: {last_error}")
        self._collection_stats['errors'].append(last_error or f"Failed after {self.MAX_RETRIES} retries")
        return None

    @property
    def stats(self) -> Dict[str, Any]:
        """Return collection statistics."""
        return self._collection_stats.copy()
