import os
from typing import List
from datetime import datetime, timezone
from src.collectors.base import BaseCollector
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger

logger = get_logger('collector.kubernetes')


class KubernetesCollector(BaseCollector):
    def collect(self, lookback_days: int = 7) -> List[PipelineEvent]:
        events = []
        
        # Validate config
        section = self._validate_config('kubernetes', [])
        if section is None:
            return events

        logger.info("Collecting Kubernetes events...")
        
        # Step 1: Try importing kubernetes library
        try:
            from kubernetes import client, config as k8s_config
        except ImportError:
            logger.warning(
                "'kubernetes' python package not installed. "
                "Install with: pip install kubernetes"
            )
            self._collection_stats['errors'].append("kubernetes package not installed")
            return events

        # Step 2: Load kube config with specific error handling
        try:
            k8s_config.load_kube_config()
            logger.debug("Loaded kubeconfig from default location")
        except Exception as e_local:
            logger.debug(f"Local kubeconfig failed: {e_local}")
            try:
                k8s_config.load_incluster_config()
                logger.debug("Loaded in-cluster kubeconfig")
            except Exception as e_cluster:
                logger.warning(
                    f"Could not load kubeconfig. "
                    f"Local: {e_local}, In-cluster: {e_cluster}. "
                    f"Skipping K8s collection."
                )
                self._collection_stats['errors'].append("kubeconfig not available")
                return events

        # Step 3: Fetch events with specific exception handling
        try:
            v1 = client.CoreV1Api()
            logger.debug("API Call: list_event_for_all_namespaces")
            
            k8s_events = v1.list_event_for_all_namespaces(limit=500)
            
            for item in k8s_events.items:
                try:
                    ts = item.last_timestamp or item.event_time or datetime.now(tz=timezone.utc)
                    
                    # Extract security-relevant details
                    details = f"{item.message or 'No message'}"
                    
                    # Check for privileged containers in involved objects
                    if item.involved_object and item.involved_object.kind == 'Pod':
                        # Flag pods with common security concerns
                        if any(kw in (item.message or '').lower() for kw in 
                               ['privileged', 'hostnetwork', 'hostpid', 'cap_sys_admin']):
                            details += " [PRIVILEGED]"
                    
                    events.append(PipelineEvent(
                        timestamp=ts,
                        source='Kubernetes',
                        event_type=item.reason or 'Unknown',
                        details=details,
                    ))
                except (AttributeError, TypeError) as e:
                    logger.debug(f"Skipping malformed K8s event: {e}")
                    continue

        except Exception as e:
            error_type = type(e).__name__
            if 'Unauthorized' in str(e) or '401' in str(e):
                logger.error(f"K8s authentication failed: {e}")
                self._collection_stats['errors'].append(f"Auth failed: {error_type}")
            elif 'Forbidden' in str(e) or '403' in str(e):
                logger.error(f"K8s permission denied — check RBAC: {e}")
                self._collection_stats['errors'].append(f"RBAC denied: {error_type}")
            elif 'Connection' in error_type or 'timeout' in str(e).lower():
                logger.error(f"K8s API connection failed: {e}")
                self._collection_stats['errors'].append(f"Connection failed: {error_type}")
            else:
                logger.error(f"Error collecting Kubernetes events ({error_type}): {e}")
                self._collection_stats['errors'].append(f"{error_type}: {e}")

        logger.info(f"Kubernetes collection complete: {len(events)} events")
        return events
