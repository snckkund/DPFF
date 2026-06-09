import os
from typing import List
from datetime import datetime, timezone, timedelta
from src.collectors.base import BaseCollector
from src.correlation_engine.models import PipelineEvent
from src.forensic_logger import get_logger

logger = get_logger('collector.docker')


class DockerCollector(BaseCollector):
    def collect(self, lookback_days: int = 7) -> List[PipelineEvent]:
        events = []
        
        # Validate config
        section = self._validate_config('docker', [])
        if section is None:
            return events

        logger.info("Collecting Docker events...")
        
        # Step 1: Try importing docker library
        try:
            import docker
        except ImportError:
            logger.warning(
                "'docker' python package not installed. "
                "Install with: pip install docker"
            )
            self._collection_stats['errors'].append("docker package not installed")
            return events

        # Step 2: Connect to Docker daemon with specific error handling
        try:
            docker_client = docker.from_env()
        except docker.errors.DockerException as e:
            logger.warning(f"Could not connect to Docker daemon: {e}")
            self._collection_stats['errors'].append(f"Docker daemon unavailable: {e}")
            return events
        except Exception as e:
            logger.warning(f"Unexpected error connecting to Docker: {type(e).__name__}: {e}")
            self._collection_stats['errors'].append(f"Docker connection error: {e}")
            return events

        # Step 3: Verify connection
        try:
            docker_client.ping()
            logger.debug("Docker daemon is responsive")
        except Exception as e:
            logger.warning(f"Docker daemon not responding to ping: {e}")
            self._collection_stats['errors'].append(f"Docker ping failed: {e}")
            return events

        # Step 4: Fetch events with time filtering
        try:
            since_dt = datetime.now(tz=timezone.utc) - timedelta(days=lookback_days)
            
            logger.debug(f"Fetching Docker events since {since_dt.isoformat()}")
            
            # 4a. Real-time Docker Events (push, pull, commit, etc.)
            try:
                until_dt = datetime.now(tz=timezone.utc)
                for event in docker_client.events(since=since_dt, until=until_dt, decode=True):
                    try:
                        # Filter for relevant events
                        e_type = event.get('Type')
                        action = event.get('Action')
                        
                        if e_type not in ('image', 'container'):
                            continue
                            
                        # Skip noise
                        if action in ('top', 'resize', 'exec_create', 'exec_start'):
                            continue

                        # Extract timestamp
                        ts_nano = event.get('timeNano')
                        if ts_nano:
                            ts = datetime.fromtimestamp(ts_nano / 1e9, tz=timezone.utc).replace(tzinfo=None)
                        else:
                            ts = datetime.fromtimestamp(event.get('time', 0), tz=timezone.utc).replace(tzinfo=None)

                        actor = event.get('Actor', {})
                        attrs = actor.get('Attributes', {})
                        name = attrs.get('name', actor.get('ID', 'unknown'))  # e.g. image tag or container name
                        
                        details = f"Type: {e_type}, Action: {action}, ID: {actor.get('ID', '')[:12]}"
                        
                        if name:
                            details += f", Name: {name}"
                        
                        # For pushes, try to capture tag specifically for correlation
                        # The 'name' attribute in image events often contains the tag
                        if e_type == 'image' and action == 'push':
                            details += f", Tag: {name}"

                        events.append(PipelineEvent(
                            timestamp=ts,
                            source='Docker',
                            event_type=f"{e_type.capitalize()} {action}",
                            details=details,
                        ))

                    except Exception as e:
                        logger.debug(f"Error parsing docker event: {e}")
                        continue
            except Exception as e:
                 logger.warning(f"Failed to stream docker events: {e}")

            # 4b. Static Container Analysis (Privileged check)
            containers = docker_client.containers.list(all=True, limit=100)
            
            for container in containers:
                try:
                    # Check container security posture
                    details = f"Container: {container.name}, Image: {container.image.tags[0] if container.image.tags else 'untagged'}, Status: {container.status}"
                    
                    # Inspect for privileged mode
                    inspect = container.attrs
                    host_config = inspect.get('HostConfig', {})
                    
                    security_flags = []
                    if host_config.get('Privileged'):
                        security_flags.append('privileged=true')
                    if host_config.get('NetworkMode') == 'host':
                        security_flags.append('hostNetwork=true')
                    if host_config.get('PidMode') == 'host':
                        security_flags.append('hostPID=true')
                    
                    cap_add = host_config.get('CapAdd') or []
                    if 'SYS_ADMIN' in cap_add or 'ALL' in cap_add:
                        security_flags.append('CAP_SYS_ADMIN')
                    
                    if security_flags:
                        details += f" [PRIVILEGED: {', '.join(security_flags)}]"
                    
                    # Use naive datetime for consistency
                    created = container.attrs.get('Created', '')
                    if created:
                        ts = datetime.fromisoformat(created.split('.')[0].replace('Z', '+00:00')).replace(tzinfo=None)
                    else:
                        ts = datetime.now()
                    
                    events.append(PipelineEvent(
                        timestamp=ts,
                        source='Docker',
                        event_type='Container Audit',
                        details=details,
                    ))
                except (AttributeError, KeyError, TypeError, IndexError) as e:
                    logger.debug(f"Skipping container analysis: {e}")
                    continue

        except Exception as e:
            error_type = type(e).__name__
            if 'APIError' in error_type:
                logger.error(f"Docker API error: {e}")
            elif 'NotFound' in error_type:
                logger.warning(f"Docker resource not found: {e}")
            else:
                logger.error(f"Error collecting Docker events ({error_type}): {e}")
            self._collection_stats['errors'].append(f"{error_type}: {e}")

        logger.info(f"Docker collection complete: {len(events)} events")
        return events
