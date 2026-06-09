"""Tests for collector base class: config validation, _safe_request, and stats."""
import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.collectors.base import BaseCollector
from src.correlation_engine.models import PipelineEvent
from datetime import datetime, timezone


class ConcreteCollector(BaseCollector):
    """Concrete implementation for testing the abstract base class."""
    def collect(self, lookback_days=7):
        return []


class TestConfigValidation(unittest.TestCase):

    def test_valid_config(self):
        c = ConcreteCollector({'github': {'enabled': True, 'org': 'myorg'}})
        result = c._validate_config('github', ['org'])
        self.assertIsNotNone(result)
        self.assertEqual(result['org'], 'myorg')

    def test_missing_section(self):
        c = ConcreteCollector({})
        result = c._validate_config('github', ['org'])
        self.assertIsNone(result)

    def test_disabled_section(self):
        c = ConcreteCollector({'github': {'enabled': False, 'org': 'myorg'}})
        result = c._validate_config('github', ['org'])
        self.assertIsNone(result)

    def test_missing_required_keys(self):
        c = ConcreteCollector({'github': {'enabled': True}})
        result = c._validate_config('github', ['org', 'token'])
        self.assertIsNone(result)
        self.assertTrue(len(c._collection_stats['errors']) > 0)

    def test_empty_required_keys(self):
        c = ConcreteCollector({'kubernetes': {'enabled': True}})
        result = c._validate_config('kubernetes', [])
        self.assertIsNotNone(result)


class TestSafeRequest(unittest.TestCase):

    @patch('src.collectors.base.requests.request')
    def test_successful_request(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_req.return_value = mock_resp

        c = ConcreteCollector({})
        result = c._safe_request('GET', 'http://example.com/api')
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(c._collection_stats['api_calls'], 1)

    @patch('src.collectors.base.requests.request')
    def test_retries_on_connection_error(self, mock_req):
        import requests as req_lib
        mock_req.side_effect = req_lib.exceptions.ConnectionError("Connection refused")

        c = ConcreteCollector({})
        # Patch time.sleep to speed up test
        with patch('src.collectors.base.time.sleep'):
            result = c._safe_request('GET', 'http://example.com/api')
        
        self.assertIsNone(result)
        self.assertEqual(c._collection_stats['api_calls'], 3)  # 3 retries
        self.assertTrue(len(c._collection_stats['errors']) > 0)

    @patch('src.collectors.base.requests.request')
    def test_retries_on_timeout(self, mock_req):
        import requests as req_lib
        mock_req.side_effect = req_lib.exceptions.Timeout("Request timed out")

        c = ConcreteCollector({})
        with patch('src.collectors.base.time.sleep'):
            result = c._safe_request('GET', 'http://example.com/api')
        
        self.assertIsNone(result)
        self.assertEqual(c._collection_stats['api_calls'], 3)

    @patch('src.collectors.base.requests.request')
    def test_no_retry_on_client_error(self, mock_req):
        import requests as req_lib
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.raise_for_status.side_effect = req_lib.exceptions.HTTPError("Forbidden")
        mock_req.return_value = mock_resp

        c = ConcreteCollector({})
        result = c._safe_request('GET', 'http://example.com/api')
        self.assertIsNone(result)
        self.assertEqual(c._collection_stats['api_calls'], 1)  # No retries for 4xx

    @patch('src.collectors.base.requests.request')
    def test_handles_rate_limiting(self, mock_req):
        rate_resp = MagicMock()
        rate_resp.status_code = 429
        rate_resp.headers = {'Retry-After': '1'}

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()

        mock_req.side_effect = [rate_resp, ok_resp]

        c = ConcreteCollector({})
        with patch('src.collectors.base.time.sleep'):
            result = c._safe_request('GET', 'http://example.com/api')
        
        self.assertIsNotNone(result)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(c._collection_stats['api_calls'], 2)

    @patch('src.collectors.base.requests.request')
    def test_retries_on_server_error(self, mock_req):
        error_resp = MagicMock()
        error_resp.status_code = 500

        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()

        mock_req.side_effect = [error_resp, ok_resp]

        c = ConcreteCollector({})
        with patch('src.collectors.base.time.sleep'):
            result = c._safe_request('GET', 'http://example.com/api')
        
        self.assertIsNotNone(result)
        self.assertEqual(c._collection_stats['api_calls'], 2)


class TestCollectionStats(unittest.TestCase):

    def test_initial_stats(self):
        c = ConcreteCollector({})
        stats = c.stats
        self.assertEqual(stats['events_collected'], 0)
        self.assertEqual(stats['api_calls'], 0)
        self.assertEqual(stats['errors'], [])

    def test_collect_and_hash(self):
        c = ConcreteCollector({})
        events = c.collect_and_hash()
        stats = c.stats
        self.assertEqual(stats['events_collected'], 0)
        self.assertGreaterEqual(stats['duration_seconds'], 0)


class TestGetSinceDate(unittest.TestCase):

    def test_returns_iso_string(self):
        c = ConcreteCollector({})
        result = c.get_since_date(7)
        self.assertIsInstance(result, str)
        # Should be parseable as ISO datetime
        datetime.fromisoformat(result)


if __name__ == '__main__':
    unittest.main()
