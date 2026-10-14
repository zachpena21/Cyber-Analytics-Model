import io
from contextlib import redirect_stderr
from unittest.mock import MagicMock, patch
import unittest
import urllib.error

from check_http_ready import ready


class ReadyTests(unittest.TestCase):
    def test_startup_connection_failure_is_quiet_and_retry_can_succeed(self):
        response = MagicMock(); response.__enter__.return_value.status = 200
        errors = io.StringIO()
        with patch('urllib.request.urlopen', side_effect=[urllib.error.URLError('refused'), response]), redirect_stderr(errors):
            self.assertFalse(ready('http://local/healthz'))
            self.assertTrue(ready('http://local/healthz'))
        self.assertEqual(errors.getvalue(), '')

    def test_timeout_and_http_failure_do_not_report_ready(self):
        for error in [TimeoutError(), urllib.error.HTTPError('http://local', 503, 'starting', {}, None)]:
            with patch('urllib.request.urlopen', side_effect=error):
                self.assertFalse(ready('http://local/healthz'))


if __name__ == '__main__':
    unittest.main()
