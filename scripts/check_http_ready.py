#!/usr/bin/env python3
"""Quiet readiness probe: a starting/unavailable service is a retryable result."""
import argparse
import urllib.error
import urllib.request


def ready(url):
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return response.status == 200
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8080/healthz')
    args = parser.parse_args()
    raise SystemExit(0 if ready(args.url) else 1)
