"""Tests for the probe SSRF/metadata target guard."""
from __future__ import annotations

import pytest

from app.core.target_guard import check_probe_target


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254:80/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata/",
    "http://100.100.100.200/",
])
def test_metadata_and_link_local_always_blocked(url):
    allowed, reason = check_probe_target(url)
    assert allowed is False
    assert reason


@pytest.mark.parametrize("url", [
    "http://localhost:8003",
    "http://127.0.0.1:8003",
    "http://10.0.0.5:8080",
    "http://192.168.1.10",
    "http://172.16.0.9",
])
def test_private_allowed_by_default_for_in_vpc(url):
    allowed, _ = check_probe_target(url, block_private=False)
    assert allowed is True


@pytest.mark.parametrize("url", [
    "http://localhost:8003",
    "http://127.0.0.1:8003",
    "http://10.0.0.5:8080",
    "http://192.168.1.10",
])
def test_private_blocked_when_opted_in(url):
    allowed, reason = check_probe_target(url, block_private=True)
    assert allowed is False
    assert reason


def test_external_targets_allowed():
    allowed, reason = check_probe_target("https://mcp.example.com/rpc")
    assert allowed is True
    assert reason == ""


def test_missing_host_rejected():
    allowed, reason = check_probe_target("not-a-url")
    assert allowed is False
