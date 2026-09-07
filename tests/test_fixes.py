"""Unit tests verifying all applied bug fixes, security patches, and enhancements."""

import asyncio
import json
import re
import string
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from auditor.cli import parse_args
from auditor.exporter import export_html_results, export_sarif_results
from auditor.patterns import (
    AZURE_CONNECTION_STRING_PATTERN,
    OPENAI_KEY_PATTERN,
)
from auditor.rate_limiter import SEARCH_QUOTA, RateLimiter
from auditor.scoring import calculate_confidence_score
from auditor.tracker import ProgressTracker
from auditor.validator import validate_groq_key, validate_slack_key


def test_azure_connection_string_preserves_base64_padding():
    """Azure connection strings must match base64 padding '=' and '=='."""
    conn_single_pad = (
        "Endpoint=sb://test.servicebus.windows.net/;"
        "SharedAccessKeyName=RootManageSharedAccessKey;"
        "SharedAccessKey=0123456789ABCDEF0123456789ABCDEF0123456789A="
    )
    match = re.search(AZURE_CONNECTION_STRING_PATTERN, conn_single_pad)
    assert match is not None
    assert match.group(0).endswith("SharedAccessKey=0123456789ABCDEF0123456789ABCDEF0123456789A=")

    conn_double_pad = (
        "DefaultEndpointsProtocol=https;AccountName=testaccount;"
        "AccountKey=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345=="
    )
    match_double = re.search(AZURE_CONNECTION_STRING_PATTERN, conn_double_pad)
    assert match_double is not None
    assert match_double.group(0).endswith("AccountKey=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345==")


def test_openai_project_keys_with_hyphens_and_underscores():
    """OpenAI project keys containing hyphens and underscores must match."""
    proj_key = (
        "sk-proj-abc_def-12345678901234567890"
        "T3BlbkFJ"
        "xyz_987-12345678901234567890"
    )
    match = re.search(OPENAI_KEY_PATTERN, proj_key)
    assert match is not None
    assert match.group(0) == proj_key


def test_diversity_score_reaches_full_points():
    """Highly diverse secret strings should receive the full 10.0 diversity points and score high."""
    # A string with 48 distinct characters in context of api_key
    chars = string.ascii_letters + string.digits
    key = "sk-" + "".join(chars[:48])
    context = "export OPENAI_API_KEY=sk-abc authorization secret token api_key"
    score = calculate_confidence_score(key, context, is_noise=False)
    # Total score should easily reach CRITICAL (>80) and up to 100
    assert score >= 90.0


@pytest.mark.asyncio
async def test_rate_limiter_resets_on_expiry():
    """RateLimiter should restore SEARCH_QUOTA when reset_time has passed without deadlocking."""
    limiter = RateLimiter()
    # Force quota to 0 with reset_time in the past
    limiter._remaining = 0
    limiter._reset_time = time.time() - 1.0
    limiter._last_request_time = time.time() - 10.0

    # acquire should succeed promptly and restore tokens
    await asyncio.wait_for(limiter.acquire(), timeout=1.0)
    assert limiter._remaining == SEARCH_QUOTA - 1


def test_tracker_strips_raw_keys_on_resume(tmp_path):
    """Resuming from a checkpoint containing raw keys must strip them if store_raw_keys is False."""
    checkpoint = tmp_path / "progress.json"
    checkpoint.write_text(
        '{"processed": [], "found_keys": [{"key": "secret123", "key_hash": "hash123", "provider": "OpenAI"}], "timestamp": "2026-09-07T00:00:00Z"}',
        encoding="utf-8",
    )
    tracker = ProgressTracker(str(checkpoint), store_raw_keys=False)
    assert len(tracker.found_keys) == 1
    assert "key" not in tracker.found_keys[0]
    assert tracker.found_keys[0]["key_hash"] == "hash123"


def test_html_report_xss_protection(tmp_path):
    """HTML report template must escape double and single quotes to prevent DOM XSS."""
    tracker = MagicMock()
    tracker.found_keys = [
        {
            "provider": 'OpenAI" onmouseover="alert(1)"',
            "severity": "HIGH",
            "confidence": 95.0,
            "repo": 'repo" onclick="evil()',
            "path": 'dir/file.py" onerror="hack()',
            "key_masked": "sk-p...56",
            "key_hash": "hash123",
            "url": 'https://example.com/file.py" onfocus="alert(1)',
            "timestamp": "2026-09-07T00:00:00Z",
            "line": 42,
            "column": 5,
        }
    ]
    out_file = tmp_path / "report.html"
    export_html_results(tracker, str(out_file))
    html = out_file.read_text(encoding="utf-8")
    assert 'replace(/"/g,"&quot;")' in html
    assert "replace(/'/g,\"&#39;\")" in html


def test_sarif_export_line_numbers_and_uri_formatting(tmp_path):
    """SARIF export must populate startLine/startColumn and use forward-slash paths."""
    tracker = MagicMock()
    tracker.found_keys = [
        {
            "provider": "OpenAI",
            "severity": "CRITICAL",
            "confidence": 98.0,
            "repo": "local",
            "path": r"src\core\config.py",
            "url": r"file://C:\project\src\core\config.py",
            "key_masked": "sk-p...56",
            "key_hash": "hash123",
            "line": 42,
            "column": 15,
            "valid": True,
        }
    ]
    out_file = tmp_path / "report.sarif"
    export_sarif_results(tracker, str(out_file))
    data = json.loads(out_file.read_text(encoding="utf-8"))
    run = data["runs"][0]
    result = run["results"][0]
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    assert result["locations"][0]["physicalLocation"]["region"]["startColumn"] == 15
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/core/config.py"


@pytest.mark.asyncio
async def test_groq_validator_uses_openai_compatible_endpoint():
    """Groq validator must call https://api.groq.com/openai/v1/models."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.content_length = 500

    session = MagicMock()
    session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
    session.get.return_value.__aexit__ = AsyncMock(return_value=None)

    result = await validate_groq_key("gsk_" + "a" * 32, session=session)
    assert result is True
    session.get.assert_called_once()
    assert session.get.call_args[0][0] == "https://api.groq.com/openai/v1/models"


@pytest.mark.asyncio
async def test_slack_webhook_skips_auth_test():
    """Slack validator must return None for webhook URLs to avoid false invalidation."""
    webhook = "https://" + "hooks." + "slack.com/services/test/placeholder"
    result = await validate_slack_key(webhook)
    assert result is None


def test_cli_ci_gatekeeper_flags():
    """CLI should support --fail-on-findings and --fail-on-severity."""
    args = parse_args(["--fail-on-findings", "--fail-on-severity", "HIGH"])
    assert args.fail_on_findings is True
    assert args.fail_on_severity == "HIGH"


def test_cli_early_encryption_key_validation():
    """CLI should fail immediately on parse if --encrypt-output is used without an encryption key."""
    with pytest.raises(SystemExit):
        parse_args(["--encrypt-output"])
