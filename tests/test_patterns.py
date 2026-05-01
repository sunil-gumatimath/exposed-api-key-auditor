import argparse
import re

from auditor import (
    ANTHROPIC_KEY_PATTERN,
    APIAuditor,
    GOOGLE_AI_KEY_PATTERN,
    OPENAI_KEY_PATTERN,
    ProgressTracker,
    RateLimiter,
    fingerprint_key,
    mask_key,
    calculate_confidence_score,
    get_severity_level,
    AWS_ACCESS_KEY_PATTERN,
    STRIPE_KEY_PATTERN,
    GITHUB_TOKEN_PATTERN,
    SLACK_TOKEN_PATTERN,
    TWILIO_API_KEY_PATTERN,
    SENDGRID_API_KEY_PATTERN,
    HUGGINGFACE_KEY_PATTERN,
    CLOUDFLARE_TOKEN_PATTERN,
    SUPABASE_KEY_PATTERN,
    AZURE_CONNECTION_STRING_PATTERN,
)


def _build_args(**overrides):
    base = {
        "max_concurrency": 2,
        "allow_patterns": [],
        "deny_patterns": [],
        "since_checkpoint": False,
        "sort": "indexed",
        "min_stars": None,
        "language": None,
        "updated_after": None,
        "max_pages": 1,
        "dry_run": True,
        "validate": False,
        "store_raw_keys": False,
        "checkpoint_interval": 5,
        "timeout": 5,
        "confidence_threshold": 50.0,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def test_valid_anthropic_key():
    key = "sk-ant-api03-" + "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNO"
    matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
    assert len(matches) == 1


def test_invalid_anthropic_key():
    invalid_keys = [
        "sk-ant-short",
        "sk-ant",
        "random-string",
    ]
    for key in invalid_keys:
        matches = re.findall(ANTHROPIC_KEY_PATTERN, key)
        assert len(matches) == 0


def test_valid_openai_formats():
    classic = "sk-" + "a" * 48
    proj = "sk-proj-abcdefghijklmnopqrstuvwxyz"
    live = "sk-live-abcdefghijklmnopqrstuvwxyz"
    assert len(re.findall(OPENAI_KEY_PATTERN, classic)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, proj)) == 1
    assert len(re.findall(OPENAI_KEY_PATTERN, live)) == 1


def test_invalid_openai_key():
    invalid_keys = ["sk-short", "not-a-key"]
    for key in invalid_keys:
        assert len(re.findall(OPENAI_KEY_PATTERN, key)) == 0


def test_valid_google_key():
    key = "AIza" + "a" * 35
    assert len(re.findall(GOOGLE_AI_KEY_PATTERN, key)) == 1


def test_valid_aws_key():
    key = "AKIA" + "A" * 12
    assert len(re.findall(AWS_ACCESS_KEY_PATTERN, key)) == 1


def test_invalid_aws_key():
    invalid_keys = ["AKIA", "AKIAshort", "NOTAKIA123456789012"]
    for key in invalid_keys:
        assert len(re.findall(AWS_ACCESS_KEY_PATTERN, key)) == 0


def test_valid_stripe_key():
    live_key = "sk_" + "live_abcdefghijklmnopqrstuvwxyz"
    test_key = "sk_" + "test_1234567890abcdefghijklmn"
    assert len(re.findall(STRIPE_KEY_PATTERN, live_key)) == 1
    assert len(re.findall(STRIPE_KEY_PATTERN, test_key)) == 1


def test_valid_github_token():
    tokens = ["ghp_" + "a" * 36, "gho_" + "b" * 36, "ghs_" + "c" * 36]
    for token in tokens:
        assert len(re.findall(GITHUB_TOKEN_PATTERN, token)) == 1


def test_valid_slack_token():
    token = "xoxb" + "-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
    assert len(re.findall(SLACK_TOKEN_PATTERN, token)) == 1


def test_valid_twilio_key():
    key = "SK" + "a" * 32
    assert len(re.findall(TWILIO_API_KEY_PATTERN, key)) == 1


def test_valid_sendgrid_key():
    key = "SG." + "a" * 22 + "." + "b" * 43
    assert len(re.findall(SENDGRID_API_KEY_PATTERN, key)) == 1


def test_mask_and_fingerprint():
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456"
    masked = mask_key(key)
    assert masked.startswith("sk-proj-")
    assert masked.endswith("3456")
    fp = fingerprint_key(key)
    assert len(fp) == 64


def test_noise_filter_rejects_placeholder_context(tmp_path):
    args = _build_args()
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    assert auditor.is_probable_secret(key, context) is False


def test_allow_pattern_overrides_noise(tmp_path):
    args = _build_args(allow_patterns=[r"OPENAI_API_KEY"], deny_patterns=[])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "a" * 48
    context = f"OPENAI_API_KEY={key} # example placeholder"
    assert auditor.is_probable_secret(key, context) is True


def test_deny_pattern_blocks(tmp_path):
    args = _build_args(deny_patterns=[r"DO_NOT_USE"])
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "A1" * 24
    context = f"DO_NOT_USE={key}"
    assert auditor.is_probable_secret(key, context) is False


def test_confidence_scoring_high_entropy():
    # High entropy key with good context should score high
    key = "sk-" + "".join(chr(65 + (i * 13) % 52) for i in range(48))
    context = "api_key=secret production token authorization"
    is_noise = False
    score = calculate_confidence_score(key, context, is_noise)
    assert score > 60.0, f"Expected score > 60, got {score}"


def test_confidence_scoring_low_entropy():
    key = "aaaaaaaa"
    context = "test key"
    is_noise = False
    score = calculate_confidence_score(key, context, is_noise)
    assert score < 40.0


def test_confidence_scoring_noise_penalty():
    key = "sk-" + "a" * 48
    context = "example placeholder dummy test"
    is_noise = True
    score = calculate_confidence_score(key, context, is_noise)
    assert score < 50.0


def test_severity_levels():
    assert get_severity_level(90.0) == "CRITICAL"
    assert get_severity_level(70.0) == "HIGH"
    assert get_severity_level(50.0) == "MEDIUM"
    assert get_severity_level(30.0) == "LOW"


def test_confidence_threshold_filtering(tmp_path):
    args = _build_args(confidence_threshold=80.0)
    tracker = ProgressTracker(checkpoint_file=str(tmp_path / "progress.json"), store_raw_keys=False)
    auditor = APIAuditor("fake-token", RateLimiter(), tracker, args)
    key = "sk-" + "".join(chr(65 + (i * 13) % 52) for i in range(48))
    context = "api_key=secret production token authorization"
    # High confidence key should pass with low threshold
    args2 = _build_args(confidence_threshold=20.0)
    tracker2 = ProgressTracker(checkpoint_file=str(tmp_path / "progress2.json"), store_raw_keys=False)
    auditor2 = APIAuditor("fake-token", RateLimiter(), tracker2, args2)
    # Same key should pass with low threshold
    assert auditor2.is_probable_secret(key, context) is True
    # But should fail with high threshold if score < 80
    score = calculate_confidence_score(key, context, False)
    if score < 80:
        assert auditor.is_probable_secret(key, context) is False


def test_valid_huggingface_key():
    key = "hf_" + "a" * 34
    assert len(re.findall(HUGGINGFACE_KEY_PATTERN, key)) == 1

def test_valid_cloudflare_token():
    key = "A" * 40
    assert len(re.findall(CLOUDFLARE_TOKEN_PATTERN, key)) == 1

def test_valid_supabase_key():
    key = "sbp_" + "b" * 36
    assert len(re.findall(SUPABASE_KEY_PATTERN, key)) == 1

def test_valid_azure_connection_string():
    key = "Endpoint=sb://my-namespace.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=ABCDEF12345+/="
    assert len(re.findall(AZURE_CONNECTION_STRING_PATTERN, key)) == 1


def test_local_scan_logic():
    # Simple check that the directory walk logic would run
    # This just verifies the logic structure is accessible
    import os
    from auditor import APIAuditor, RateLimiter, ProgressTracker
    import argparse
    
    args = argparse.Namespace(max_concurrency=1)
    tracker = ProgressTracker(checkpoint_file="temp_progress.json", store_raw_keys=False)
    auditor = APIAuditor("fake", RateLimiter(), tracker, args)
    
    # We verify the method exists and can be called
    assert hasattr(auditor, "scan_local_directory")
