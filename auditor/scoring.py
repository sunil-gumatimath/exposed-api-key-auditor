"""Confidence scoring, entropy calculation, key masking / fingerprinting."""

import hashlib
import math
import re


def shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random)."""
    if not isinstance(value, str) or not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_char_diversity(value: str) -> float:
    """Ratio of unique characters to total length."""
    if not isinstance(value, str) or not value:
        return 0.0
    return len(set(value)) / len(value)


def calculate_confidence_score(key: str, context: str, is_noise: bool) -> float:
    """Calculate confidence score (0-100) for a potential secret.

    Higher score = more likely to be a real API key.
    """
    if not isinstance(key, str):
        key = str(key) if key is not None else ""
    if not isinstance(context, str):
        context = str(context) if context is not None else ""
    # Entropy contribution (0-30 points)
    entropy = shannon_entropy(key)
    entropy_score = min(entropy / 4.5, 1.0) * 30.0

    # Context pattern contribution (0-25 points)
    secret_indicators = [
        r"api[_-]?key",
        r"secret[_-]?key",
        r"private[_-]?key",
        r"access[_-]?key",
        r"auth[_-]?token",
        r"bearer[_-]?token",
        r"password",
        r"passwd",
        r"pwd",
        r"token",
        r"credential",
        r"secret",
    ]
    context_lower = context.lower()
    context_matches = sum(1 for pattern in secret_indicators if re.search(pattern, context_lower))
    context_score = min(context_matches / 2.0, 1.0) * 25.0

    # Noise graduated penalty: clean gets 20, noisy gets 5 (not zero)
    noise_score = 5.0 if is_noise else 20.0

    # Length continuous scaling (0-15 points)
    length = len(key)
    length_score = min(length / 32.0, 1.0) * 15.0

    # Character diversity (0-10 points) with guard for short keys
    if len(key) < 12:
        diversity_score = 0.0
    else:
        raw_diversity = calculate_char_diversity(key)
        diversity_score = min(raw_diversity / 0.7, 1.0) * 10.0

    score = entropy_score + context_score + noise_score + length_score + diversity_score
    return min(max(score, 0.0), 100.0)


def get_severity_level(score: float) -> str:
    """Map a confidence score to a severity label."""
    if score >= 80.0:
        return "CRITICAL"
    if score >= 60.0:
        return "HIGH"
    if score >= 40.0:
        return "MEDIUM"
    return "LOW"


def mask_key(value: str) -> str:
    """Return a masked preview (first 4 … last 2)."""
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    if len(value) <= 6:
        return "***"
    return f"{value[:4]}...{value[-2:]}"


def fingerprint_key(value: str) -> str:
    """Return the SHA-256 hex digest of the key (for deduplication)."""
    if not isinstance(value, str):
        value = str(value) if value is not None else ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
