
import argparse
import asyncio
import base64
import csv
import hashlib
import io
import json
import logging
import math
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus

import aiohttp
from dotenv import load_dotenv

load_dotenv()

try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# Provider patterns
ANTHROPIC_KEY_PATTERN = r"\bsk-ant-[A-Za-z0-9_-]{50,}\b"
OPENAI_KEY_PATTERN = r"\b(?:sk-[A-Za-z0-9]{48}|sk-(?:live|test)-[A-Za-z0-9]{24,}|sk-proj-[A-Za-z0-9_-]{20,})\b"
GOOGLE_AI_KEY_PATTERN = r"\bAIza[A-Za-z0-9_-]{35}\b"

# Additional provider patterns
AWS_ACCESS_KEY_PATTERN = r"\bAKIA[0-9A-Z]{12}\b"
AWS_SECRET_KEY_PATTERN = r"\b(?i)aws_secret_access_key[\s:=]+['\"]?([A-Za-z0-9/+=]{40})['\"]?\b"
STRIPE_KEY_PATTERN = r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"
GITHUB_TOKEN_PATTERN = r"\bgh[poas]_[0-9a-zA-Z]{36}\b"
SLACK_TOKEN_PATTERN = r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}\b"
TWILIO_API_KEY_PATTERN = r"\bSK[0-9a-fA-F]{32}\b"
SENDGRID_API_KEY_PATTERN = r"\bSG\.[0-9a-zA-Z\.\-_]{22}\.[0-9a-zA-Z\.\-_]{43}\b"

DEFAULT_VALIDATION_TIMEOUT = 10
DEFAULT_MAX_CONCURRENCY = 10
DEFAULT_CHECKPOINT_INTERVAL = 25
DEFAULT_CONFIDENCE_THRESHOLD = 50.0

NOISE_SUBSTRINGS = {
    "example",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "your_key",
    "your-api-key",
    "fake",
    "mock",
    "testtest",
    "xxxxx",
}

handlers = [logging.StreamHandler()]
if os.getenv("GITHUB_AUDITOR_DISABLE_FILE_LOG", "0").lower() not in {"1", "true", "yes"}:
    handlers.insert(0, logging.FileHandler("audit.log"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=handlers,
)
logger = logging.getLogger(__name__)


def parse_iso8601(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def safe_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    length = len(value)
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_char_diversity(value: str) -> float:
    """Calculate character diversity ratio (unique chars / total chars)."""
    if not value:
        return 0.0
    return len(set(value)) / len(value)


def calculate_confidence_score(key: str, context: str, is_noise: bool) -> float:
    """Calculate confidence score (0-100) for a potential secret.
    
    Higher score = more likely to be a real secret.
    """
    # Entropy contribution (0-30 points)
    entropy = shannon_entropy(key)
    # Normalize: entropy of 4.5+ is excellent, scale to 30 points
    entropy_score = min(entropy / 4.5, 1.0) * 30.0
    
    # Context pattern contribution (0-25 points)
    # Check for common secret variable names
    secret_indicators = [
        r"api[_-]?key", r"secret[_-]?key", r"private[_-]?key",
        r"access[_-]?key", r"auth[_-]?token", r"bearer[_-]?token",
        r"password", r"passwd", r"pwd", r"token",
        r"credential", r"secret", r"apikey",
    ]
    context_lower = context.lower()
    context_matches = sum(1 for pattern in secret_indicators if re.search(pattern, context_lower))
    context_score = min(context_matches / 2.0, 1.0) * 25.0
    
    # Noise filter penalty (0-20 points, full penalty if noise detected)
    noise_score = 0.0 if is_noise else 20.0
    
    # Length contribution (0-15 points)
    # Longer keys are more likely to be real
    length = len(key)
    if length >= 32:
        length_score = 15.0
    elif length >= 24:
        length_score = 12.0
    elif length >= 16:
        length_score = 8.0
    elif length >= 8:
        length_score = 4.0
    else:
        length_score = 1.0
    
    # Character diversity contribution (0-10 points)
    diversity = calculate_char_diversity(key)
    diversity_score = diversity * 10.0
    
    # Total score (sum of all components, max 100)
    score = entropy_score + context_score + noise_score + length_score + diversity_score
    
    return min(max(score, 0.0), 100.0)


def get_severity_level(score: float) -> str:
    """Get severity level based on confidence score."""
    if score >= 80.0:
        return "CRITICAL"
    elif score >= 60.0:
        return "HIGH"
    elif score >= 40.0:
        return "MEDIUM"
    else:
        return "LOW"


def mask_key(value: str) -> str:
    if len(value) <= 12:
        return "***"
    return f"{value[:8]}...{value[-4:]}"


def fingerprint_key(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class RateLimiter:
    def __init__(self, max_retries: int = 5):
        self.max_retries = max_retries

    async def wait_if_needed(self, status: int, response_headers: Dict[str, str]) -> None:
        remaining = int(response_headers.get("X-RateLimit-Remaining", "1"))
        reset_timestamp = int(response_headers.get("X-RateLimit-Reset", "0"))
        retry_after = response_headers.get("Retry-After")

        if retry_after and status in {403, 429}:
            wait_time = max(1, int(retry_after))
            logger.warning("Rate-limited (Retry-After). Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)
            return

        if remaining == 0 and reset_timestamp:
            wait_time = max(1, int(reset_timestamp - time.time() + 3))
            logger.warning("Rate limit reached. Waiting %s seconds...", wait_time)
            await asyncio.sleep(wait_time)

    async def exponential_backoff(self, attempt: int) -> None:
        wait_time = min(2 ** attempt, 300)
        logger.warning("Backing off for %s seconds (attempt %s/%s)", wait_time, attempt + 1, self.max_retries)
        await asyncio.sleep(wait_time)


class ProgressTracker:
    def __init__(self, checkpoint_file: str = "progress.json", store_raw_keys: bool = False):
        self.checkpoint_file = checkpoint_file
        self.store_raw_keys = store_raw_keys
        self.processed: Set[str] = set()
        self.found_keys: List[Dict[str, Any]] = []
        self.seen_hashes: Set[str] = set()
        self.checkpoint_timestamp: Optional[str] = None
        self.load_progress()

    def load_progress(self) -> None:
        if not Path(self.checkpoint_file).exists():
            return
        try:
            with open(self.checkpoint_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.processed = set(data.get("processed", []))
            self.found_keys = data.get("found_keys", [])
            self.checkpoint_timestamp = data.get("timestamp")

            # New format.
            for item in data.get("seen_keys", []):
                key_hash = item.get("key_hash")
                if key_hash:
                    self.seen_hashes.add(key_hash)

            # Backward compatibility with previous raw-key checkpoints.
            if not self.seen_hashes and data.get("seen_keys"):
                for old_item in data["seen_keys"]:
                    raw = old_item.get("key") if isinstance(old_item, dict) else str(old_item)
                    self.seen_hashes.add(fingerprint_key(raw))

            # Backfill hashes from found_keys if needed.
            for item in self.found_keys:
                if item.get("key_hash"):
                    self.seen_hashes.add(item["key_hash"])
                elif item.get("key"):
                    item["key_hash"] = fingerprint_key(item["key"])
                    item["key_masked"] = mask_key(item["key"])
                    self.seen_hashes.add(item["key_hash"])
                    if not self.store_raw_keys:
                        item.pop("key", None)

            logger.info(
                "Resumed: %s items processed, %s keys found",
                len(self.processed),
                len(self.found_keys),
            )
        except Exception as exc:
            logger.error("Failed to load progress: %s", exc)

    def save_progress(self) -> None:
        try:
            structured_seen = [{"key_hash": key_hash} for key_hash in sorted(self.seen_hashes)]
            serializable_keys = []
            for item in self.found_keys:
                entry = dict(item)
                if not self.store_raw_keys:
                    entry.pop("key", None)
                serializable_keys.append(entry)

            payload = {
                "processed": sorted(self.processed),
                "found_keys": serializable_keys,
                "seen_keys": structured_seen,
                "timestamp": safe_utc_now(),
            }
            with open(self.checkpoint_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as exc:
            logger.error("Failed to save progress: %s", exc)

    def is_processed(self, identifier: str) -> bool:
        return identifier in self.processed

    def mark_processed(self, identifier: str) -> None:
        self.processed.add(identifier)

    def is_duplicate_hash(self, key_hash: str) -> bool:
        return key_hash in self.seen_hashes

    def add_key(self, key_data: Dict[str, Any]) -> None:
        key_hash = key_data["key_hash"]
        if key_hash not in self.seen_hashes:
            self.seen_hashes.add(key_hash)
            self.found_keys.append(key_data)


class APIAuditor:
    def __init__(self, token: str, rate_limiter: RateLimiter, progress: ProgressTracker, args: argparse.Namespace):
        self.token = token
        self.rate_limiter = rate_limiter
        self.progress = progress
        self.args = args
        self.session: Optional[aiohttp.ClientSession] = None
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(max(1, args.max_concurrency))
        self.compiled_allow = [re.compile(p, re.IGNORECASE) for p in args.allow_patterns] if args.allow_patterns else []
        self.compiled_deny = [re.compile(p, re.IGNORECASE) for p in args.deny_patterns] if args.deny_patterns else []
        self.stats_by_provider: Dict[str, Dict[str, int]] = {}
        self.stats_by_repo: Dict[str, int] = {}
        self.since_dt = None
        if args.since_checkpoint and progress.checkpoint_timestamp:
            self.since_dt = parse_iso8601(progress.checkpoint_timestamp)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(headers={"Authorization": f"token {self.token}"})
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def _incr_stat(self, provider: str, repo: str) -> None:
        provider_stats = self.stats_by_provider.setdefault(provider, {"found": 0, "validated_true": 0, "validated_false": 0})
        provider_stats["found"] += 1
        self.stats_by_repo[repo] = self.stats_by_repo.get(repo, 0) + 1

    def _record_validation(self, provider: str, valid: Optional[bool]) -> None:
        provider_stats = self.stats_by_provider.setdefault(provider, {"found": 0, "validated_true": 0, "validated_false": 0})
        if valid is True:
            provider_stats["validated_true"] += 1
        elif valid is False:
            provider_stats["validated_false"] += 1

    async def request_with_retry(self, url: str, headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        for attempt in range(self.rate_limiter.max_retries):
            try:
                request_headers = {"Authorization": f"token {self.token}"}
                if headers:
                    request_headers.update(headers)
                async with self.session.get(url, headers=request_headers) as response:
                    await self.rate_limiter.wait_if_needed(response.status, dict(response.headers))

                    if response.status in {403, 429}:
                        logger.warning("Rate limit/auth issue for %s (status %s)", url, response.status)
                        await self.rate_limiter.exponential_backoff(attempt)
                        continue
                    if response.status == 404:
                        return None

                    response.raise_for_status()
                    return await response.json()
            except aiohttp.ClientError as exc:
                logger.error("Request error for %s: %s", url, exc)
                if attempt < self.rate_limiter.max_retries - 1:
                    await self.rate_limiter.exponential_backoff(attempt)
                    continue
                return None
        return None

    async def search_github_code(self, query: str, page: int = 1) -> Optional[Dict[str, Any]]:
        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = f"https://api.github.com/search/code?q={encoded_q}&per_page=100&page={page}{sort_param}"
        return await self.request_with_retry(url)

    async def search_github_commits(self, query: str, page: int = 1) -> Optional[Dict[str, Any]]:
        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = f"https://api.github.com/search/commits?q={encoded_q}&per_page=100&page={page}{sort_param}"
        return await self.request_with_retry(url, headers={"Accept": "application/vnd.github.cloak-preview+json"})

    async def get_file_content(self, repo_full_name: str, path: str) -> Optional[str]:
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        data = await self.request_with_retry(url)
        if not data or "content" not in data:
            return None
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.error("Failed to decode content from %s/%s: %s", repo_full_name, path, exc)
            return None

    def _matches_allow(self, text: str) -> bool:
        if not self.compiled_allow:
            return True
        return any(p.search(text) for p in self.compiled_allow)

    def _matches_deny(self, text: str) -> bool:
        if not self.compiled_deny:
            return False
        return any(p.search(text) for p in self.compiled_deny)

    def is_probable_secret(self, key: str, context: str) -> bool:
        combined = f"{key} {context}"
        lowered = combined.lower()

        if self._matches_deny(combined):
            return False
        if self.compiled_allow and self._matches_allow(combined):
            return True

        is_noise = any(noise in lowered for noise in NOISE_SUBSTRINGS)
        
        # Calculate confidence score
        confidence = calculate_confidence_score(key, context, is_noise)
        
        # Check against threshold
        return confidence >= self.args.confidence_threshold

    def extract_candidates(self, content: str, pattern: str) -> List[Tuple[str, str, float, str]]:
        candidates: List[Tuple[str, str, float, str]] = []
        for match in re.finditer(pattern, content):
            key = match.group(0)
            start = max(0, match.start() - 40)
            end = min(len(content), match.end() + 40)
            context = content[start:end]
            if self.is_probable_secret(key, context):
                combined = f"{key} {context}"
                is_noise = any(noise in combined.lower() for noise in NOISE_SUBSTRINGS)
                confidence = calculate_confidence_score(key, context, is_noise)
                severity = get_severity_level(confidence)
                candidates.append((key, context, confidence, severity))
        return candidates

    async def validate_openai_key(self, key: str) -> bool:
        try:
            timeout = aiohttp.ClientTimeout(total=self.args.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    "https://api.openai.com/v1/models",
                    headers={"Authorization": f"Bearer {key}"},
                ) as response:
                    return response.status == 200
        except Exception:
            return False

    async def validate_anthropic_key(self, key: str) -> bool:
        try:
            timeout = aiohttp.ClientTimeout(total=self.args.timeout)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    "https://api.anthropic.com/v1/models",
                    headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                ) as response:
                    return response.status == 200
        except Exception:
            return False

    async def validate_google_key(self, key: str) -> Optional[bool]:
        return None

    async def batch_validate_keys(self, keys_data: List[Tuple[Dict[str, Any], str]], provider: str) -> None:
        validation_map = {
            "OpenAI": self.validate_openai_key,
            "Anthropic": self.validate_anthropic_key,
            "Google": self.validate_google_key,
        }
        validator = validation_map.get(provider)
        if not validator:
            return
        tasks = [validator(raw_key) for _, raw_key in keys_data]
        results = await asyncio.gather(*tasks)
        for (key_data, _), valid in zip(keys_data, results):
            key_data["valid"] = valid
            self._record_validation(provider, valid)

    def _is_recent_enough(self, repo_updated_at: str = "", commit_date: str = "") -> bool:
        if not self.since_dt:
            return True
        check_dt = parse_iso8601(commit_date) or parse_iso8601(repo_updated_at)
        if not check_dt:
            return True
        return check_dt > self.since_dt

    def filter_repo(self, item: Dict[str, Any]) -> bool:
        repo = item.get("repository", {})

        if self.args.min_stars and repo.get("stargazers_count", 0) < self.args.min_stars:
            return False
        if self.args.language:
            repo_lang = str(repo.get("language", "")).lower()
            if repo_lang != self.args.language.lower():
                return False
        if self.args.updated_after:
            updated_at = parse_iso8601(repo.get("updated_at", ""))
            cutoff = parse_iso8601(self.args.updated_after)
            if updated_at and cutoff and updated_at <= cutoff:
                return False
        return True

    async def audit_api_keys(self, provider: str, query: str, pattern: str) -> None:
        logger.info("Auditing %s API keys...", provider)
        all_items: List[Dict[str, Any]] = []

        page = 1
        while True:
            results = await self.search_github_code(query, page)
            if not results or "items" not in results:
                break
            items = results["items"]
            if not items:
                break

            filtered = [item for item in items if self.filter_repo(item)]
            all_items.extend(filtered)
            logger.info("Fetched page %s, got %s filtered code hits", page, len(filtered))

            if len(items) < 100:
                break
            page += 1
            if self.args.max_pages and page > self.args.max_pages:
                logger.info("Reached max pages limit: %s", self.args.max_pages)
                break

        if self.args.dry_run:
            logger.info("[Dry run] %s code hits for %s", len(all_items), provider)
            return

        keys_to_validate: List[Tuple[Dict[str, Any], str]] = []

        async def process_item(item: Dict[str, Any]) -> None:
            repo = item["repository"]["full_name"]
            path = item["path"]
            identifier = f"{repo}/{path}"

            if not self._is_recent_enough(repo_updated_at=item["repository"].get("updated_at", "")):
                return

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            async with self.semaphore:
                content = await self.get_file_content(repo, path)
            if not content:
                async with self.lock:
                    self.progress.mark_processed(identifier)
                return

            local_candidates = self.extract_candidates(content, pattern)

            async with self.lock:
                for key, _context, confidence, severity in local_candidates:
                    key_hash = fingerprint_key(key)
                    if self.progress.is_duplicate_hash(key_hash):
                        continue
                    key_data: Dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": repo,
                        "path": path,
                        "url": item.get("html_url") or f"https://github.com/{repo}/blob/{path}",
                        "timestamp": safe_utc_now(),
                        "confidence": round(confidence, 2),
                        "severity": severity,
                        "valid": None,
                    }
                    if self.args.store_raw_keys:
                        key_data["key"] = key
                    self.progress.add_key(key_data)
                    self._incr_stat(provider, repo)
                    keys_to_validate.append((key_data, key))
                self.progress.mark_processed(identifier)
                if len(self.progress.processed) % self.args.checkpoint_interval == 0:
                    self.progress.save_progress()

        tasks = [asyncio.create_task(process_item(item)) for item in all_items]
        iterator = asyncio.as_completed(tasks)
        if tqdm:
            iterator = tqdm(iterator, total=len(tasks), desc=f"Auditing {provider}")
        for coro in iterator:
            await coro

        if self.args.validate and keys_to_validate:
            logger.info("Validating %s %s keys...", len(keys_to_validate), provider)
            await self.batch_validate_keys(keys_to_validate, provider)

        self.progress.save_progress()
        logger.info("Completed %s audit: %s total unique keys found", provider, len(self.progress.found_keys))

    async def audit_commit_messages(self, provider: str, query: str, pattern: str) -> None:
        logger.info("Auditing %s API keys in commit messages...", provider)
        all_items: List[Dict[str, Any]] = []

        page = 1
        while True:
            results = await self.search_github_commits(query, page)
            if not results or "items" not in results:
                break
            items = results["items"]
            if not items:
                break

            filtered = [item for item in items if self.filter_repo(item)]
            all_items.extend(filtered)
            logger.info("Fetched page %s, got %s filtered commits", page, len(filtered))

            if len(items) < 100:
                break
            page += 1
            if self.args.max_pages and page > self.args.max_pages:
                logger.info("Reached max pages limit: %s", self.args.max_pages)
                break

        if self.args.dry_run:
            logger.info("[Dry run] %s commit hits for %s", len(all_items), provider)
            return

        keys_to_validate: List[Tuple[Dict[str, Any], str]] = []

        async def process_commit(item: Dict[str, Any]) -> None:
            repo = item["repository"]["full_name"]
            commit_sha = item["sha"]
            commit_msg = item.get("commit", {}).get("message", "")
            commit_date = (
                item.get("commit", {}).get("author", {}).get("date", "")
                or item.get("commit", {}).get("committer", {}).get("date", "")
            )
            identifier = f"{repo}/commit/{commit_sha}"

            if not self._is_recent_enough(
                repo_updated_at=item["repository"].get("updated_at", ""),
                commit_date=commit_date,
            ):
                return

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            local_candidates = self.extract_candidates(commit_msg, pattern)

            async with self.lock:
                for key, _context, confidence, severity in local_candidates:
                    key_hash = fingerprint_key(key)
                    if self.progress.is_duplicate_hash(key_hash):
                        continue
                    key_data: Dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": repo,
                        "commit": commit_sha,
                        "url": item.get("html_url") or f"https://github.com/{repo}/commit/{commit_sha}",
                        "message": commit_msg[:120],
                        "timestamp": safe_utc_now(),
                        "confidence": round(confidence, 2),
                        "severity": severity,
                        "valid": None,
                    }
                    if self.args.store_raw_keys:
                        key_data["key"] = key
                    self.progress.add_key(key_data)
                    self._incr_stat(provider, repo)
                    keys_to_validate.append((key_data, key))
                self.progress.mark_processed(identifier)
                if len(self.progress.processed) % self.args.checkpoint_interval == 0:
                    self.progress.save_progress()

        tasks = [asyncio.create_task(process_commit(item)) for item in all_items]
        iterator = asyncio.as_completed(tasks)
        if tqdm:
            iterator = tqdm(iterator, total=len(tasks), desc=f"Auditing {provider} commits")
        for coro in iterator:
            await coro

        if self.args.validate and keys_to_validate:
            logger.info("Validating %s %s keys...", len(keys_to_validate), provider)
            await self.batch_validate_keys(keys_to_validate, provider)

        self.progress.save_progress()
        logger.info("Completed %s commits audit: %s total unique keys found", provider, len(self.progress.found_keys))


def maybe_encrypt_bytes(data: bytes, encryption_key: str) -> bytes:
    try:
        from cryptography.fernet import Fernet
    except Exception as exc:
        raise RuntimeError("cryptography package is required for encrypted output") from exc
    cipher = Fernet(encryption_key.encode("utf-8"))
    return cipher.encrypt(data)


def export_results(
    progress: ProgressTracker,
    output_format: str,
    output_file: str,
    encrypt_output: bool = False,
    encryption_key: str = "",
) -> None:
    if not progress.found_keys:
        logger.info("No keys found to export")
        return

    payload = {
        "total_keys": len(progress.found_keys),
        "scan_date": safe_utc_now(),
        "keys": progress.found_keys,
    }

    raw_bytes: bytes
    if output_format == "json":
        raw_bytes = json.dumps(payload, indent=2).encode("utf-8")
    elif output_format == "csv":
        csv_buffer = io.StringIO()
        fieldnames = sorted({k for row in progress.found_keys for k in row.keys()})
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(progress.found_keys)
        raw_bytes = csv_buffer.getvalue().encode("utf-8")
    elif output_format == "txt":
        lines: List[str] = []
        for key_data in progress.found_keys:
            lines.append(f"{key_data['provider']}: {key_data.get('repo', 'N/A')}")
            if "key" in key_data:
                lines.append(f"  Key: {key_data['key']}")
            lines.append(f"  Key masked: {key_data['key_masked']}")
            lines.append(f"  Key hash: {key_data['key_hash']}")
            if key_data.get("valid") is not None:
                lines.append(f"  Valid: {key_data['valid']}")
            lines.append(f"  URL: {key_data.get('url', 'N/A')}")
            lines.append(f"  Timestamp: {key_data['timestamp']}")
            lines.append("")
        raw_bytes = "\n".join(lines).encode("utf-8")
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

    output_path = Path(output_file)
    if encrypt_output:
        if not encryption_key:
            raise ValueError("Encryption enabled but no encryption key provided")
        encrypted = maybe_encrypt_bytes(raw_bytes, encryption_key)
        output_path.write_bytes(encrypted)
        logger.info("Encrypted results exported to %s", output_path)
    else:
        output_path.write_bytes(raw_bytes)
        logger.info("Results exported to %s", output_path)


def print_summary(auditor: APIAuditor) -> None:
    if not auditor.stats_by_provider:
        logger.info("No provider stats to summarize.")
        return
    logger.info("=" * 60)
    logger.info("Summary by provider")
    logger.info("%-12s | %-6s | %-10s | %-10s", "Provider", "Found", "Valid true", "Valid false")
    for provider, stats in sorted(auditor.stats_by_provider.items()):
        logger.info(
            "%-12s | %-6s | %-10s | %-10s",
            provider,
            stats.get("found", 0),
            stats.get("validated_true", 0),
            stats.get("validated_false", 0),
        )
    logger.info("-" * 60)
    
    # Severity breakdown
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_confidence = 0.0
    for key_data in auditor.progress.found_keys:
        severity = key_data.get("severity", "LOW")
        if severity in severity_counts:
            severity_counts[severity] += 1
        total_confidence += key_data.get("confidence", 0.0)
    
    logger.info("Severity breakdown")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts[sev] > 0:
            logger.info("  %-10s: %s", sev, severity_counts[sev])
    
    avg_confidence = total_confidence / len(auditor.progress.found_keys) if auditor.progress.found_keys else 0
    logger.info("  Avg confidence: %.1f/100", avg_confidence)
    
    logger.info("-" * 60)
    logger.info("Top repos by findings")
    for repo, count in sorted(auditor.stats_by_repo.items(), key=lambda kv: kv[1], reverse=True)[:10]:
        logger.info("%-40s %s", repo, count)
    logger.info("=" * 60)


def get_github_token() -> str:
    token = os.getenv("GITHUB_TOKEN")
    if token:
        return token
    return input("Enter your GitHub token: ").strip()


def parse_csv_arg(value: str) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="GitHub API Key Auditor with security, speed, and filtering improvements")
    parser.add_argument("--repo", type=str, default="", help="Specific repository to search (format: owner/repo)")
    parser.add_argument("--extensions", type=str, default="", help="File extensions to search (comma-separated, e.g., py,js,env)")
    parser.add_argument("--mode", type=str, choices=["code", "commits"], default="code", help="Search mode: code or commits")
    parser.add_argument("--validate", action="store_true", help="Validate found API keys")
    parser.add_argument("--output-format", type=str, choices=["json", "csv", "txt"], default="json", help="Output format")
    parser.add_argument("--output-file", type=str, default="audit_results.json", help="Output file path")
    parser.add_argument("--max-pages", type=int, help="Maximum pages to fetch from GitHub API")
    parser.add_argument("--min-stars", type=int, help="Minimum stars for repositories")
    parser.add_argument("--language", type=str, help="Filter by programming language")
    parser.add_argument("--updated-after", type=str, help="Filter repositories updated after date (YYYY-MM-DD)")
    parser.add_argument("--sort", type=str, choices=["indexed", ""], default="indexed", help="Sort mode")
    parser.add_argument("--resume", action="store_true", help="Resume from previous checkpoint")
    parser.add_argument("--checkpoint-file", type=str, default="progress.json", help="Checkpoint file path")
    parser.add_argument("--timeout", type=int, default=DEFAULT_VALIDATION_TIMEOUT, help="Validation timeout in seconds")
    parser.add_argument("--providers", type=str, default="openai,anthropic", help="Providers (openai,anthropic,google,aws,stripe,github,slack,twilio,sendgrid)")

    parser.add_argument("--max-concurrency", type=int, default=DEFAULT_MAX_CONCURRENCY, help="Max concurrent item processors")
    parser.add_argument("--checkpoint-interval", type=int, default=DEFAULT_CHECKPOINT_INTERVAL, help="Save checkpoint every N processed items")
    parser.add_argument("--dry-run", action="store_true", help="Search only; do not fetch contents or export findings")
    parser.add_argument("--since-checkpoint", action="store_true", help="Only process items newer than checkpoint timestamp")
    parser.add_argument("--confidence-threshold", type=float, default=DEFAULT_CONFIDENCE_THRESHOLD, help="Minimum confidence score (0-100) to report a key")

    parser.add_argument("--allow-patterns", type=str, default="", help="Comma-separated regex allow patterns")
    parser.add_argument("--deny-patterns", type=str, default="", help="Comma-separated regex deny patterns")
    parser.add_argument("--store-raw-keys", action="store_true", help="Store raw keys in checkpoint and output (unsafe)")
    parser.add_argument("--encrypt-output", action="store_true", help="Encrypt output file using Fernet key")
    parser.add_argument("--encryption-key", type=str, default="", help="Fernet key (or use OUTPUT_ENCRYPTION_KEY env var)")
    return parser.parse_args()


async def main() -> None:
    args = parse_args()
    args.allow_patterns = parse_csv_arg(args.allow_patterns)
    args.deny_patterns = parse_csv_arg(args.deny_patterns)

    logger.info("=" * 60)
    logger.info("GitHub API Key Auditor - Enhanced Version")
    logger.info("=" * 60)
    logger.info("Mode: %s", args.mode)
    logger.info("Repository: %s", args.repo or "All (global search)")
    logger.info("Providers: %s", args.providers)
    logger.info("Validate: %s", args.validate)
    logger.info("Dry run: %s", args.dry_run)
    logger.info("Max concurrency: %s", args.max_concurrency)
    logger.info("Store raw keys: %s", args.store_raw_keys)
    logger.info("Encrypt output: %s", args.encrypt_output)
    logger.info("=" * 60)

    try:
        token = get_github_token()
        if not token:
            raise ValueError("GitHub token is required")

        if not args.resume and Path(args.checkpoint_file).exists():
            logger.warning("Removing existing checkpoint file: %s", args.checkpoint_file)
            Path(args.checkpoint_file).unlink()

        progress = ProgressTracker(args.checkpoint_file, store_raw_keys=args.store_raw_keys)
        rate_limiter = RateLimiter()

        query_suffix = f" repo:{args.repo}" if args.repo else ""
        if args.mode == "code" and args.extensions:
            for ext in parse_csv_arg(args.extensions):
                query_suffix += f" extension:{ext.lstrip('.')}"

        provider_configs = {
            "anthropic": ("Anthropic", "sk-ant-", ANTHROPIC_KEY_PATTERN),
            "openai": ("OpenAI", "sk-", OPENAI_KEY_PATTERN),
            "google": ("Google", "AIza", GOOGLE_AI_KEY_PATTERN),
            "aws": ("AWS", "AKIA", AWS_ACCESS_KEY_PATTERN),
            "stripe": ("Stripe", "sk_", STRIPE_KEY_PATTERN),
            "github": ("GitHub", "ghp_", GITHUB_TOKEN_PATTERN),
            "slack": ("Slack", "xoxb-", SLACK_TOKEN_PATTERN),
            "twilio": ("Twilio", "SK", TWILIO_API_KEY_PATTERN),
            "sendgrid": ("SendGrid", "SG.", SENDGRID_API_KEY_PATTERN),
        }
        selected = [p.strip().lower() for p in args.providers.split(",") if p.strip()]

        async with APIAuditor(token, rate_limiter, progress, args) as auditor:
            for provider_key in selected:
                config = provider_configs.get(provider_key)
                if not config:
                    logger.warning("Unknown provider: %s, skipping", provider_key)
                    continue
                name, search_term, pattern = config
                query = f"{search_term}{query_suffix}"
                if args.mode == "commits":
                    await auditor.audit_commit_messages(name, query, pattern)
                else:
                    await auditor.audit_api_keys(name, query, pattern)

            if not args.dry_run:
                encryption_key = args.encryption_key or os.getenv("OUTPUT_ENCRYPTION_KEY", "")
                export_results(
                    progress,
                    args.output_format,
                    args.output_file,
                    encrypt_output=args.encrypt_output,
                    encryption_key=encryption_key,
                )
            print_summary(auditor)

        logger.info("Audit complete.")
        logger.info("Total unique keys found: %s", len(progress.found_keys))
        logger.info("Results file: %s", args.output_file)
        logger.info("Progress file: %s", args.checkpoint_file)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc, exc_info=True)


if __name__ == "__main__":
    asyncio.run(main())
