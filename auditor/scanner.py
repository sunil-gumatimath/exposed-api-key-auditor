"""Core APIAuditor class — scans GitHub, local directories, and git history."""

import asyncio
import base64
import logging
import re
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aiohttp

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

from datetime import UTC

from auditor.cli import parse_csv_arg
from auditor.patterns import NOISE_SUBSTRINGS
from auditor.rate_limiter import SEARCH_QUOTA, RateLimiter
from auditor.scoring import (
    calculate_confidence_score,
    fingerprint_key,
    get_severity_level,
    mask_key,
)
from auditor.tracker import ProgressTracker
from auditor.utils import parse_iso8601, safe_utc_now
from auditor.validator import VALIDATION_MAP, create_validator_session

logger = logging.getLogger(__name__)

# Audit hardening constants
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # Skip files larger than 5 MB (avoid OOM)
CONTEXT_WINDOW = 80  # Characters of context around a match (was 40; S-MED-02)
VALIDATION_CONCURRENCY = 5  # Max parallel validation requests (V-MED-04)
_PATTERN_CACHE: dict[str, re.Pattern[str]] = {}


class APIAuditor:
    """Scans GitHub code/commits, local directories, or git history for exposed API keys."""

    def __init__(
        self,
        token: str,
        rate_limiter: RateLimiter,
        progress: ProgressTracker,
        args: Any,
    ):
        self.token = token
        self.rate_limiter = rate_limiter
        self.progress = progress
        self.args = args
        self.session: aiohttp.ClientSession | None = None
        self.lock = asyncio.Lock()
        self.semaphore = asyncio.Semaphore(max(1, args.max_concurrency))
        self.compiled_allow = []
        if getattr(args, "allow_patterns", None):
            for p in args.allow_patterns:
                try:
                    self.compiled_allow.append(re.compile(p, re.IGNORECASE))
                except re.error as exc:
                    logger.warning("Invalid allow pattern '%s' skipped: %s", p, exc)
        self.compiled_deny = []
        if getattr(args, "deny_patterns", None):
            for p in args.deny_patterns:
                try:
                    self.compiled_deny.append(re.compile(p, re.IGNORECASE))
                except re.error as exc:
                    logger.warning("Invalid deny pattern '%s' skipped: %s", p, exc)
        self.stats_by_provider: dict[str, dict[str, int]] = {}
        self.stats_by_repo: dict[str, int] = {}
        self._provider_found_count: dict[str, int] = {}
        self.since_dt = None
        if args.since_checkpoint and progress.checkpoint_timestamp:
            self.since_dt = parse_iso8601(progress.checkpoint_timestamp)
            if self.since_dt is None:
                logger.warning(
                    "Could not parse checkpoint timestamp '%s'; "
                    "will process all items (no incremental filtering)",
                    progress.checkpoint_timestamp,
                )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def __aenter__(self):
        connector_kwargs: dict[str, Any] = {}
        if getattr(self.args, "no_ssl_verify", False):
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            connector_kwargs["ssl"] = ssl_ctx
            logger.warning("SSL certificate verification is disabled")
        connector = aiohttp.TCPConnector(**connector_kwargs)
        self.session = aiohttp.ClientSession(
            connector=connector,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------
    def _incr_stat(self, provider: str, repo: str) -> None:
        provider_stats = self.stats_by_provider.setdefault(
            provider, {"found": 0, "validated_true": 0, "validated_false": 0}
        )
        provider_stats["found"] += 1
        self.stats_by_repo[repo] = self.stats_by_repo.get(repo, 0) + 1
        self._provider_found_count[provider] = self._provider_found_count.get(provider, 0) + 1

    def _record_validation(self, provider: str, valid: bool | None) -> None:
        provider_stats = self.stats_by_provider.setdefault(
            provider, {"found": 0, "validated_true": 0, "validated_false": 0}
        )
        if valid is True:
            provider_stats["validated_true"] += 1
        elif valid is False:
            provider_stats["validated_false"] += 1

    # ------------------------------------------------------------------
    # GitHub API
    # ------------------------------------------------------------------

    async def _fetch_initial_rate_limit(self) -> None:
        """Sync the token bucket with GitHub's actual remaining search quota."""
        try:
            assert self.session is not None, "ClientSession not initialized; use async with"
            headers = {"Authorization": f"token {self.token}"}
            async with self.session.get(
                "https://api.github.com/rate_limit", headers=headers
            ) as resp:
                data = await resp.json()
            resources = data.get("resources", {})
            # Code search has its own, stricter quota (10/min authenticated)
            # separate from general search (30/min). Prefer code_search so we
            # don't seed the bucket with 30 and blow the 10/min budget on the
            # first concurrent volley.
            search = resources.get("code_search") or resources.get("search", {})
            remaining = search.get("remaining", SEARCH_QUOTA)
            reset_at = search.get("reset", 0)
            await self.rate_limiter.update_from_headers(
                {
                    "X-RateLimit-Remaining": str(remaining),
                    "X-RateLimit-Reset": str(reset_at),
                }
            )
            logger.debug(
                "Rate-limit bucket synced: %s search requests remaining",
                remaining,
            )
        except Exception as exc:
            logger.debug("Could not fetch initial rate limit: %s", exc)

    async def request_with_retry(
        self, url: str, headers: dict[str, str] | None = None
    ) -> dict[str, Any] | None:
        assert self.session is not None, "ClientSession not initialized; use async with"
        for attempt in range(self.rate_limiter.max_retries):
            try:
                request_headers = {"Authorization": f"token {self.token}"}
                if headers:
                    request_headers.update(headers)
                async with self.session.get(url, headers=request_headers) as response:
                    resp_headers = dict(response.headers)

                    if response.status in {403, 429}:
                        # Prefer GitHub's Retry-After over blind exponential backoff.
                        retry_after = response.headers.get("Retry-After")
                        if retry_after:
                            try:
                                wait_time = max(1, int(retry_after))
                            except (ValueError, TypeError):
                                wait_time = min(2**attempt, 300)
                        else:
                            wait_time = min(2**attempt, 300)
                        logger.warning(
                            "Rate limit/auth issue for %s (status %s), waiting %ss",
                            url,
                            response.status,
                            wait_time,
                        )
                        await asyncio.sleep(wait_time)
                        if "/search/" in url:
                            await self.rate_limiter.update_from_headers(resp_headers)
                        continue

                    if "/search/" in url:
                        await self.rate_limiter.wait_if_needed(response.status, resp_headers)

                    if response.status == 404:
                        return None

                    response.raise_for_status()
                    return await response.json()  # type: ignore[no-any-return]
            except aiohttp.ClientError as exc:
                logger.error("Request error for %s: %s", url, exc)
                if attempt < self.rate_limiter.max_retries - 1:
                    await self.rate_limiter.exponential_backoff(attempt)
                    continue
                return None
        return None

    async def discover_recent_repositories(self, days: int) -> list[str]:
        """Query GitHub search API for public repositories updated/pushed to within the last N days."""
        from datetime import datetime, timedelta

        # Sync the token bucket with actual GitHub remaining quota
        await self._fetch_initial_rate_limit()

        cutoff_date = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%d")

        # Build query
        q = f"pushed:>{cutoff_date}"
        if self.args.language:
            q += f" language:{self.args.language}"
        if self.args.min_stars:
            q += f" stars:>={self.args.min_stars}"

        logger.info("Discovering public repositories with query: %s", q)
        repos: list[str] = []

        page = 1
        max_repos = 100  # Default safe upper bound
        while len(repos) < max_repos:
            await self.rate_limiter.acquire()
            url = f"https://api.github.com/search/repositories?q={q}&sort=updated&order=desc&per_page=100&page={page}"
            data = await self.request_with_retry(url)
            if not data or "items" not in data:
                break

            items = data["items"]
            if not items:
                break

            for item in items:
                full_name = item.get("full_name")
                if full_name:
                    repos.append(full_name)

            if len(items) < 100:
                break
            page += 1
            if self.args.max_pages and page > self.args.max_pages:
                break

        logger.info("Discovered %s recent repositories to scan", len(repos))
        return repos[:max_repos]

    async def search_github_code(self, query: str, page: int = 1) -> dict[str, Any] | None:
        from urllib.parse import quote_plus

        await self.rate_limiter.acquire()

        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = (
            f"https://api.github.com/search/code?q={encoded_q}&per_page=100&page={page}{sort_param}"
        )
        return await self.request_with_retry(url)

    async def search_github_commits(self, query: str, page: int = 1) -> dict[str, Any] | None:
        from urllib.parse import quote_plus

        await self.rate_limiter.acquire()

        encoded_q = quote_plus(query)
        sort_param = f"&sort={self.args.sort}&order=desc" if self.args.sort else ""
        url = f"https://api.github.com/search/commits?q={encoded_q}&per_page=100&page={page}{sort_param}"
        return await self.request_with_retry(
            url, headers={"Accept": "application/vnd.github.cloak-preview+json"}
        )

    async def get_file_content(self, repo_full_name: str, path: str) -> str | None:
        url = f"https://api.github.com/repos/{repo_full_name}/contents/{path}"
        data = await self.request_with_retry(url)
        if not data or "content" not in data:
            return None
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.error(
                "Failed to decode content from %s/%s: %s",
                repo_full_name,
                path,
                exc,
            )
            return None

    # ------------------------------------------------------------------
    # Candidate extraction and filtering
    # ------------------------------------------------------------------
    def _matches_allow(self, text: str) -> bool:
        if not self.compiled_allow:
            return True
        return any(p.search(text) for p in self.compiled_allow)

    def _matches_deny(self, text: str) -> bool:
        if not self.compiled_deny:
            return False
        return any(p.search(text) for p in self.compiled_deny)

    def is_probable_secret(self, key: str, context: str) -> tuple[bool, float]:
        """Return (is_likely_secret, confidence_score).

        Filters through deny/allow patterns, noise detection, and entropy analysis.
        Noise substrings (example, dummy, …) cause a hard reject unless explicitly
        overridden by an allow pattern.  The caller uses the pre-calculated score to
        avoid double computation.
        """
        combined = f"{key} {context}"
        lowered = combined.lower()

        if self._matches_deny(combined):
            return False, 0.0

        is_noise = any(noise in lowered for noise in NOISE_SUBSTRINGS)

        # Allow pattern overrides the noise hard-reject.
        if self.compiled_allow and self._matches_allow(combined):
            confidence = calculate_confidence_score(key, context, is_noise)
            return True, confidence

        if is_noise:
            return False, 0.0

        confidence = calculate_confidence_score(key, context, is_noise=False)
        return confidence >= self.args.confidence_threshold, confidence

    def extract_candidates(
        self, content: str, pattern: str
    ) -> list[tuple[str, str, float, str, int, int]]:
        candidates: list[tuple[str, str, float, str, int, int]] = []
        # Cache compiled patterns to avoid re.compile on every file (P-LOW-01).
        compiled = _PATTERN_CACHE.get(pattern)
        if compiled is None:
            try:
                compiled = re.compile(pattern)
            except re.error as exc:
                logger.warning("Invalid regex pattern skipped: %s (%s)", pattern, exc)
                return candidates
            _PATTERN_CACHE[pattern] = compiled
        for match in compiled.finditer(content):
            key = match.group(0)
            start = max(0, match.start() - CONTEXT_WINDOW)
            end = min(len(content), match.end() + CONTEXT_WINDOW)
            context = content[start:end]
            is_probable, confidence = self.is_probable_secret(key, context)
            if is_probable:
                severity = get_severity_level(confidence)
                line_no = content[: match.start()].count("\n") + 1
                last_nl = content.rfind("\n", 0, match.start())
                col_no = match.start() - last_nl if last_nl != -1 else match.start() + 1
                candidates.append((key, context, confidence, severity, line_no, col_no))
        return candidates

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    async def batch_validate_keys(
        self, keys_data: list[tuple[dict[str, Any], str]], provider: str
    ) -> None:
        validator = VALIDATION_MAP.get(provider)
        if not validator:
            return
        no_ssl_verify = getattr(self.args, "no_ssl_verify", False)
        timeout = getattr(self.args, "timeout", 10)
        # Bound validation concurrency to avoid provider rate-limits / FD exhaustion (V-MED-04).
        val_semaphore = asyncio.Semaphore(VALIDATION_CONCURRENCY)

        # Reuse a single session for all validations in this batch
        async with create_validator_session(no_ssl_verify, timeout) as session:

            async def _validated(key: str) -> bool | None:
                async with val_semaphore:
                    return await validator(key, timeout, no_ssl_verify, session)  # type: ignore[no-untyped-call]

            tasks = [_validated(raw_key) for _, raw_key in keys_data]
            results = await asyncio.gather(*tasks)
            for (key_data, _), valid in zip(keys_data, results, strict=False):
                async with self.lock:
                    key_data["valid"] = valid
                    self._record_validation(provider, valid)

    # ------------------------------------------------------------------
    # Repo / date filtering
    # ------------------------------------------------------------------
    def _is_recent_enough(self, repo_updated_at: str = "", commit_date: str = "") -> bool:
        """Return True if the item is newer than the checkpoint timestamp."""
        if not self.since_dt:
            return True
        check_dt = parse_iso8601(commit_date) or parse_iso8601(repo_updated_at)
        if not check_dt:
            return True
        return check_dt > self.since_dt

    def filter_repo(self, item: dict[str, Any]) -> bool:
        """Return True if the repository item passes all user-specified filters."""
        repo = item.get("repository", {})

        if self.args.min_stars and repo.get("stargazers_count", 0) < self.args.min_stars:
            return False
        if self.args.language:
            repo_lang = (repo.get("language") or "").lower()
            if repo_lang != self.args.language.lower():
                return False
        if self.args.updated_after:
            updated_at = parse_iso8601(repo.get("updated_at", ""))
            cutoff = parse_iso8601(self.args.updated_after)
            if updated_at and cutoff and updated_at <= cutoff:
                return False
        return True

    # ------------------------------------------------------------------
    # Shared item-processing loop
    # ------------------------------------------------------------------
    async def _run_item_loop(
        self,
        items: list[Any],
        provider: str,
        pattern: str,
        process_func: "Callable[[Any, list[tuple[dict[str, Any], str]]], Any]",
        description: str,
    ) -> None:
        """Run a generic item processing loop with concurrency, progress,
        checkpoint, and optional validation.

        ``process_func`` is an async callable ``(item, keys_to_validate) -> None``
        that extracts candidates from *item* and appends to ``keys_to_validate``.
        """
        if self.args.dry_run:
            logger.info("[Dry run] %s items for %s", len(items), provider)
            return

        keys_to_validate: list[tuple[dict[str, Any], str]] = []

        async def _wrapped(item: Any) -> None:
            async with self.semaphore:
                try:
                    await process_func(item, keys_to_validate)
                except Exception as exc:
                    logger.debug("Item processing failed for %s: %s", provider, exc)

        tasks = [asyncio.create_task(_wrapped(item)) for item in items]
        iterator = asyncio.as_completed(tasks)
        if tqdm:
            iterator = tqdm(iterator, total=len(tasks), desc=description)
        for coro in iterator:
            try:
                await coro
            except Exception as exc:  # pragma: no cover - defensive (wrapped above)
                logger.debug("Task failed for %s: %s", provider, exc)

        if self.args.validate and keys_to_validate:
            logger.info("Validating %s %s keys...", len(keys_to_validate), provider)
            await self.batch_validate_keys(keys_to_validate, provider)

        self.progress.save_progress()
        logger.info(
            "Completed %s: %s keys found (session), %s total unique keys overall",
            description,
            self._provider_found_count.get(provider, 0),
            len(self.progress.found_keys),
        )

    # ------------------------------------------------------------------
    # Scan modes
    # ------------------------------------------------------------------
    async def audit_api_keys(self, provider: str, query: str, pattern: str) -> None:
        """GitHub code search mode."""
        logger.info("Auditing %s API keys...", provider)

        # Sync rate-limit bucket with GitHub's actual remaining quota
        await self._fetch_initial_rate_limit()

        all_items: list[dict[str, Any]] = []

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

        async def process_item(
            item: dict[str, Any],
            keys_to_validate: list[tuple[dict[str, Any], str]],
        ) -> None:
            repo = item["repository"]["full_name"]
            path = item["path"]
            identifier = f"{provider}/{repo}/{path}"

            if not self._is_recent_enough(repo_updated_at=item["repository"].get("updated_at", "")):
                return

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            content = await self.get_file_content(repo, path)
            if not content:
                async with self.lock:
                    self.progress.mark_processed(identifier)
                return

            local_candidates = self.extract_candidates(content, pattern)

            async with self.lock:
                for key, _context, confidence, severity, line_no, col_no in local_candidates:
                    key_hash = fingerprint_key(key)
                    if self.progress.is_duplicate_hash(key_hash):
                        continue
                    key_data: dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": repo,
                        "path": path,
                        "url": item.get("html_url") or f"https://github.com/{repo}/blob/{path}",
                        "line": line_no,
                        "column": col_no,
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

        await self._run_item_loop(
            all_items,
            provider,
            pattern,
            process_item,
            description=f"Auditing {provider}",
        )

    async def audit_commit_messages(self, provider: str, query: str, pattern: str) -> None:
        """GitHub commit-message search mode."""
        logger.info("Auditing %s API keys in commit messages...", provider)

        # Sync rate-limit bucket with GitHub's actual remaining quota
        await self._fetch_initial_rate_limit()

        all_items: list[dict[str, Any]] = []

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

        async def process_commit(
            item: dict[str, Any],
            keys_to_validate: list[tuple[dict[str, Any], str]],
        ) -> None:
            repo = item["repository"]["full_name"]
            commit_sha = item["sha"]
            commit_msg = item.get("commit", {}).get("message", "")
            commit_date = item.get("commit", {}).get("author", {}).get("date", "") or item.get(
                "commit", {}
            ).get("committer", {}).get("date", "")
            identifier = f"{provider}/{repo}/commit/{commit_sha}"

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
                for key, _context, confidence, severity, line_no, col_no in local_candidates:
                    key_hash = fingerprint_key(key)
                    if self.progress.is_duplicate_hash(key_hash):
                        continue
                    key_data: dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": repo,
                        "commit": commit_sha,
                        "url": item.get("html_url")
                        or f"https://github.com/{repo}/commit/{commit_sha}",
                        "message": commit_msg[:120],
                        "line": line_no,
                        "column": col_no,
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

        await self._run_item_loop(
            all_items,
            provider,
            pattern,
            process_commit,
            description=f"Auditing {provider} commits",
        )

    async def audit_local_directory(self, provider: str, pattern: str, directory: str) -> None:
        """Recursive local directory scan."""
        logger.info("Auditing %s API keys in local directory: %s", provider, directory)
        dir_path = Path(directory)
        if not dir_path.is_dir():
            logger.error("Directory not found: %s", directory)
            return

        skip_extensions = {
            ".pyc",
            ".pyo",
            ".pyd",
            ".so",
            ".dll",
            ".exe",
            ".bin",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".ico",
            ".bmp",
            ".svg",
            ".zip",
            ".tar",
            ".gz",
            ".bz2",
            ".7z",
            ".rar",
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".mp3",
            ".mp4",
            ".avi",
            ".mov",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".class",
            ".o",
            ".obj",
        }

        allowed_extensions = None
        if self.args.extensions:
            allowed_extensions = {
                f".{ext.lstrip('.')}" for ext in parse_csv_arg(self.args.extensions)
            }

        all_files: list[Path] = []
        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue
            # Skip symlinks to avoid loops / out-of-scope reads.
            if file_path.is_symlink():
                continue
            # Skip hidden directories (e.g., .git, .venv), but NOT .github or hidden files like .env
            parts = file_path.relative_to(dir_path).parts
            if any(part.startswith(".") and part != ".github" for part in parts[:-1]):
                continue
            if file_path.suffix.lower() in skip_extensions:
                continue
            file_ext = file_path.suffix.lower() or f".{file_path.name.lstrip('.')}"
            if allowed_extensions and file_ext not in allowed_extensions:
                continue
            # Skip very large files to avoid OOM.
            try:
                if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                    logger.debug(
                        "Skipping large file %s (%s bytes)", file_path, file_path.stat().st_size
                    )
                    continue
            except OSError:
                continue
            all_files.append(file_path)

        async def process_file(
            file_path: Path,
            keys_to_validate: list[tuple[dict[str, Any], str]],
        ) -> None:
            identifier = f"{provider}/{file_path}"

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except Exception as exc:
                logger.debug("Failed to read %s: %s", file_path, exc)
                async with self.lock:
                    self.progress.mark_processed(identifier)
                return

            local_candidates = self.extract_candidates(content, pattern)

            async with self.lock:
                for key, _context, confidence, severity, line_no, col_no in local_candidates:
                    key_hash = fingerprint_key(key)
                    if self.progress.is_duplicate_hash(key_hash):
                        continue
                    key_data: dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": "local",
                        "path": str(file_path.relative_to(dir_path)),
                        "url": f"file://{file_path}",
                        "line": line_no,
                        "column": col_no,
                        "timestamp": safe_utc_now(),
                        "confidence": round(confidence, 2),
                        "severity": severity,
                        "valid": None,
                    }
                    if self.args.store_raw_keys:
                        key_data["key"] = key
                    self.progress.add_key(key_data)
                    self._incr_stat(provider, "local")
                    keys_to_validate.append((key_data, key))
                self.progress.mark_processed(identifier)
                if len(self.progress.processed) % self.args.checkpoint_interval == 0:
                    self.progress.save_progress()

        await self._run_item_loop(
            all_files,
            provider,
            pattern,
            process_file,
            description=f"Scanning {provider} (local)",
        )

    async def audit_git_history(self, provider: str, pattern: str, directory: str) -> None:
        """Scan local git commit history across all branches."""
        logger.info("Auditing %s API keys in git history: %s", provider, directory)
        dir_path = Path(directory).resolve()
        git_dir = dir_path / ".git"
        if not git_dir.is_dir():
            logger.error("Not a git repository: %s", directory)
            return

        # Gather all commits via ``git log`` with security isolation
        try:
            process = await asyncio.create_subprocess_exec(
                "git",
                "-c", "core.fsmonitor=",
                "-c", "diff.external=",
                "log",
                "--all",
                "--format=%H%x00%an%x00%ae%x00%aI%x00%s",
                "--reverse",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(dir_path),
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(), timeout=120
                )
            except TimeoutError:
                process.kill()
                await process.communicate()
                logger.error("git log timed out (large repository?)")
                return

            if process.returncode != 0:
                logger.error("git log failed: %s", stderr_bytes.decode("utf-8", errors="replace").strip())
                return
            raw_log = stdout_bytes.decode("utf-8", errors="replace").strip()
        except FileNotFoundError:
            logger.error("git executable not found on PATH")
            return

        if not raw_log:
            logger.info("No commits found in %s", directory)
            return

        commits: list[dict[str, str]] = []
        for line in raw_log.splitlines():
            parts = line.split("\x00", 4)
            if len(parts) == 5:
                commits.append(
                    {
                        "sha": parts[0],
                        "author": parts[1],
                        "author_email": parts[2],
                        "date": parts[3],
                        "subject": parts[4],
                    }
                )

        async def process_commit(
            commit: dict[str, str],
            keys_to_validate: list[tuple[dict[str, Any], str]],
        ) -> None:
            sha = commit["sha"]
            if not re.fullmatch(r"[0-9a-fA-F]{7,40}", sha):
                logger.warning("Invalid commit SHA: %s", sha)
                return
            identifier = f"{provider}/git-history/{sha}"

            async with self.lock:
                if self.progress.is_processed(identifier):
                    return

            try:
                process = await asyncio.create_subprocess_exec(
                    "git",
                    "-c", "core.fsmonitor=",
                    "-c", "diff.external=",
                    "show",
                    "--no-ext-diff",
                    "--format=",
                    sha,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(dir_path),
                )
                try:
                    stdout_bytes, _ = await asyncio.wait_for(process.communicate(), timeout=30)
                except TimeoutError:
                    process.kill()
                    await process.communicate()
                    logger.warning("git show timed out for %s", sha)
                    async with self.lock:
                        self.progress.mark_processed(identifier)
                    return
                diff_text = stdout_bytes.decode("utf-8", errors="replace")
            except FileNotFoundError:
                async with self.lock:
                    self.progress.mark_processed(identifier)
                return

            local_candidates = self.extract_candidates(diff_text, pattern)

            async with self.lock:
                for key, _context, confidence, severity, line_no, col_no in local_candidates:
                    key_hash = fingerprint_key(key)
                    if self.progress.is_duplicate_hash(key_hash):
                        continue
                    key_data: dict[str, Any] = {
                        "provider": provider,
                        "key_hash": key_hash,
                        "key_masked": mask_key(key),
                        "repo": "local (git history)",
                        "path": f"commit/{sha}",
                        "url": f"file://{dir_path}",
                        "commit": sha,
                        "author": commit["author"],
                        "date": commit["date"][:10],
                        "message": commit["subject"][:120],
                        "line": line_no,
                        "column": col_no,
                        "timestamp": safe_utc_now(),
                        "confidence": round(confidence, 2),
                        "severity": severity,
                        "valid": None,
                    }
                    if self.args.store_raw_keys:
                        key_data["key"] = key
                    self.progress.add_key(key_data)
                    self._incr_stat(provider, "local (git)")
                    keys_to_validate.append((key_data, key))
                self.progress.mark_processed(identifier)
                if len(self.progress.processed) % self.args.checkpoint_interval == 0:
                    self.progress.save_progress()

        await self._run_item_loop(
            commits,
            provider,
            pattern,
            process_commit,
            description=f"Git history {provider}",
        )
