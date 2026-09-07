"""Entry point for python -m auditor."""

import argparse
import asyncio
import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from auditor.cli import generate_pre_commit_config, get_github_token, parse_args, parse_csv_arg
from auditor.config import load_config
from auditor.exporter import (
    export_html_results,
    export_results,
    export_sarif_results,
    print_summary,
)
from auditor.patterns import PROVIDER_CONFIGS
from auditor.rate_limiter import RateLimiter
from auditor.scanner import APIAuditor
from auditor.tracker import ProgressTracker

logger = logging.getLogger("auditor")


def _setup_file_logging() -> None:
    """Add a file handler to the ``auditor`` logger."""
    log_dir = Path("output")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / "audit.log"

    file_handler = logging.FileHandler(str(log_path))
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
    # Avoid duplicate handlers if called more than once
    auditor_logger = logging.getLogger("auditor")
    existing = {type(h).__name__ for h in auditor_logger.handlers}
    if "FileHandler" not in existing:
        auditor_logger.addHandler(file_handler)


async def main() -> None:
    """Main entry point — parse args, run audit, export results."""
    # Early parse to get --config before full argument resolution
    early_parser = argparse.ArgumentParser(add_help=False)
    early_parser.add_argument("--config", type=str, default="auditor.yaml")
    early_parser.add_argument("--generate-pre-commit-hook", action="store_true")
    early_parser.add_argument("--force", action="store_true")
    early_args, _ = early_parser.parse_known_args()

    # Handle standalone utility flags before full parsing
    if early_args.generate_pre_commit_hook:
        generate_pre_commit_config(force=early_args.force)
        return

    # Ensure output directory exists and set up file logging
    _setup_file_logging()

    # Load YAML config and parse args (config values act as defaults, CLI still wins)
    config = load_config(early_args.config)
    args = parse_args(config=config)

    args.allow_patterns = parse_csv_arg(args.allow_patterns)
    args.deny_patterns = parse_csv_arg(args.deny_patterns)

    logger.info("=" * 60)
    logger.info("CredsClaw")
    logger.info("=" * 60)
    logger.info("Mode: %s", args.mode)
    logger.info("Repository: %s", args.repo or "All (global search)")
    logger.info("Providers: %s", args.providers)
    logger.info("Validate: %s", args.validate)
    logger.info("Dry run: %s", args.dry_run)
    logger.info("Max concurrency: %s", args.max_concurrency)
    logger.info("Parallel providers: %s", "yes" if len(parse_csv_arg(args.providers)) > 1 else "no")
    logger.info("Store raw keys: %s", args.store_raw_keys)
    logger.info("Encrypt output: %s", args.encrypt_output)
    logger.info("Output format: %s", args.output_format)
    logger.info("=" * 60)

    try:
        if args.mode in ("local", "git-history"):
            token = os.getenv("GITHUB_TOKEN", "")
        else:
            token = get_github_token()
            if not token:
                raise ValueError("GitHub token is required")

        if not args.resume and not args.since_checkpoint and Path(args.checkpoint_file).exists():
            logger.warning("Removing existing checkpoint file: %s", args.checkpoint_file)
            Path(args.checkpoint_file).unlink()

        progress = ProgressTracker(args.checkpoint_file, store_raw_keys=args.store_raw_keys)
        rate_limiter = RateLimiter()

        selected = [p.strip().lower() for p in args.providers.split(",") if p.strip()]
        # Expand "all" to every available provider key
        if "all" in selected:
            selected = list(PROVIDER_CONFIGS.keys())

        async with APIAuditor(token, rate_limiter, progress, args) as auditor:
            # If recent_repos_days is set, discover repositories first
            discovered_repos = []
            if args.recent_repos_days is not None:
                discovered_repos = await auditor.discover_recent_repositories(
                    args.recent_repos_days
                )
                if not discovered_repos:
                    logger.warning(
                        "No recently updated repositories found matching criteria. Exiting."
                    )
                    return

            # Generate suffix list
            # A query suffix is either derived from:
            # 1. A single repo: `repo:owner/repo`
            # 2. Chunked discovered repos: `(repo:A OR repo:B OR ...)`
            # 3. Nothing (global search)
            suffix_chunks = []
            if args.repo:
                suffix_chunks = [f" repo:{args.repo}"]
            elif args.recent_repos_days is not None:
                # GitHub's code-search `repo:` qualifier accepts exactly ONE
                # repository per query. Comma-joining several (`repo:A,B,C`)
                # is accepted but silently drops every repo after the first,
                # and an OR-group (`(repo:A OR repo:B)`) is rejected with 422.
                # The only correct form is therefore one query per repo.
                for repo in discovered_repos:
                    suffix_chunks.append(f" repo:{repo}")
            else:
                suffix_chunks = [""]
                if args.mode in ("code", "commits"):
                    logger.warning(
                        "No --repo or --recent-repos-days specified. "
                        "This will search ALL of GitHub which may return "
                        "many results and consume significant API quota. "
                        "Consider specifying --repo or --recent-repos-days."
                    )

            # Add extension filters if mode == code
            if args.mode == "code" and args.extensions:
                ext_filter = ""
                for ext in parse_csv_arg(args.extensions):
                    ext_filter += f" extension:{ext.lstrip('.')}"
                # Append extension filters to each suffix chunk
                suffix_chunks = [s + ext_filter for s in suffix_chunks]

            provider_tasks = []
            for provider_key in selected:
                config_entry = PROVIDER_CONFIGS.get(provider_key)
                if not config_entry:
                    logger.warning("Unknown provider: %s, skipping", provider_key)
                    continue
                name, search_term, pattern = config_entry

                for suffix in suffix_chunks:
                    query = f"{search_term}{suffix}"

                    if args.mode == "local":
                        if not args.dir:
                            raise ValueError("--dir is required for local mode")
                        provider_tasks.append(
                            auditor.audit_local_directory(name, pattern, args.dir)
                        )
                    elif args.mode == "git-history":
                        if not args.dir:
                            raise ValueError("--dir is required for git-history mode")
                        provider_tasks.append(auditor.audit_git_history(name, pattern, args.dir))
                    elif args.mode == "commits":
                        provider_tasks.append(auditor.audit_commit_messages(name, query, pattern))
                    else:
                        provider_tasks.append(auditor.audit_api_keys(name, query, pattern))

            if provider_tasks:
                results = await asyncio.gather(*provider_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, Exception):
                        logger.error("Provider task failed: %s", result, exc_info=result)

            if not args.dry_run:
                encryption_key = args.encryption_key or os.getenv("OUTPUT_ENCRYPTION_KEY", "")
                if args.output_format == "html":
                    export_html_results(
                        progress,
                        args.output_file,
                        encrypt_output=args.encrypt_output,
                        encryption_key=encryption_key,
                    )
                elif args.output_format == "sarif":
                    export_sarif_results(
                        progress,
                        args.output_file,
                        encrypt_output=args.encrypt_output,
                        encryption_key=encryption_key,
                    )
                else:
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

        # CI / CD gatekeeper exit code handling
        if not args.dry_run and progress.found_keys:
            if getattr(args, "fail_on_findings", False):
                logger.error(
                    "CI gatekeeper: %s exposed key(s) detected — exiting with status 2",
                    len(progress.found_keys),
                )
                sys.exit(2)
            fail_severity = getattr(args, "fail_on_severity", "")
            if fail_severity:
                severity_ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                min_rank = severity_ranks.get(fail_severity.upper(), 1)
                matching = [
                    k
                    for k in progress.found_keys
                    if severity_ranks.get(str(k.get("severity", "LOW")).upper(), 1) >= min_rank
                ]
                if matching:
                    logger.error(
                        "CI gatekeeper: %s finding(s) with severity >= %s detected — exiting with status 2",
                        len(matching),
                        fail_severity,
                    )
                    sys.exit(2)
    except Exception as exc:
        logger.error("Unexpected error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
