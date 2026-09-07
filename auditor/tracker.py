"""Checkpoint / resume progress tracking."""

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from auditor.scoring import fingerprint_key, mask_key
from auditor.utils import safe_utc_now

logger = logging.getLogger(__name__)


class ProgressTracker:
    """Tracks processed items, found keys, and checkpoint/resume state."""

    def __init__(
        self,
        checkpoint_file: str = "output/progress.json",
        store_raw_keys: bool = False,
    ) -> None:
        self.checkpoint_file = checkpoint_file
        self.store_raw_keys = store_raw_keys
        self.processed: set[str] = set()
        self.found_keys: list[dict[str, Any]] = []
        self.seen_hashes: set[str] = set()
        self.checkpoint_timestamp: str | None = None
        self.load_progress()

    def load_progress(self) -> None:
        path = Path(self.checkpoint_file)
        if not path.exists():
            return
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.processed = set(data.get("processed", []))
            self.found_keys = data.get("found_keys", [])
            self.checkpoint_timestamp = data.get("timestamp")

            # Populate seen_hashes from seen_keys (new format) or found_keys (legacy).
            for item in data.get("seen_keys", []):
                key_hash = item.get("key_hash")
                if key_hash:
                    self.seen_hashes.add(key_hash)

            # Backfill hashes from found_keys for backward compat with older checkpoints.
            for item in self.found_keys:
                if not self.store_raw_keys:
                    item.pop("key", None)
                if item.get("key_hash"):
                    self.seen_hashes.add(item["key_hash"])
                elif item.get("key"):
                    item["key_hash"] = fingerprint_key(item["key"])
                    item["key_masked"] = mask_key(item["key"])
                    self.seen_hashes.add(item["key_hash"])

            logger.info(
                "Resumed: %s items processed, %s keys found",
                len(self.processed),
                len(self.found_keys),
            )
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.error("Failed to load progress (format error): %s", exc)
        except OSError as exc:
            logger.warning("Failed to read progress file %s: %s", path, exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Unexpected error loading progress: %s", exc, exc_info=True)

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

            path = Path(self.checkpoint_file)
            path.parent.mkdir(parents=True, exist_ok=True)

            tmp_fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                os.replace(tmp_path, str(path))
                # Restrict checkpoint to owner-only (contains key hashes/masks).
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o600)
            except Exception:
                # Clean up temporary file on failure.
                with contextlib.suppress(OSError):
                    os.unlink(tmp_path)
                raise
        except Exception as exc:
            logger.error("Failed to save progress: %s", exc)

    def is_processed(self, identifier: str) -> bool:
        return identifier in self.processed

    def mark_processed(self, identifier: str) -> None:
        self.processed.add(identifier)

    def is_duplicate_hash(self, key_hash: str) -> bool:
        return key_hash in self.seen_hashes

    def add_key(self, key_data: dict[str, Any]) -> None:
        key_hash = key_data["key_hash"]
        if key_hash not in self.seen_hashes:
            self.seen_hashes.add(key_hash)
            self.found_keys.append(key_data)
