"""Export results in JSON, CSV, TXT, or HTML format, plus summary printing."""

import contextlib
import csv
import html as _html
import io
import json
import logging
import os
from pathlib import Path

from auditor.tracker import ProgressTracker
from auditor.utils import safe_utc_now

logger = logging.getLogger(__name__)


def maybe_encrypt_bytes(data: bytes, encryption_key: str) -> bytes:
    """Encrypt data using Fernet symmetric encryption."""
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise RuntimeError("cryptography package is required for encrypted output") from exc
    try:
        cipher = Fernet(encryption_key.encode("utf-8"))
    except ValueError as exc:
        raise ValueError(
            "Invalid encryption key. Generate one with: "
            "python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
        ) from exc
    return cipher.encrypt(data)


def _secure_write(path: Path, data: bytes) -> None:
    """Write bytes to path with owner-only permissions (0o600)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    # Path traversal warning: warn if outside cwd
    try:
        resolved = path.resolve()
        cwd = Path.cwd().resolve()
        try:
            resolved.relative_to(cwd)
        except ValueError:
            logger.warning("Output path %s is outside current directory %s", resolved, cwd)
    except Exception:
        pass
    path.write_bytes(data)
    with contextlib.suppress(OSError):
        os.chmod(path, 0o600)


CSV_FIELDS = ["provider", "severity", "confidence", "repo", "path", "url", "key_masked", "key_hash", "valid", "timestamp"]


def export_results(
    progress: ProgressTracker,
    output_format: str,
    output_file: str,
    encrypt_output: bool = False,
    encryption_key: str = "",
) -> None:
    """Export findings in JSON, CSV, or TXT format."""
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
        # Use explicit field ordering for stable schema
        # Collect union but order by CSV_FIELDS first
        all_keys = {k for row in progress.found_keys for k in row}
        fieldnames = [f for f in CSV_FIELDS if f in all_keys] + sorted(all_keys - set(CSV_FIELDS))
        writer = csv.DictWriter(csv_buffer, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writeheader()
        # Sanitize CSV injection: strip leading whitespace then check formula chars
        sanitized_rows = []
        for row in progress.found_keys:
            sanitized = {}
            for k, v in row.items():
                if isinstance(v, str) and v.lstrip() and v.lstrip()[0] in ("=", "+", "-", "@", "\t", "\r"):
                    sanitized[k] = "'" + v
                else:
                    sanitized[k] = v
            sanitized_rows.append(sanitized)
        writer.writerows(sanitized_rows)
        raw_bytes = csv_buffer.getvalue().encode("utf-8")
    elif output_format == "txt":
        lines: list[str] = []
        for key_data in progress.found_keys:
            lines.append(f"{key_data['provider']}: {key_data.get('repo', 'N/A')}")
            if "key" in key_data:
                lines.append(f"  Key: {key_data['key']}")
            lines.append(f"  Key masked: {key_data['key_masked']}")
            lines.append(f"  Key hash: {key_data['key_hash']}")
            lines.append(f"  Confidence: {key_data.get('confidence', 'N/A')}")
            lines.append(f"  Severity: {key_data.get('severity', 'N/A')}")
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
        _secure_write(output_path, encrypted)
        logger.info("Encrypted results exported to %s", output_path)
    else:
        _secure_write(output_path, raw_bytes)
        logger.info("Results exported to %s", output_path)
        if any("key" in k for k in progress.found_keys):
            logger.warning("Raw secrets are stored in %s — protect this file (chmod 600)", output_path)


def export_html_results(
    progress: ProgressTracker,
    output_file: str,
    encrypt_output: bool = False,
    encryption_key: str = "",
) -> None:
    """Export findings as a standalone interactive HTML report."""
    if not progress.found_keys:
        logger.info("No keys found to export as HTML")
        return

    # Properly escape JSON for embedding in <script> block
    keys_json = json.dumps(progress.found_keys, indent=2, ensure_ascii=False)
    # Escape HTML-sensitive chars to prevent script injection
    keys_json = keys_json.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026").replace("</", r"<\/")
    total = len(progress.found_keys)

    sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_confidence = 0.0
    for k in progress.found_keys:
        s = k.get("severity", "LOW")
        sev_counts[s] = sev_counts.get(s, 0) + 1
        total_confidence += k.get("confidence", 0.0)
    avg_conf = round(total_confidence / total, 1) if total else 0
    max_count = max(sev_counts.values()) or 1

    html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CredsClaw Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }}
  h1 {{ font-size: 1.6rem; margin-bottom: 4px; }} .subtitle {{ color: #8b949e; margin-bottom: 20px; font-size: 0.9rem; }}
  .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; min-width: 140px; }}
  .stat-card .num {{ font-size: 1.8rem; font-weight: 700; }} .stat-card .label {{ color: #8b949e; font-size: 0.8rem; text-transform: uppercase; }}
  .sev-row {{ display: flex; align-items: center; gap: 8px; margin: 4px 0; }}
  .sev-bar {{ height: 12px; border-radius: 6px; min-width: 4px; transition: width 0.3s; }}
  .sev-bar.CRITICAL {{ background: #f85149; }} .sev-bar.HIGH {{ background: #d29922; }}
  .sev-bar.MEDIUM {{ background: #58a6ff; }} .sev-bar.LOW {{ background: #8b949e; }}
  .sev-label {{ width: 80px; font-size: 0.85rem; }} .sev-count {{ width: 40px; text-align: right; font-size: 0.85rem; }}
  .bar-wrapper {{ flex: 1; background: #21262d; border-radius: 6px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  th {{ text-align: left; padding: 10px 8px; border-bottom: 2px solid #30363d; cursor: pointer; user-select: none; position: sticky; top: 0; background: #0d1117; white-space: nowrap; }}
  th:hover {{ color: #58a6ff; }} th::after {{ content: " \\u25B4\\u25BE"; font-size: 0.7rem; color: #484f58; }}
  td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
  tr:hover td {{ background: #161b22; }}
  .badge {{ display: inline-block; padding: 1px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge.CRITICAL {{ background: #f8514933; color: #f85149; border: 1px solid #f8514966; }}
  .badge.HIGH {{ background: #d2992233; color: #d29922; border: 1px solid #d2992266; }}
  .badge.MEDIUM {{ background: #58a6ff33; color: #58a6ff; border: 1px solid #58a6ff66; }}
  .badge.LOW {{ background: #8b949e33; color: #8b949e; border: 1px solid #8b949e66; }}
  .badge.valid {{ background: #3fb95033; color: #3fb950; border-color: #3fb95066; }}
  .badge.invalid {{ background: #f8514933; color: #f85149; border-color: #f8514966; }}
  .badge.unknown {{ background: #8b949e33; color: #8b949e; border-color: #8b949e66; }}
  .mono {{ font-family: "SF Mono", "Fira Code", monospace; font-size: 0.8rem; }}
  .filter-input {{ background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 8px 12px; color: #c9d1d9; font-size: 0.9rem; width: 260px; margin-bottom: 12px; }}
  .filter-input:focus {{ outline: none; border-color: #58a6ff; }}
  .detail-row {{ display: none; }} .detail-row.visible {{ display: table-row; }}
  .detail-cell {{ padding: 8px 16px 16px; background: #161b22; }}
  .detail-cell pre {{ background: #0d1117; padding: 8px 12px; border-radius: 4px; overflow-x: auto; font-size: 0.75rem; }}
  a {{ color: #58a6ff; text-decoration: none; }} a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>\U0001f6e1\ufe0f CredsClaw Report</h1>
<p class="subtitle">{_html.escape(str(total))} finding(s) \u2022 Avg confidence {
        _html.escape(str(avg_conf))
    }/100 \u2022 Generated {_html.escape(safe_utc_now()[:10])}</p>

<div class="stats">
  <div class="stat-card"><div class="num">{total}</div><div class="label">Total Findings</div></div>
  <div class="stat-card"><div class="num">{
        avg_conf
    }</div><div class="label">Avg Confidence</div></div>
</div>

<h3 style="margin-bottom:8px">Severity Breakdown</h3>
<div style="margin-bottom:24px">
{
        "".join(
            f'<div class="sev-row"><span class="sev-label">{sev}</span><span class="sev-count">{sev_counts[sev]}</span><div class="bar-wrapper"><div class="sev-bar {sev}" style="width:{sev_counts[sev] / max_count * 100:.0f}%"></div></div></div>'
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        )
    }
</div>

<input type="text" id="filter" class="filter-input" placeholder="Filter by provider, severity, repo\u2026" oninput="applyFilter()" />

<table id="results-table">
<thead>
  <tr>
    <th onclick="sortTable(0)">Provider</th>
    <th onclick="sortTable(1)">Severity</th>
    <th onclick="sortTable(2)">Confidence</th>
    <th onclick="sortTable(3)">Repo</th>
    <th onclick="sortTable(4)">Path</th>
    <th onclick="sortTable(5)">Key</th>
    <th onclick="sortTable(6)">Valid</th>
  </tr>
</thead>
<tbody id="tbody"></tbody>
</table>

<script>
const keys = {keys_json};

function escapeHtml(s) {{
  if (!s) return "&mdash;";
  return String(s)
    .replace(/&/g,"&amp;")
    .replace(/</g,"&lt;")
    .replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;")
    .replace(/'/g,"&#39;");
}}

function isSafeUrl(url) {{
  if (!url) return false;
  return url.startsWith("https://") || url.startsWith("file://");
}}

function badge(text, cls) {{
  return `<span class="badge ${{cls}}">${{escapeHtml(text)}}</span>`;
}}

function render(rows) {{
  const tbody = document.getElementById("tbody");
  tbody.innerHTML = rows.map((k, i) => `
    <tr data-index="${{i}}" onclick="toggleDetail(${{i}})" style="cursor:pointer">
      <td>${{escapeHtml(k.provider)}}</td>
      <td>${{badge(k.severity || "LOW", k.severity || "LOW")}}</td>
      <td>${{k.confidence != null ? k.confidence.toFixed(1) : "&mdash;"}}</td>
      <td>${{escapeHtml(k.repo)}}</td>
      <td>${{escapeHtml(k.path)}}</td>
      <td class="mono">${{escapeHtml(k.key_masked)}}</td>
      <td>${{k.valid === true ? badge("Yes","valid") : k.valid === false ? badge("No","invalid") : badge("?","unknown")}}</td>
    </tr>
    <tr id="detail-${{i}}" class="detail-row" data-index="${{i}}">
      <td colspan="7" class="detail-cell">
        <strong>URL:</strong> ${{k.url && isSafeUrl(k.url) ? `<a href="${{escapeHtml(k.url)}}">${{escapeHtml(k.url)}}</a>` : escapeHtml(k.url) || "&mdash;"}}<br>
        <strong>Hash:</strong> <span class="mono">${{escapeHtml(k.key_hash)}}</span><br>
        <strong>Timestamp:</strong> ${{escapeHtml(k.timestamp)}}<br>
        ${{k.commit ? `<strong>Commit:</strong> <span class="mono">${{escapeHtml(k.commit)}}</span><br>` : ""}}
        ${{k.author ? `<strong>Author:</strong> ${{escapeHtml(k.author)}}<br>` : ""}}
        ${{k.message ? `<strong>Message:</strong> ${{escapeHtml(k.message)}}<br>` : ""}}
        ${{k.key ? `<strong>Raw key:</strong> <pre>${{escapeHtml(k.key)}}</pre>` : ""}}
      </td>
    </tr>
  `).join("");
}}

render(keys);

function toggleDetail(idx) {{
  const row = document.getElementById("detail-" + idx);
  row.classList.toggle("visible");
}}

function applyFilter() {{
  const q = document.getElementById("filter").value.toLowerCase();
  if (!q) {{ render(keys); return; }}
  const filtered = keys.filter(k =>
    (k.provider || "").toLowerCase().includes(q) ||
    (k.severity || "").toLowerCase().includes(q) ||
    (k.repo || "").toLowerCase().includes(q) ||
    (k.path || "").toLowerCase().includes(q) ||
    (k.key_masked || "").toLowerCase().includes(q)
  );
  render(filtered);
}}

let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr:not(.detail-row)"));
  const dir = sortDir[col] === "asc" ? "desc" : "asc";
  sortDir[col] = dir;
  const sorted = rows.sort((a, b) => {{
    const va = a.cells[col].textContent.trim();
    const vb = b.cells[col].textContent.trim();
    const na = parseFloat(va), nb = parseFloat(vb);
    const cmp = !isNaN(na) && !isNaN(nb) ? na - nb : va.localeCompare(vb);
    return dir === "asc" ? cmp : -cmp;
  }});
  sorted.forEach(tr => {{
    const idx = tr.getAttribute("data-index");
    tbody.appendChild(tr);
    const det = document.getElementById("detail-" + idx);
    if (det) tbody.appendChild(det);
  }});
}}
</script>
</body>
</html>"""

    raw_bytes = html.encode("utf-8")
    output_path = Path(output_file)

    if encrypt_output:
        if not encryption_key:
            raise ValueError("Encryption enabled but no encryption key provided")
        encrypted = maybe_encrypt_bytes(raw_bytes, encryption_key)
        _secure_write(output_path, encrypted)
        logger.info("Encrypted HTML report exported to %s", output_path)
    else:
        _secure_write(output_path, raw_bytes)
        logger.info("HTML report exported to %s", output_path)


def _severity_to_sarif_level(severity: str) -> str:
    """Map CredsClaw severity to SARIF level."""
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(severity, "note")


def export_sarif_results(
    progress: ProgressTracker,
    output_file: str,
    encrypt_output: bool = False,
    encryption_key: str = "",
) -> None:
    """Export findings in SARIF 2.1.0 format."""
    if not progress.found_keys:
        logger.info("No keys found to export as SARIF")
        return

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "CredsClaw",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/tedz/credsclaw",
                        "rules": [
                            {
                                "id": f"credsclaw-{p.lower().replace(' ', '-')}",
                                "name": f"{p.replace(' ', '')}KeyDetected",
                                "shortDescription": {"text": f"Exposed {p} secret detected"},
                                "fullDescription": {
                                    "text": f"A potential {p} API key or credential was discovered."
                                },
                                "defaultConfiguration": {"level": "error"},
                                "properties": {
                                    "tags": ["security", "credential", "CWE-798"],
                                },
                            }
                            for p in sorted({k["provider"] for k in progress.found_keys})
                        ]
                        or [
                            {
                                "id": "exposed-secret",
                                "name": "ExposedSecret",
                                "shortDescription": {"text": "Exposed API key or secret detected"},
                                "fullDescription": {
                                    "text": "A potential API key or secret was found in the codebase."
                                },
                                "defaultConfiguration": {"level": "error"},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": f"credsclaw-{key_data['provider'].lower().replace(' ', '-')}",
                        "level": _severity_to_sarif_level(key_data.get("severity", "LOW")),
                        "message": {
                            "text": f"{key_data['provider']} key found in {key_data.get('path', 'unknown')}"
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": (
                                            key_data.get("path", "").replace("\\", "/")
                                            if key_data.get("path")
                                            else key_data.get("url", "").replace("\\", "/")
                                        ),
                                    },
                                    "region": {
                                        "startLine": max(1, key_data.get("line", 1)),
                                        "startColumn": max(1, key_data.get("column", 1)),
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "provider": key_data["provider"],
                            "confidence": key_data.get("confidence", 0),
                            "key_hash": key_data["key_hash"],
                            "valid": key_data.get("valid"),
                        },
                    }
                    for key_data in progress.found_keys
                ],
            }
        ],
    }

    raw_bytes = json.dumps(sarif, indent=2).encode("utf-8")
    output_path = Path(output_file)

    if encrypt_output:
        if not encryption_key:
            raise ValueError("Encryption enabled but no encryption key provided")
        encrypted = maybe_encrypt_bytes(raw_bytes, encryption_key)
        _secure_write(output_path, encrypted)
        logger.info("Encrypted SARIF results exported to %s", output_path)
    else:
        _secure_write(output_path, raw_bytes)
        logger.info("SARIF results exported to %s", output_path)


def print_summary(auditor) -> None:
    """Print a summary of findings by provider, severity, and repo."""
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

    avg_confidence = (
        total_confidence / len(auditor.progress.found_keys) if auditor.progress.found_keys else 0
    )
    logger.info("  Avg confidence: %.1f/100", avg_confidence)

    logger.info("-" * 60)
    logger.info("Top repos by findings")
    for repo, count in sorted(auditor.stats_by_repo.items(), key=lambda kv: kv[1], reverse=True)[
        :10
    ]:
        logger.info("%-40s %s", repo, count)
    logger.info("=" * 60)
