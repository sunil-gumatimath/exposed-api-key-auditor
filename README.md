# Exposed API Key Auditor

Async Python CLI to scan GitHub code or commit messages for exposed API keys (OpenAI, Anthropic, Google AI, AWS, Stripe, GitHub, Slack, Twilio, SendGrid), with resumable checkpoints, optional validation, safer storage defaults, and **confidence-based severity scoring**.

## Features

- Scans GitHub `code` search or `commits` search.
- Provider support:
  - OpenAI (`sk-...`, `sk-proj-...`, `sk-live-...`, `sk-test-...`)
  - Anthropic (`sk-ant-...`)
  - Google AI (`AIza...`)
  - AWS (`AKIA...`)
  - Stripe (`sk_live_...`, `sk_test_...`)
  - GitHub (`ghp_...`, `gho_...`, `ghs_...`)
  - Slack (`xoxb-...`, `xoxp-...`, `xoxa-...`, `xoxr-...`)
  - Twilio (`SK...`)
  - SendGrid (`SG.xxx.yyy`)
- **Confidence-based severity scoring** (CRITICAL/HIGH/MEDIUM/LOW) with tunable threshold
- Async + bounded concurrency for faster scans.
- Checkpoint/resume support (`progress.json`).
- Optional key validation:
  - OpenAI: yes
  - Anthropic: yes
  - Google AI: no reliable lightweight validation endpoint
- Context/noise filtering to reduce false positives.
- Optional allow/deny regex filters.
- Export to JSON/CSV/TXT with confidence and severity fields.
- Optional encrypted output using Fernet.

## Confidence Scoring

Each detected key is assigned a **confidence score (0-100)** based on multiple factors:

- **Entropy** (30 pts): Randomness/complexity of the key
- **Context patterns** (25 pts): Presence of keywords like `api_key`, `secret`, `token`
- **Noise filter** (20 pts): Penalizes placeholder/example contexts
- **Length** (15 pts): Longer keys score higher
- **Character diversity** (10 pts): More unique characters = higher score

Keys are categorized by severity:
- **CRITICAL**: Score ≥ 80 (high-confidence production secrets)
- **HIGH**: Score 60-79
- **MEDIUM**: Score 40-59
- **LOW**: Score < 40

Use `--confidence-threshold` to set the minimum score to report (default: 50.0):

```bash
# Only report high-confidence findings
python auditor.py --confidence-threshold 70

# Lower threshold for broader catch (more false positives)
python auditor.py --confidence-threshold 30 --dry-run
```

The summary report includes severity breakdown and average confidence score.

By default, raw keys are **not** stored.

Stored fields are:
- `key_hash` (SHA-256)
- `key_masked` (partial view only)

Where stored:
- Checkpoint: `progress.json`
- Export output: file from `--output-file` (default `audit_results.json`)

Raw keys are stored only if you explicitly pass:
- `--store-raw-keys` (unsafe)

## Requirements

- Python 3.11+ recommended
- GitHub Personal Access Token in `GITHUB_TOKEN`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Setup

1. Copy `.env.example` to `.env`.
2. Set:
   - `GITHUB_TOKEN=your_token`
3. Optional:
   - `OUTPUT_ENCRYPTION_KEY=...` for encrypted exports.
   - `GITHUB_AUDITOR_DISABLE_FILE_LOG=1` to disable `audit.log`.

## Quick start

Basic run:

```bash
python auditor.py
```

Dry run (search only, no findings export):

```bash
python auditor.py --dry-run --providers openai,anthropic,google
```

Target a single repository:

```bash
python auditor.py --repo owner/repo --providers openai,anthropic,google
```

Validate discovered keys:

```bash
python auditor.py --validate
```

High-throughput scan:

```bash
python auditor.py --max-concurrency 20 --checkpoint-interval 50
```

Scan with confidence threshold (only report high-confidence findings):

```bash
python auditor.py --confidence-threshold 70 --providers openai,aws,stripe
```

Scan all available providers:

```bash
python auditor.py --providers openai,anthropic,google,aws,stripe,github,slack,twilio,sendgrid
```

## Common commands

Code mode with filters:

```bash
python auditor.py --mode code --extensions py,js,env --language python --min-stars 50
```

Commit-message scan:

```bash
python auditor.py --mode commits --repo owner/repo
```

Incremental scan from last checkpoint time:

```bash
python auditor.py --resume --since-checkpoint
```

Encrypted JSON export:

```bash
python auditor.py --encrypt-output --output-file results.enc
```

Allow/deny filtering:

```bash
python auditor.py --allow-patterns OPENAI_API_KEY,ANTHROPIC_API_KEY --deny-patterns example,dummy,mock
```

## CLI options

Core:

- `--repo`: target repository (`owner/repo`), default global search.
- `--mode`: `code` or `commits` (default `code`).
- `--providers`: comma-separated providers (`openai,anthropic,google,aws,stripe,github,slack,twilio,sendgrid`).
- `--extensions`: comma-separated file extensions (code mode only).
- `--validate`: validate found keys where supported.
- `--output-format`: `json`, `csv`, `txt`.
- `--output-file`: export path.
- `--resume`: continue from checkpoint.
- `--checkpoint-file`: checkpoint path (default `progress.json`).
- `--max-pages`: max GitHub result pages.
- `--min-stars`: minimum repo stars.
- `--language`: repo language filter.
- `--updated-after`: repo updated after date (`YYYY-MM-DD`).
- `--sort`: search sort mode (`indexed` or empty best-match mode).
- `--timeout`: validation request timeout seconds.

Performance/UX:

- `--max-concurrency`: concurrent item workers.
- `--checkpoint-interval`: save progress every N processed items.
- `--dry-run`: search only; do not fetch contents or export findings.
- `--since-checkpoint`: only process items newer than checkpoint timestamp.
- `--confidence-threshold`: minimum confidence score (0-100) to report a key (default: 50.0).

Security/filtering:

- `--allow-patterns`: comma-separated regex list; if provided, matching context is prioritized.
- `--deny-patterns`: comma-separated regex list; matched context is rejected.
- `--store-raw-keys`: include raw keys in checkpoint/export (unsafe).
- `--encrypt-output`: encrypt exported file with Fernet.
- `--encryption-key`: Fernet key string (or use `OUTPUT_ENCRYPTION_KEY` env var).

## Output files

- `progress.json`:
  - processed identifiers
  - findings
  - dedupe hashes
  - checkpoint timestamp
- `audit.log`:
  - runtime logs (unless disabled)
- Export file:
  - JSON/CSV/TXT or encrypted bytes if `--encrypt-output`

## Docker

Build the image:

```bash
docker build -t api-key-auditor .
```

Run with your `.env` file and persist outputs in `docker-output/`:

```bash
docker run --rm --env-file .env -v "${PWD}/docker-output:/work" api-key-auditor --dry-run --providers openai,anthropic,google
```

On Windows PowerShell, use:

```powershell
docker run --rm --env-file .env -v "${PWD}/docker-output:/work" api-key-auditor --dry-run --providers openai,anthropic,google
```

Or with Compose:

```bash
docker compose run --rm auditor --dry-run --providers openai,anthropic,google
```

Files such as `progress.json`, `audit.log`, and `audit_results.json` will be written under `docker-output/`.

## Testing

Run tests:

```bash
python -m pytest -q
```

CI:
- GitHub Actions workflow in `.github/workflows/ci.yml` runs tests on Python 3.11 and 3.12.

## Troubleshooting

- `ModuleNotFoundError: dotenv` or `No module named pytest`:
  - `python -m pip install -r requirements.txt`
- GitHub rate limits:
  - use a valid PAT with appropriate scope
  - reduce `--max-concurrency`
  - set `--max-pages`
- Empty results:
  - broaden providers
  - remove strict filters (`--language`, `--min-stars`, `--updated-after`)

## Responsible use

This tool is for authorized security auditing and responsible disclosure only.
Do not use discovered credentials. Report exposures to repository owners/providers for revocation.
