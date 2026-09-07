"""Regex patterns for detecting API keys and secrets across 14 providers."""

# ---------------------------------------------------------------------------
# Provider key patterns (updated June 2026 — audit hardened)
# ---------------------------------------------------------------------------
ANTHROPIC_KEY_PATTERN = r"\bsk-ant-(?:api\d{2}|oat\d{2}|admin|auth\d{2}|[A-Za-z0-9_-]+)-[A-Za-z0-9_-]{40,}\b"
OPENAI_KEY_PATTERN = (
    r"\b(?:sk-(?:proj|svcacct|admin|svc|session)-[A-Za-z0-9_-]{20,80}T3BlbkFJ"
    r"[A-Za-z0-9_-]{20,80}|sk-[A-Za-z0-9_-]{48,51})\b"
)
GOOGLE_AI_KEY_PATTERN = (
    r"\b(?:AIza[A-Za-z0-9_-]{35}|AQ\.[A-Za-z0-9_-]{35,}|ya29\.[A-Za-z0-9._\-/]{30,})\b"
)
AWS_ACCESS_KEY_PATTERN = (
    r"\b(?:AKIA|ASIA|ABIA|ACCA|APKA|AIDA|AROA|AIPA|ANPA|AGPA|ASCA)[0-9A-Z]{16}\b"
)
GITHUB_TOKEN_PATTERN = (
    r"\b(?:ghp_[0-9a-zA-Z]{36,70}|gho_[0-9a-zA-Z]{36}|ghs_[0-9a-zA-Z]{36,200}|"
    r"ghr_[0-9a-zA-Z]{36}|ghu_[0-9a-zA-Z]{36}|"
    r"github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59})\b"
)
SLACK_TOKEN_PATTERN = (
    r"\b(?:xox[baprsoecde]-[0-9]{9,13}-[0-9]{9,13}-[0-9a-zA-Z]{24,}|"
    r"xapp-[0-9a-zA-Z-]{24,}|xwfp-[0-9a-zA-Z-]{24,}|"
    r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)\b"
)
HUGGINGFACE_KEY_PATTERN = r"\bhf_[A-Za-z0-9]{34,40}\b"
CLOUDFLARE_TOKEN_PATTERN = r"\b(?:cfk_|cfut_|cfat_|cft_)[A-Za-z0-9_-]{30,50}[A-Fa-f0-9]{6,16}\b"
AZURE_CONNECTION_STRING_PATTERN = (
    r"(?i)(?:Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;"
    r"SharedAccessKey=[A-Za-z0-9+/]+={0,2}(?=[^A-Za-z0-9+/=]|$)|"
    r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;"
    r"AccountKey=[A-Za-z0-9+/]+={0,2}(?=[^A-Za-z0-9+/=]|$))"
)
REPLICATE_API_TOKEN_PATTERN = r"\br8_[A-Za-z0-9]{37,40}\b"
GROQ_API_KEY_PATTERN = r"\bgsk_[A-Za-z0-9_-]{30,64}\b"
OPENROUTER_API_KEY_PATTERN = r"\bsk-or-[A-Za-z0-9_-]{30,70}\b"
TOGETHER_API_KEY_PATTERN = r"\btogether_[A-Za-z0-9_-]{30,64}\b"
MISTRAL_API_KEY_PATTERN = r"\bmist_[A-Za-z0-9_-]{30,64}\b"

# ---------------------------------------------------------------------------
# Noise / placeholder detection
# ---------------------------------------------------------------------------
NOISE_SUBSTRINGS = frozenset(
    {
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
)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
DEFAULT_VALIDATION_TIMEOUT = 10
DEFAULT_MAX_CONCURRENCY = 10
DEFAULT_CHECKPOINT_INTERVAL = 25
DEFAULT_CONFIDENCE_THRESHOLD = 50.0

# ---------------------------------------------------------------------------
# Provider registry  (name_key -> (display_name, search_prefix, pattern))
# ---------------------------------------------------------------------------
PROVIDER_CONFIGS = {
    "anthropic": ("Anthropic", "sk-ant-", ANTHROPIC_KEY_PATTERN),
    "openai": ("OpenAI", "sk-", OPENAI_KEY_PATTERN),
    "google": ("Google", "AIza OR ya29", GOOGLE_AI_KEY_PATTERN),
    "aws": ("AWS", "AKIA", AWS_ACCESS_KEY_PATTERN),
    "github": (
        "GitHub",
        "ghp_ OR github_pat_ OR gho_ OR ghs_ OR ghr_ OR ghu_",
        GITHUB_TOKEN_PATTERN,
    ),
    "slack": ("Slack", "xoxb- OR xapp- OR xwfp- OR hooks.slack.com", SLACK_TOKEN_PATTERN),
    "huggingface": ("HuggingFace", "hf_", HUGGINGFACE_KEY_PATTERN),
    "cloudflare": ("Cloudflare", "cfk_ OR cfut_ OR cfat_", CLOUDFLARE_TOKEN_PATTERN),
    "azure": ("Azure", "Endpoint=sb OR DefaultEndpointsProtocol", AZURE_CONNECTION_STRING_PATTERN),
    "replicate": ("Replicate", "r8_", REPLICATE_API_TOKEN_PATTERN),
    "groq": ("Groq", "gsk_", GROQ_API_KEY_PATTERN),
    "openrouter": ("OpenRouter", "sk-or-", OPENROUTER_API_KEY_PATTERN),
    "together": ("Together AI", "together_", TOGETHER_API_KEY_PATTERN),
    "mistral": ("Mistral AI", "mist_", MISTRAL_API_KEY_PATTERN),
}

# Provider names that support live validation
VALIDATABLE_PROVIDERS = frozenset(
    {
        "OpenAI",
        "Anthropic",
        "GitHub",
        "Slack",
        "HuggingFace",
        "Cloudflare",
        "Replicate",
        "Groq",
        "OpenRouter",
        "Together AI",
        "Mistral AI",
    }
)
