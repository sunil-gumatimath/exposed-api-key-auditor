"""Standalone validation functions for discovered API keys.

Each function takes a (key, timeout) and returns True/False/None.
Supports an optional ``session`` parameter to reuse a single aiohttp.ClientSession
across multiple validation calls for efficiency.
"""

import json
import logging
import ssl as _ssl

import aiohttp

logger = logging.getLogger(__name__)

# Allowlist of hosts we ever contact for validation (V-MED-02 / SSRF guard).
ALLOWED_VALIDATION_HOSTS = frozenset(
    {
        "api.openai.com",
        "api.anthropic.com",
        "api.github.com",
        "slack.com",
        "huggingface.co",
        "api.cloudflare.com",
        "api.replicate.com",
        "api.groq.com",
        "openrouter.ai",
        "api.together.xyz",
        "api.mistral.ai",
    }
)


def _assert_allowed_url(url: str) -> None:
    """Guard against SSRF — only allow hard-coded validation hosts."""
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    if host not in ALLOWED_VALIDATION_HOSTS:
        raise ValueError(f"Validation host not allowed: {host}")
    if not url.startswith("https://"):
        raise ValueError(f"Validation URL must be https: {url}")

def create_validator_session(
    no_ssl_verify: bool = False, timeout: int = 10
) -> aiohttp.ClientSession:
    """Create a ClientSession with optional SSL verification bypass."""
    if no_ssl_verify:
        logger.warning("SSL certificate verification is disabled — connections are insecure")
    connector_kwargs: dict = {}
    if no_ssl_verify:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl.CERT_NONE
        connector_kwargs["ssl"] = ctx
    t = aiohttp.ClientTimeout(sock_connect=5, sock_read=timeout)
    return aiohttp.ClientSession(connector=aiohttp.TCPConnector(**connector_kwargs), timeout=t)


async def validate_openai_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.openai.com/v1/models"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    logger.warning("OpenAI validation response too large: %s", response.content_length)
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("OpenAI validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("OpenAI validation unexpected error: %s", exc)
        return None


async def validate_anthropic_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.anthropic.com/v1/models"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("Anthropic validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Anthropic validation unexpected error: %s", exc)
        return None


async def validate_google_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    # No reliable lightweight validation endpoint for Google AI keys.
    # Preserved as a stub for future implementation.
    logger.info("Google validation not implemented — skipping")
    return None


async def validate_github_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.github.com/user"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={
                    "Authorization": f"Bearer {key}",
                    "Accept": "application/vnd.github+json",
                },
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status == 401:
                    return False
                if response.status in (403, 429):
                    remaining = response.headers.get("X-RateLimit-Remaining")
                    if remaining == "0":
                        return None
                    try:
                        data = await response.json()
                        msg = str(data.get("message", "")).lower()
                        if "rate limit" in msg:
                            return None
                    except Exception:
                        pass
                    return False
                return None
        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("GitHub validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("GitHub validation unexpected error: %s", exc)
        return None


async def validate_slack_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    if "hooks.slack.com" in key:
        # Webhook URLs should not be tested against auth.test (treats them as bearer tokens)
        return None
    try:
        url = "https://slack.com/api/auth.test"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.post(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                try:
                    data = await response.json()
                except (json.JSONDecodeError, aiohttp.ContentTypeError):
                    return None
                # Only treat explicit ok:true as valid; rate-limit or other ok:false -> unknown
                if response.status != 200:
                    return None
                ok_val = data.get("ok")
                if ok_val is True:
                    return True
                if ok_val is False:
                    # Need to distinguish invalid vs rate-limited; slack returns error field
                    err = str(data.get("error", "")).lower()
                    if "ratelimited" in err or "rate_limited" in err:
                        return None
                    return False
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError) as exc:
        logger.debug("Slack validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Slack validation unexpected error: %s", exc)
        return None


async def validate_huggingface_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://huggingface.co/api/whoami-v2"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("HuggingFace validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("HuggingFace validation unexpected error: %s", exc)
        return None


async def validate_cloudflare_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.cloudflare.com/client/v4/user/tokens/verify"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                if response.status != 200:
                    # Cloudflare returns 200 even for invalid tokens but with success:false
                    # For non-200, treat as unknown unless 401/403
                    return None
                try:
                    data = await response.json()
                except (json.JSONDecodeError, aiohttp.ContentTypeError):
                    return None
                success = data.get("success")
                if success is True:
                    return True
                if success is False:
                    # Check if failure due to rate limit
                    errors = data.get("errors") or []
                    err_str = json.dumps(errors).lower()
                    if "rate" in err_str or "429" in err_str:
                        return None
                    return False
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError) as exc:
        logger.debug("Cloudflare validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Cloudflare validation unexpected error: %s", exc)
        return None


async def validate_replicate_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.replicate.com/v1/account"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("Replicate validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Replicate validation unexpected error: %s", exc)
        return None


async def validate_groq_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.groq.com/openai/v1/models"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("Groq validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Groq validation unexpected error: %s", exc)
        return None


async def validate_openrouter_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://openrouter.ai/api/v1/auth/key"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("OpenRouter validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("OpenRouter validation unexpected error: %s", exc)
        return None


async def validate_together_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.together.xyz/v1/models"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("Together validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Together validation unexpected error: %s", exc)
        return None


async def validate_mistral_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    try:
        url = "https://api.mistral.ai/v1/models"
        _assert_allowed_url(url)

        async def _do(s: aiohttp.ClientSession) -> bool | None:
            async with s.get(
                url,
                headers={"Authorization": f"Bearer {key}"},
            ) as response:
                if response.content_length is not None and response.content_length > 1_000_000:
                    return None
                if response.status == 200:
                    return True
                if response.status in (401, 403):
                    return False
                if response.status == 429:
                    return None
                return None

        if session is not None:
            return await _do(session)
        async with create_validator_session(no_ssl_verify, timeout) as s:
            return await _do(s)
    except (aiohttp.ClientError, TimeoutError, json.JSONDecodeError) as exc:
        logger.debug("Mistral validation failed: %s", exc)
        return None
    except Exception as exc:  # pragma: no cover
        logger.debug("Mistral validation unexpected error: %s", exc)
        return None


async def validate_aws_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    # AWS keys require both Access Key ID AND Secret Access Key.
    # Preserved as a stub for future implementation.
    logger.info("AWS validation not implemented — skipping")
    return None


async def validate_azure_key(
    key: str,
    timeout: int = 10,
    no_ssl_verify: bool = False,
    session: aiohttp.ClientSession | None = None,
) -> bool | None:
    # Azure connection strings require SDK-based validation.
    # Preserved as a stub for future implementation.
    logger.info("Azure validation not implemented — skipping")
    return None


# ---------------------------------------------------------------------------
# Validation registry  (provider_display_name -> callable)
# ---------------------------------------------------------------------------
VALIDATION_MAP = {
    "OpenAI": validate_openai_key,
    "Anthropic": validate_anthropic_key,
    "GitHub": validate_github_key,
    "Slack": validate_slack_key,
    "HuggingFace": validate_huggingface_key,
    "Cloudflare": validate_cloudflare_key,
    "Replicate": validate_replicate_key,
    "Groq": validate_groq_key,
    "OpenRouter": validate_openrouter_key,
    "Together AI": validate_together_key,
    "Mistral AI": validate_mistral_key,
    "Google": validate_google_key,
    "AWS": validate_aws_key,
    "Azure": validate_azure_key,
}
