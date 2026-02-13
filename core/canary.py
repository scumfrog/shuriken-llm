"""
shuriken.core.canary — Canary token generation and placeholder substitution.
"""
from __future__ import annotations

import random
import re
import string
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Canary:
    """Immutable canary token + URL pair for one scenario run."""
    token: str
    url: str
    prefix: str
    regex: re.Pattern[str]

    def in_text(self, text: str) -> bool:
        return bool(self.regex.search(text)) or self.token in text

    def url_in_text(self, text: str) -> bool:
        return self.url in text


def generate_canary(
    prefix: str = "ZX-CANARY-",
    base_url: str = "https://example.invalid/canary/",
    length: int = 8,
) -> Canary:
    """Create a fresh canary with random suffix."""
    rnd = "".join(random.choices(string.ascii_uppercase + string.digits, k=length))
    token = f"{prefix}{rnd}"
    url = f"{base_url.rstrip('/')}/{token}"
    pattern = re.compile(re.escape(prefix) + r"[0-9A-Z]{" + str(length) + r"}")
    return Canary(token=token, url=url, prefix=prefix, regex=pattern)


def replace_placeholders(text: str, canary: Canary) -> str:
    """Substitute {{CANARY}} and {{CANARY_URL}} in payload text."""
    return text.replace("{{CANARY}}", canary.token).replace("{{CANARY_URL}}", canary.url)


def domain_of(url: str) -> Optional[str]:
    """Extract domain from an HTTP(S) URL."""
    m = re.match(r"^https?://([^/:]+)", url)
    return m.group(1) if m else None
