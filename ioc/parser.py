"""IOC parsing and normalization."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse
from dataclasses import dataclass
from typing import List


HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
URL_RE = re.compile(r"^(https?://).+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
# Bare keyword: letters/digits/hyphens only, no dots — used for Whoxy keyword reverse WHOIS
WHOIS_KEYWORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9\-]{1,61}[A-Za-z0-9]$")


@dataclass
class IOC:
    value: str
    type: str  # ip, domain, url, hash


def _normalize_url(value: str) -> str:
    try:
        parsed = urlparse(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    netloc = parsed.netloc.lower()
    normalized = parsed._replace(netloc=netloc)
    return urlunparse(normalized)


def _detect_type(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    if HASH_RE.match(v):
        return "hash"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.match(v):
        return "email"
    if URL_RE.match(v):
        return "url"
    if DOMAIN_RE.match(v):
        return "domain"
    if WHOIS_KEYWORD_RE.match(v):
        return "whois"
    return None


def parse_iocs(
    raw: str,
    auto_detect: bool = True,
    allowed_types: set[str] | None = None,
) -> List[IOC]:
    lines = [ln.strip() for ln in raw.splitlines()]
    cleaned = [ln for ln in lines if ln]
    seen: set[str] = set()
    unique: list[str] = []
    for item in cleaned:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    iocs: List[IOC] = []
    for item in unique:
        t = _detect_type(item)
        if not t:
            continue
        if not auto_detect and allowed_types is not None and t not in allowed_types:
            continue
        if t == "url":
            item = _normalize_url(item)
        elif t == "domain":
            item = item.lower()
        iocs.append(IOC(value=item, type=t))
    return iocs
