from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from typing import Optional

import requests

from .util import canonicalize_url, extract_links, same_host


@dataclass(frozen=True)
class CrawlResult:
    start_url: str
    pages: tuple[str, ...]
    errors: tuple[str, ...]


def crawl_site(
    start_url: str,
    *,
    host: str,
    max_depth: int = 1,
    max_pages: int = 50,
    timeout: float = 8.0,
    pause_s: float = 0.0,
    user_agent: str = "SubEnumX/0.1",
) -> CrawlResult:
    start = canonicalize_url(start_url) or start_url
    session = requests.Session()
    headers = {"User-Agent": user_agent}

    seen: set[str] = set()
    pages: list[str] = []
    errors: list[str] = []

    q = deque([(start, 0)])
    while q and len(pages) < max_pages:
        url, depth = q.popleft()
        canon = canonicalize_url(url)
        if not canon:
            continue
        if canon in seen:
            continue
        if not same_host(canon, host):
            continue
        if depth > max_depth:
            continue

        seen.add(canon)
        pages.append(canon)

        try:
            if pause_s > 0:
                time.sleep(pause_s)
            r = session.get(canon, headers=headers, timeout=timeout, allow_redirects=True)
            ct = (r.headers.get("content-type") or "").lower()
            if "text/html" not in ct:
                continue
            for link in extract_links(r.text, r.url):
                if same_host(link, host):
                    q.append((link, depth + 1))
        except requests.RequestException as e:
            errors.append(f"{canon} -> {type(e).__name__}: {e}")

    return CrawlResult(start_url=start, pages=tuple(pages), errors=tuple(errors))

