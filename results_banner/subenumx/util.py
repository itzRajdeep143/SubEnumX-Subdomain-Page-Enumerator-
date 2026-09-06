from __future__ import annotations

import re
import socket
import time
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse

import dns.resolver
import requests


_DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")


def normalize_domain(domain: str) -> str:
    d = domain.strip().lower().rstrip(".")
    if not d or "/" in d or "://" in d:
        raise ValueError("domain must be a bare hostname like example.com")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"domain looks invalid: {domain!r}")
    return d


def is_subdomain_of(candidate: str, root: str) -> bool:
    c = candidate.rstrip(".").lower()
    r = root.rstrip(".").lower()
    return c == r or c.endswith("." + r)


def canonicalize_url(url: str) -> Optional[str]:
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in ("http", "https"):
        return None
    if not p.netloc:
        return None
    # Drop fragments, normalize empty path
    path = p.path or "/"
    return urlunparse((p.scheme, p.netloc, path, p.params, p.query, ""))


def same_host(url: str, host: str) -> bool:
    u = urlparse(url)
    return u.netloc.lower() == host.lower()


def extract_links(html: str, base_url: str) -> list[str]:
    # Imported lazily to keep startup fast if crawl isn't used.
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a.get("href")
        if not href:
            continue
        absolute = urljoin(base_url, href)
        canon = canonicalize_url(absolute)
        if canon:
            out.append(canon)
    return out


@dataclass(frozen=True)
class DNSResult:
    host: str
    a: tuple[str, ...] = ()
    aaaa: tuple[str, ...] = ()
    cname: tuple[str, ...] = ()

    @property
    def resolves(self) -> bool:
        return bool(self.a or self.aaaa or self.cname)


def resolve_host(host: str, timeout: float = 3.0) -> DNSResult:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    resolver.timeout = timeout

    def _query(rrtype: str) -> tuple[str, ...]:
        try:
            answers = resolver.resolve(host, rrtype)
            return tuple(sorted({str(r).rstrip(".") for r in answers}))
        except Exception:
            return ()

    return DNSResult(
        host=host,
        a=_query("A"),
        aaaa=_query("AAAA"),
        cname=_query("CNAME"),
    )


@dataclass(frozen=True)
class ProbeResult:
    host: str
    url: Optional[str]
    status: Optional[int]
    error: Optional[str] = None


def probe_host_http(
    host: str,
    timeout: float = 6.0,
    user_agent: str = "SubEnumX/0.1",
    pause_s: float = 0.0,
) -> ProbeResult:
    headers = {"User-Agent": user_agent}
    session = requests.Session()

    last_err: Optional[str] = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            if pause_s > 0:
                time.sleep(pause_s)
            r = session.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            return ProbeResult(host=host, url=r.url, status=r.status_code, error=None)
        except requests.RequestException as e:
            last_err = f"{type(e).__name__}: {e}"
            continue
    return ProbeResult(host=host, url=None, status=None, error=last_err)


def chunks(it: Iterable[str], size: int) -> Iterable[list[str]]:
    buf: list[str] = []
    for x in it:
        buf.append(x)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def is_valid_hostname(host: str) -> bool:
    h = host.strip().lower().rstrip(".")
    if not h or len(h) > 253:
        return False
    if not _DOMAIN_RE.match(h):
        return False
    try:
        socket.getaddrinfo("localhost", None)
    except Exception:
        pass
    return True

