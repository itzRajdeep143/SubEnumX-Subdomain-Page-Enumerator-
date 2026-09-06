from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

import requests
from requests import exceptions as reqexc

from .util import is_subdomain_of, is_valid_hostname


_HOST_LIKE_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")


def _filter_candidates(candidates: Iterable[str], domain: str) -> set[str]:
    out: set[str] = set()
    for c in candidates:
        h = str(c).strip().lower().lstrip("*.").rstrip(".")
        if not h:
            continue
        if not is_valid_hostname(h):
            continue
        if not is_subdomain_of(h, domain):
            continue
        out.add(h)
    return out


def from_crtsh(
    domain: str,
    timeout: float = 12.0,
    pause_s: float = 0.0,
    retries: int = 2,
) -> set[str]:
    """
    Query crt.sh JSON endpoint for certificate names.

    Notes:
    - crt.sh is a public service and can rate-limit; use pause_s to be polite.
    - Results may contain wildcards (*.example.com) and duplicates.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    headers = {"User-Agent": "SubEnumX/0.1"}

    last_err: str | None = None
    for attempt in range(max(1, retries + 1)):
        try:
            if pause_s > 0:
                time.sleep(pause_s)
            r = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=(min(5.0, timeout), timeout),
            )
            r.raise_for_status()
            break
        except (reqexc.ReadTimeout, reqexc.ConnectTimeout, reqexc.ConnectionError) as e:
            last_err = f"{type(e).__name__}: {e}"
            # small backoff
            time.sleep(min(2.0, 0.3 * (attempt + 1)))
        except reqexc.RequestException as e:
            # Other HTTP errors, don't spam retries.
            last_err = f"{type(e).__name__}: {e}"
            return set()
    else:
        # Exhausted retries
        return set()

    # crt.sh sometimes returns invalid JSON when empty; treat as empty.
    try:
        data = r.json()
    except json.JSONDecodeError:
        return set()

    out: set[str] = set()
    for row in data:
        name = row.get("name_value")
        if not name:
            continue
        for line in str(name).splitlines():
            out.update(_filter_candidates([line], domain))
    return out


def from_bufferover(
    domain: str,
    timeout: float = 12.0,
    pause_s: float = 0.0,
) -> set[str]:
    """
    Query dns.bufferover.run for passive DNS results.
    Response JSON contains entries like: "sub.example.com,IP".
    """
    url = "https://dns.bufferover.run/dns"
    params = {"q": f".{domain}"}
    headers = {"User-Agent": "SubEnumX/0.1"}

    try:
        if pause_s > 0:
            time.sleep(pause_s)
        r = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=(min(5.0, timeout), timeout),
        )
        r.raise_for_status()
        data = r.json()
    except Exception:
        return set()

    candidates: list[str] = []
    for key in ("FDNS_A", "RDNS"):
        for item in data.get(key, []) or []:
            # "host,ip" or "ip,host"
            parts = str(item).split(",")
            for p in parts:
                if "." in p:
                    candidates.append(p)
    return _filter_candidates(candidates, domain)


def from_hackertarget(
    domain: str,
    timeout: float = 12.0,
    pause_s: float = 0.0,
) -> set[str]:
    """
    Query HackerTarget hostsearch (unauthenticated; may rate-limit).
    Format: sub.example.com,1.2.3.4 per line.
    """
    url = "https://api.hackertarget.com/hostsearch/"
    params = {"q": domain}
    headers = {"User-Agent": "SubEnumX/0.1"}

    try:
        if pause_s > 0:
            time.sleep(pause_s)
        r = requests.get(
            url,
            params=params,
            headers=headers,
            timeout=(min(5.0, timeout), timeout),
        )
        r.raise_for_status()
        text = r.text or ""
    except Exception:
        return set()

    # If rate-limited, response is often a short message string.
    candidates: list[str] = []
    for line in text.splitlines():
        if "," in line:
            candidates.append(line.split(",", 1)[0])
    return _filter_candidates(candidates, domain)


def from_rapiddns(
    domain: str,
    timeout: float = 12.0,
    pause_s: float = 0.0,
) -> set[str]:
    """
    Scrape RapidDNS subdomain page.
    This is best-effort and may break if the site changes.
    """
    url = f"https://rapiddns.io/subdomain/{domain}"
    headers = {"User-Agent": "SubEnumX/0.1"}

    try:
        if pause_s > 0:
            time.sleep(pause_s)
        r = requests.get(url, headers=headers, timeout=(min(5.0, timeout), timeout))
        r.raise_for_status()
        html = r.text or ""
    except Exception:
        return set()

    candidates = _HOST_LIKE_RE.findall(html)
    return _filter_candidates(candidates, domain)


def gather_subdomains(
    domain: str,
    *,
    timeout: float = 12.0,
    pause_s: float = 0.0,
    crt_retries: int = 2,
) -> dict[str, set[str]]:
    """
    Returns mapping: source_name -> set(hosts)
    """
    calls = {
        "crtsh": lambda: from_crtsh(
            domain, timeout=timeout, pause_s=pause_s, retries=crt_retries
        ),
        "bufferover": lambda: from_bufferover(domain, timeout=timeout, pause_s=pause_s),
        "hackertarget": lambda: from_hackertarget(domain, timeout=timeout, pause_s=pause_s),
        "rapiddns": lambda: from_rapiddns(domain, timeout=timeout, pause_s=pause_s),
    }

    # Run in parallel so one slow source doesn't block the rest.
    out: dict[str, set[str]] = {k: set() for k in calls.keys()}
    # Overall time budget: roughly 1 read timeout per source (+ a bit of buffer).
    overall_timeout_s = max(5.0, float(timeout) + 5.0)

    ex = ThreadPoolExecutor(max_workers=len(calls))
    futs = {ex.submit(fn): name for name, fn in calls.items()}
    try:
        try:
            for fut in as_completed(futs, timeout=overall_timeout_s):
                name = futs[fut]
                try:
                    out[name] = fut.result()
                except Exception:
                    out[name] = set()
        except TimeoutError:
            # Some sources are too slow/hung; ignore them.
            pass
    finally:
        # Don't block shutdown on hung network calls.
        ex.shutdown(wait=False, cancel_futures=True)

    return out


def iter_sorted(hosts: Iterable[str]) -> list[str]:
    return sorted({h.rstrip(".").lower() for h in hosts if h})

