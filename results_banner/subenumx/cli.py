from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from . import __version__
from .crawl import crawl_site
from .sources import gather_subdomains, iter_sorted
from .util import ProbeResult, normalize_domain, probe_host_http, resolve_host


BANNER = r"""
   _____       _     ______                      __   __
  / ___/__  __| |__ / ____/___  __  ______ ___  / /__/ /
  \__ \/ / / /| '_ \\__ \/ __ \/ / / / __ `__ \/ //_/ /
 ___/ / /_/ / | |_) /__/ / /_/ / /_/ / / / / / / ,< /_/
/____/\__,_/  |_.__/____/\____/\__,_/_/ /_/ /_/_/|_|(_)
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subenumx",
        description="Subdomain enumerator + optional page crawler (authorized testing only).",
    )
    p.add_argument("-d", "--domain", required=True, help="Root domain, e.g. example.com")
    p.add_argument("-o", "--output", help="Save full output to a text file")
    p.add_argument(
        "--out-dir",
        help=(
            "Save all artifacts into a directory (creates it if needed). "
            "Writes: report.txt, subdomains.txt, resolved.txt, probed.txt, pages.txt"
        ),
    )

    p.add_argument("--resolve", action="store_true", help="DNS-resolve discovered hosts")
    p.add_argument("--probe", action="store_true", help="HTTP probe discovered hosts")
    p.add_argument("--crawl", action="store_true", help="Crawl pages on live hosts")

    p.add_argument("--depth", type=int, default=1, help="Crawl depth per host (default: 1)")
    p.add_argument("--max-pages", type=int, default=50, help="Max pages per host (default: 50)")

    p.add_argument(
        "--threads",
        type=int,
        default=20,
        help="Worker threads for resolve/probe/crawl (default: 20)",
    )
    p.add_argument(
        "--pause",
        type=float,
        default=0.0,
        help="Polite pause (seconds) between requests per worker (default: 0)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=12.0,
        help="Timeout seconds for passive sources (default: 12)",
    )
    p.add_argument(
        "--crt-retries",
        type=int,
        default=2,
        help="Retries for crt.sh timeouts (default: 2)",
    )
    p.add_argument("--version", action="version", version=f"subenumx {__version__}")
    return p


def _write(out_fp, s: str) -> None:
    out_fp.write(s)
    if not s.endswith("\n"):
        out_fp.write("\n")
    try:
        out_fp.flush()
    except Exception:
        pass


def _write_lines(path: str, lines: list[str]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        domain = normalize_domain(args.domain)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    out_dir = args.out_dir
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        report_path = os.path.join(out_dir, "report.txt")
        out_fp = open(report_path, "w", encoding="utf-8")
    else:
        out_fp = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        for line in BANNER.strip("\n").splitlines():
            _write(out_fp, line)
        _write(out_fp, f"SubEnumX v{__version__}")
        _write(out_fp, f"Target: {domain}")
        _write(out_fp, f"Time (UTC): {ts}")
        _write(out_fp, "")

        # 1) Passive subdomain gather (multiple sources) + always include root
        timeout = max(1.0, float(args.timeout))
        src_map = gather_subdomains(
            domain,
            timeout=timeout,
            pause_s=args.pause,
            crt_retries=max(0, int(args.crt_retries)),
        )
        merged = set().union(*src_map.values()) if src_map else set()
        if not merged:
            _write(
                out_fp,
                "[!] Warning: all passive sources returned no results (network/rate-limit). Continuing with root domain only.",
            )
        subs = iter_sorted(merged | {domain})

        _write(out_fp, "[*] Passive sources:")
        for name in sorted(src_map.keys()):
            _write(out_fp, f"  - {name}: {len(src_map[name])}")
        _write(out_fp, "")
        _write(out_fp, f"[+] Subdomains discovered: {len(subs)}")
        for h in subs:
            _write(out_fp, f"  - {h}")
        _write(out_fp, "")
        if out_dir:
            _write_lines(os.path.join(out_dir, "subdomains.txt"), subs)

        dns_map = {}
        resolved: list[str] = []
        if args.resolve:
            _write(out_fp, "[*] Resolving DNS (A/AAAA/CNAME)...")
            with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
                futs = {ex.submit(resolve_host, h): h for h in subs}
                for fut in as_completed(futs):
                    res = fut.result()
                    dns_map[res.host] = res

            resolved = [h for h in subs if dns_map.get(h) and dns_map[h].resolves]
            _write(out_fp, f"[+] Hosts that resolve: {len(resolved)}/{len(subs)}")
            for h in resolved:
                r = dns_map[h]
                bits = []
                if r.a:
                    bits.append("A=" + ",".join(r.a))
                if r.aaaa:
                    bits.append("AAAA=" + ",".join(r.aaaa))
                if r.cname:
                    bits.append("CNAME=" + ",".join(r.cname))
                _write(out_fp, f"  - {h} ({' | '.join(bits)})")
            _write(out_fp, "")
            if out_dir:
                _write_lines(os.path.join(out_dir, "resolved.txt"), resolved)

        # 2) HTTP probing
        probe_results: dict[str, ProbeResult] = {}
        probed_lines: list[str] = []
        if args.probe:
            hosts_to_probe = subs
            if args.resolve and dns_map:
                hosts_to_probe = [h for h in subs if dns_map.get(h) and dns_map[h].resolves]

            _write(out_fp, f"[*] Probing HTTP(S) for {len(hosts_to_probe)} hosts...")
            with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
                futs = {
                    ex.submit(probe_host_http, h, pause_s=args.pause): h
                    for h in hosts_to_probe
                }
                for fut in as_completed(futs):
                    pr = fut.result()
                    probe_results[pr.host] = pr

            ok = [h for h, pr in probe_results.items() if pr.status is not None]
            _write(out_fp, f"[+] Hosts responding over HTTP(S): {len(ok)}/{len(hosts_to_probe)}")
            for h in sorted(probe_results.keys()):
                pr = probe_results[h]
                if pr.status is None:
                    _write(out_fp, f"  - {h} -> no response ({pr.error})")
                    probed_lines.append(f"{h}\tNO_RESPONSE\t{pr.error or ''}")
                else:
                    _write(out_fp, f"  - {h} -> {pr.status} ({pr.url})")
                    probed_lines.append(f"{h}\t{pr.status}\t{pr.url}")
            _write(out_fp, "")
            if out_dir:
                _write_lines(os.path.join(out_dir, "probed.txt"), probed_lines)

        # 3) Crawl pages
        pages_lines: list[str] = []
        if args.crawl:
            if not args.probe:
                _write(out_fp, "[-] --crawl requires --probe (to discover a start URL per host).")
                return 2

            live_hosts = [
                h for h, pr in probe_results.items() if pr.status is not None and pr.url
            ]
            _write(out_fp, f"[*] Crawling pages on {len(live_hosts)} live hosts...")
            with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
                futs = {
                    ex.submit(
                        crawl_site,
                        probe_results[h].url,
                        host=h,
                        max_depth=max(0, args.depth),
                        max_pages=max(1, args.max_pages),
                        pause_s=args.pause,
                    ): h
                    for h in live_hosts
                }
                for fut in as_completed(futs):
                    h = futs[fut]
                    cr = fut.result()
                    _write(out_fp, f"[+] {h} pages ({len(cr.pages)}):")
                    for u in cr.pages:
                        _write(out_fp, f"  - {u}")
                        pages_lines.append(u)
                    if cr.errors:
                        _write(out_fp, f"  [!] errors ({len(cr.errors)}):")
                        for e in cr.errors[:10]:
                            _write(out_fp, f"    - {e}")
                    _write(out_fp, "")
            if out_dir:
                _write_lines(os.path.join(out_dir, "pages.txt"), sorted(set(pages_lines)))

        return 0
    finally:
        if out_fp is not sys.stdout:
            out_fp.close()


if __name__ == "__main__":
    raise SystemExit(main())

