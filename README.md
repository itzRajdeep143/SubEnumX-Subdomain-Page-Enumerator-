## SubEnumX (Subdomain + Page Enumerator)

SubEnumX is a small cybersecurity/OSINT-style **subdomain enumerator** with an optional **page (URL) crawler** per discovered subdomain.

> **Authorized testing only:** run this tool only on domains you **own** or where you have **explicit written permission** to test. Do not run it against targets like `example.com` unless you are authorized.

## What is domain / subdomain enumeration?

In web security, a “target” is usually not a single website page—it is an **entire domain ecosystem**.

- **Domain**: a root name like `example.com`.
- **Subdomain**: a hostname under that domain, like `api.example.com`, `mail.example.com`, `dev.example.com`.

### Why enumeration matters in cybersecurity

Subdomain enumeration is a core step in reconnaissance (recon) because:

- **Attack surface discovery**: organizations often host multiple apps under different subdomains (customer portal, admin portal, APIs, staging environments).
- **Misconfiguration detection**: forgotten staging sites, outdated apps, debug endpoints, or exposed admin panels often live on subdomains.
- **Asset inventory**: security teams need a list of public-facing assets to monitor and protect.

### Passive vs active enumeration

There are two major approaches:

- **Passive enumeration**: collects subdomains from public datasets (OSINT) without brute forcing DNS.  
  Examples: certificate transparency logs, passive DNS databases, public indexes.
- **Active enumeration**: generates guesses (wordlists) and queries DNS to see which exist (brute force).  
  This is noisier and more likely to be blocked; it’s also easier to cross ethical lines.

**SubEnumX focuses on passive enumeration** (best-effort) and then optionally does light verification (DNS resolve, HTTP probe) and page crawling.

## What SubEnumX does (pipeline)

SubEnumX runs in clear stages:

1. **Passive subdomain gathering (OSINT)**  
   Queries multiple public sources and merges results. (Different sources may be down or rate-limited, so we use several.)

2. **DNS verification (optional)** with `--resolve`  
   Checks whether each subdomain actually resolves using DNS record lookups:
   - A (IPv4)
   - AAAA (IPv6)
   - CNAME (alias)

3. **HTTP probing (optional)** with `--probe`  
   For each host, tries:
   - `https://<host>/`
   - then `http://<host>/`  
   Records status code (like 200/301/403) and the final URL after redirects.

4. **Page enumeration / crawling (optional)** with `--crawl`  
   For each live host, the crawler fetches HTML pages and extracts internal links (`<a href="...">`) that stay on the **same host**.  
   It is **depth-limited** (`--depth`) and **page-limited** (`--max-pages`) so it won’t run forever.

5. **Reporting & saving artifacts**  
   - `-o output.txt` saves one full report file
   - `--out-dir results_name` saves multiple files (recommended for submissions)

## Tech stack used (and why)

- **Language**: Python 3  
  Chosen because it is common in security tooling, fast to prototype, and easy to run in a demo.

- **HTTP client**: `requests`  
  Used for reliable GET requests (OSINT sources, probing, crawling).

- **HTML parsing**: `beautifulsoup4`  
  Used to safely parse HTML and extract links for page enumeration.

- **DNS**: `dnspython`  
  Used for DNS record lookups (A / AAAA / CNAME) when `--resolve` is enabled.

- **Concurrency**: `concurrent.futures.ThreadPoolExecutor`  
  Used to speed up DNS/probing/crawling and to avoid one slow OSINT source blocking everything.

## Install

```bash
cd subenumx
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage

Basic subdomain enumeration (passive OSINT only):

```bash
python -m subenumx -d example.com
```

DNS resolve + HTTP probe:

```bash
python -m subenumx -d example.com --resolve --probe
```

Also crawl pages (same-host) up to depth 1:

```bash
python -m subenumx -d example.com --resolve --probe --crawl --depth 1 --max-pages 50
```

Save output to a text file:

```bash
python -m subenumx -d example.com --resolve --probe --crawl -o output.txt
```

Save **all artifacts** into a folder (recommended for submissions):

```bash
python -m subenumx -d example.com --resolve --probe --crawl --out-dir results_example
```

If sources are slow/rate-limited, increase timeout:

```bash
python -m subenumx -d example.com --timeout 30 --crt-retries 4
```

## Output files (when using `--out-dir`)

`--out-dir results_example` writes:

- `results_example/report.txt` (full report)
- `results_example/subdomains.txt`
- `results_example/resolved.txt`
- `results_example/probed.txt`
- `results_example/pages.txt`

## How to present this in evaluation (suggested demo flow)

Use a domain you own (best) or a safe demo domain like `example.com`.

1. Run passive enumeration:

```bash
python -m subenumx -d example.com
```

2. Show DNS + HTTP verification:

```bash
python -m subenumx -d example.com --resolve --probe
```

3. Save everything for your report:

```bash
python -m subenumx -d example.com --resolve --probe --crawl --out-dir results_example
```

Then open `results_example/report.txt` and explain each section.

## Notes, limitations, and ethical use

- **OSINT sources can fail**: public endpoints may be rate-limited, blocked by your network, or temporarily down. SubEnumX prints a per-source count so you can see which sources worked.
- **Not a brute-forcer**: this tool does not do active wordlist brute-forcing; it is intentionally safer/less noisy for demos.
- **Crawling is conservative**:
  - same-host only (does not spider the whole internet)
  - depth-limited + max-pages cap
  - only follows links found in HTML `<a href=...>`
- **Results are not “all subdomains on Earth”**: no tool can guarantee complete coverage. Recon is about combining multiple methods and validating results.

## Project structure (code overview)

- `subenumx/cli.py`: argument parsing + orchestration
- `subenumx/sources.py`: passive subdomain sources (OSINT)
- `subenumx/crawl.py`: simple same-host crawler
- `subenumx/util.py`: URL helpers, DNS resolving, probing helpers, formatting

