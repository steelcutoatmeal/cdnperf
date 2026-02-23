# cdnperf

A Python CLI tool that measures latency to CDN Points of Presence with granular per-phase timing breakdown (DNS, TCP, TLS, TTFB) and traces the network path to each CDN showing every hop with ASN information.

## Features

- **Per-phase latency breakdown** — DNS resolution, TCP connect, TLS handshake, and time-to-first-byte measured independently
- **PoP detection** — Automatically identifies which CDN edge location you're routed to (e.g., DFW, DEN, LAX)
- **Network path tracing** — Traceroute to each CDN with ASN ownership via Team Cymru DNS lookups
- **6 CDN providers** — Cloudflare, CloudFront, Fastly, Akamai, Azure CDN, Google
- **Statistical aggregation** — Min, avg, median, P95, max, stdev, jitter across samples
- **User geolocation** — Shows your IP, location, ISP, and distance to each detected PoP
- **Multiple output formats** — Rich terminal tables, JSON, CSV
- **Concurrent measurement** — All providers measured in parallel; samples run sequentially per provider with fresh connections

## Installation

```bash
cd cdnperf
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick Start

```bash
# Measure all 6 CDN providers (default: 5 samples each)
cdnperf

# Single provider, 3 samples, verbose per-sample detail
cdnperf -p cloudflare -n 3 -v

# Multiple providers, comparison table only
cdnperf -p cloudflare,cloudfront,google --compare

# Skip traceroute for faster results
cdnperf --no-trace

# Export to JSON
cdnperf --json -o results.json

# Export to CSV
cdnperf --csv -o results.csv

# Use a custom DNS server
cdnperf --dns-server 8.8.8.8

# Quiet mode (no progress bar)
cdnperf -q
```

You can also run it as a module:

```bash
python -m cdnperf -p cloudflare -n 3
```

## CLI Options

```
Usage: cdnperf [OPTIONS]

Options:
  -p, --providers TEXT   Comma-separated providers [default: all]
                         Available: akamai, azure, cloudflare, cloudfront, fastly, google
  -n, --samples INTEGER  Samples per provider [default: 5]
  -w, --warmup INTEGER   Warmup requests (discarded) [default: 1]
  --no-warmup            Disable warmup
  -d, --delay INTEGER    Inter-sample delay in ms [default: 100]
  -t, --timeout FLOAT    Request timeout in seconds [default: 10.0]
  --dns-server TEXT      Custom DNS server (e.g., 8.8.8.8)
  -4, --ipv4-only        Force IPv4
  -6, --ipv6-only        Force IPv6
  --trace / --no-trace   Enable/disable network path tracing [default: trace]
  --max-hops INTEGER     Max hops for traceroute [default: 30]
  --json                 Output JSON to stdout
  --csv                  Output CSV to stdout
  -o, --output FILE      Write results to file
  -q, --quiet            Suppress progress, show only results
  -v, --verbose          Show per-sample details
  --no-geo               Skip geolocation lookup
  --compare              Show only summary comparison table
  --version              Show the version and exit.
  --help                 Show this message and exit.
```

## Output

### Per-Provider Detail

Each provider shows a phase breakdown stats table and optional network path:

```
Cloudflare — PoP: DEN (Denver, US) — 623 km away
┌──────────┬────────┬────────┬────────┬────────┬────────┬────────┐
│ Phase    │    Min │    Avg │ Median │    P95 │    Max │ Jitter │
├──────────┼────────┼────────┼────────┼────────┼────────┼────────┤
│ DNS      │ 15.7ms │ 16.9ms │ 15.8ms │ 18.9ms │ 19.2ms │  1.8ms │
│ TCP      │ 13.8ms │ 13.9ms │ 13.8ms │ 14.1ms │ 14.2ms │  0.2ms │
│ TLS      │ 18.6ms │ 19.0ms │ 19.2ms │ 19.2ms │ 19.2ms │  0.3ms │
│ TTFB     │ 49.4ms │ 53.5ms │ 54.8ms │ 56.1ms │ 56.3ms │  6.1ms │
│ Total    │100.3ms │101.4ms │101.8ms │101.9ms │102.0ms │  1.5ms │
└──────────┴────────┴────────┴────────┴────────┴────────┴────────┘
  Edge IP: 162.159.140.220 | TLS: TLSv1.3 | HTTP/1.1
```

### Network Path

Hop-by-hop traceroute with reverse DNS and ASN ownership:

```
Network Path (16 hops, 4 ASNs traversed)
┌─────┬─────────────────┬──────────────────────────────────────┬────────┬──────────────────────────────┐
│ Hop │ IP              │ Hostname                             │    RTT │ ASN                          │
├─────┼─────────────────┼──────────────────────────────────────┼────────┼──────────────────────────────┤
│  1  │ X.X.X.X         │ —                                    │  1.8ms │ (private)                    │
│  2  │ X.X.X.X         │ —                                    │  2.1ms │ AS13614 ALL-WEST, US         │
│  3  │ 135.129.252.170 │ —                                    │  2.4ms │ AS13614 ALL-WEST, US         │
│  4  │ 154.54.85.37    │ be4484.ccr32.slc01.atlas.cogentco.c… │  5.1ms │ AS174 COGENT-174, US         │
│  5  │ 154.54.42.97    │ be3036.ccr22.den01.atlas.cogentco.c… │ 11.2ms │ AS174 COGENT-174, US         │
│  6  │ 154.54.5.146    │ be8969.ccr32.slc01.atlas.cogentco.c… │  4.3ms │ AS174 COGENT-174, US         │
│  7  │ 154.54.31.34    │ be3382.ccr21.den01.atlas.cogentco.c… │ 12.8ms │ AS174 COGENT-174, US         │
│  8  │ 154.54.7.129    │ be3109.ccr21.mci01.atlas.cogentco.c… │ 13.1ms │ AS174 COGENT-174, US         │
│  9  │ *               │                                      │      * │                              │
│ 10  │ *               │                                      │      * │                              │
│ 11  │ 198.51.100.2    │ ix-ae-12-0.tcore2.DEN.net.telstra.c… │ 13.5ms │ AS4637 TELSTRA-AS, AU        │
│ 12  │ *               │                                      │      * │                              │
│ 13  │ 172.68.32.10    │ —                                    │ 14.5ms │ AS13335 CLOUDFLARENET, US     │
│ 14  │ 162.159.140.220 │ —                                    │ 13.9ms │ AS13335 CLOUDFLARENET, US     │
└─────┴─────────────────┴──────────────────────────────────────┴────────┴──────────────────────────────┘
  target reached ✓
```

### Summary Comparison

When measuring multiple providers, a comparison table is shown sorted by median total latency with color-coded bars:

```
CDN Comparison (sorted by median total latency)
┌──────────────┬──────┬───────┬───────┬───────┬───────┬───────┬────────┬──────┬──────────────────────┐
│ Provider     │ PoP  │   DNS │   TCP │   TLS │  TTFB │ Total │ Jitter │ Hops │ Latency Bar          │
├──────────────┼──────┼───────┼───────┼───────┼───────┼───────┼────────┼──────┼──────────────────────┤
│ Cloudflare   │ DEN  │ 17ms  │ 14ms  │ 17ms  │ 55ms  │ 102ms │  2ms   │   16 │ ████████████░░░░░░░░ │
│ Google       │ —    │ 16ms  │ 15ms  │ 27ms  │ 61ms  │ 120ms │  3ms   │   15 │ ██████████████░░░░░░ │
│ CloudFront   │ DEN  │ 35ms  │ 16ms  │ 19ms  │ 59ms  │ 131ms │ 24ms   │    — │ ████████████████░░░░ │
│ Akamai       │ —    │ 19ms  │ 29ms  │ 31ms  │125ms  │ 213ms │ 26ms   │   18 │ ████████████████████ │
└──────────────┴──────┴───────┴───────┴───────┴───────┴───────┴────────┴──────┴──────────────────────┘
```

## How It Works

### Measurement Phases

Each sample measures 5 phases independently using low-level timing (`time.perf_counter()`):

| Phase | Technique |
|---|---|
| **DNS** | `dnspython` async resolver, supports custom DNS server and IPv4/IPv6 filtering |
| **TCP** | `asyncio.open_connection()` to the resolved IP |
| **TLS** | `start_tls()` upgrade on the TCP connection (fallback to combined TCP+TLS) |
| **TTFB** | `httpx` streaming request — time from send to first response bytes |
| **Transfer** | Time from first byte to last byte of response body |

Each sample creates a **fresh connection** (no keepalive/reuse) to ensure independent measurements.

### PoP Detection

Each CDN provider uses a different method to identify the serving edge location:

| Provider | Method | Confidence |
|---|---|---|
| **Cloudflare** | `colo=XXX` in `/cdn-cgi/trace` response body | Confirmed |
| **CloudFront** | `x-amz-cf-pop` response header (e.g., `DFW55-C1`) | Confirmed |
| **Fastly** | `X-Served-By` header, trailing IATA code (e.g., `cache-dfw18681-DFW`) | Confirmed |
| **Akamai** | `X-Cache` header with debug Pragma headers | Unknown (best effort) |
| **Azure CDN** | `x-msedge-ref` header is opaque; uses IP geolocation | Inferred |
| **Google** | Reverse DNS of resolved IP (e.g., `dfw25s42-in-f4.1e100.net`) | Best effort |

### Network Path Tracing

Traces the route to each CDN's resolved IP address:

1. **Primary**: `icmplib.traceroute()` — pure Python, cross-platform
2. **Fallback**: System `/usr/sbin/traceroute -n` if ICMP permissions fail

For each hop IP, two concurrent DNS lookups are performed:
- **ASN info**: Team Cymru DNS (`<reversed-ip>.origin.asn.cymru.com` TXT record)
- **Reverse DNS**: PTR record lookup for hostname

Results are cached per-IP to avoid duplicate lookups when multiple providers share intermediate hops.

### Concurrency Model

- **Inter-provider**: All providers run concurrently via `asyncio.gather()`
- **Intra-provider**: Samples run sequentially with configurable delay (default 100ms)
- **Traceroute**: Runs concurrently for all providers after latency sampling completes
- **ASN/rDNS**: All hop lookups run concurrently within each trace

## Project Structure

```
cdnperf/
├── pyproject.toml          # Package config and dependencies
├── cdnperf/
│   ├── __init__.py         # Package version
│   ├── __main__.py         # python -m cdnperf entry point
│   ├── cli.py              # Click CLI, async orchestration
│   ├── config.py           # Constants, color thresholds
│   ├── models.py           # Dataclasses (TimingBreakdown, HopInfo, NetworkPath, etc.)
│   ├── engine.py           # Core async measurement (DNS/TCP/TLS/TTFB per-phase)
│   ├── trace.py            # Traceroute + Team Cymru ASN lookup + reverse DNS
│   ├── stats.py            # Statistical aggregation (min/avg/median/p95/stdev/jitter)
│   ├── location.py         # User IP geolocation via free APIs
│   ├── display.py          # Rich terminal output (tables, progress bars, path diagrams)
│   ├── export.py           # JSON/CSV export
│   ├── providers/
│   │   ├── __init__.py     # Provider registry
│   │   ├── base.py         # Abstract CDNProvider base class
│   │   ├── cloudflare.py
│   │   ├── cloudfront.py
│   │   ├── fastly.py
│   │   ├── akamai.py
│   │   ├── azure.py
│   │   └── google.py
│   └── data/
│       └── iata_codes.json # 319 IATA codes with city/country/coordinates
```

## Dependencies

| Package | Purpose |
|---|---|
| [httpx](https://www.python-httpx.org/) (with HTTP/2) | Async HTTP client for TTFB/Transfer measurement |
| [dnspython](https://www.dnspython.org/) | Async DNS resolution, PTR lookups, Team Cymru ASN queries |
| [rich](https://rich.readthedocs.io/) | Terminal tables, progress bars, live display, color coding |
| [click](https://click.palletsprojects.com/) | CLI argument parsing |
| [icmplib](https://github.com/ValentinBELYN/icmplib) | Cross-platform traceroute with unprivileged ICMP fallback |

## Error Handling

cdnperf is designed to degrade gracefully:

- **Timeouts**: Excluded from stats; provider marked "unreachable" if all samples fail
- **DNS failures**: Remaining phases skipped for that sample
- **Rate limiting (429)**: Backs off once (2s), then marks as rate-limited
- **TLS issues**: Falls back to combined TCP+TLS timing
- **Traceroute permissions**: Tries `icmplib` first, falls back to system `traceroute`
- **ASN lookup failures**: Hop shown without ASN info
- **Proxy detection**: Warns if `HTTP_PROXY`/`HTTPS_PROXY` env vars are set
- A single provider failure never crashes the entire run
