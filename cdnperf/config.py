"""Constants and configuration for cdnperf."""

# Latency color thresholds (milliseconds)
FAST_THRESHOLD_MS = 20.0    # Green: <= 20ms
MEDIUM_THRESHOLD_MS = 50.0  # Yellow: <= 50ms
# Red: > 50ms

# Phase-specific thresholds for color coding
PHASE_THRESHOLDS = {
    "dns": {"fast": 5.0, "medium": 20.0},
    "tcp": {"fast": 10.0, "medium": 30.0},
    "tls": {"fast": 20.0, "medium": 50.0},
    "ttfb": {"fast": 30.0, "medium": 80.0},
    "total": {"fast": 50.0, "medium": 150.0},
}

# Default measurement settings
DEFAULT_SAMPLES = 5
DEFAULT_WARMUP = 1
DEFAULT_DELAY_MS = 100
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_HOPS = 30

# Traceroute settings
TRACE_PROBES_PER_HOP = 3
TRACE_HOP_TIMEOUT = 2.0

# ASN lookup DNS zones
CYMRU_ORIGIN_ZONE = "origin.asn.cymru.com"
CYMRU_PEER_ZONE = "peer.asn.cymru.com"

# Geolocation API fallback chain
GEO_APIS = [
    "https://ipinfo.io/json",
    "https://ipapi.co/json/",
    "http://ip-api.com/json/?fields=status,message,query,city,regionName,country,lat,lon,isp,org,as",
]

# User agent for HTTP requests
USER_AGENT = "cdnperf/0.1.0"

# Phase display names
PHASE_NAMES = ["dns", "tcp", "tls", "ttfb", "total"]
PHASE_LABELS = {
    "dns": "DNS",
    "tcp": "TCP",
    "tls": "TLS",
    "ttfb": "TTFB",
    "transfer": "Transfer",
    "total": "Total",
}
