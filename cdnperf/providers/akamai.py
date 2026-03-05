"""Akamai CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class AkamaiProvider(CDNProvider):
    """Akamai detection via debug headers.

    Akamai requires special ``Pragma`` headers to expose cache/edge
    information.  The ``X-Cache`` response header may contain an edge
    hostname from which a PoP code can sometimes be extracted, but
    reliable PoP detection is generally not possible from headers
    alone, so the confidence level is typically ``"unknown"``.
    """

    @property
    def name(self) -> str:
        return "Akamai"

    @property
    def slug(self) -> str:
        return "akamai"

    @property
    def probe_url(self) -> str:
        return "https://www.akamai.com/favicon.ico"

    @property
    def extra_headers(self) -> dict[str, str]:
        return {
            "Pragma": (
                "akamai-x-cache-on, "
                "akamai-x-cache-remote-on, "
                "akamai-x-get-true-cache-key"
            ),
        }

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        x_cache = response.headers.get("x-cache", "")
        if x_cache:
            # Akamai x-cache may contain edge hostname like
            # "TCP_HIT from a23-45-67-89.deploy.akamaitechnologies.com"
            match = re.search(
                r"\b([a-z]{3})\d*\.\w+\.akamaitechnologies\.com\b",
                x_cache, re.IGNORECASE,
            )
            if not match:
                match = re.search(
                    r"\b([a-z]{3})\d*\.\w+\.akamaiedge\.net\b",
                    x_cache, re.IGNORECASE,
                )
            if match:
                return PoPIdentity(
                    code=match.group(1).upper(),
                    confidence="best_effort",
                    raw_header=x_cache,
                )

        # server-timing may contain "cdn-cache; desc=HIT, edge; dur=10"
        server_timing = response.headers.get("server-timing", "")
        if server_timing and "cdn-cache" in server_timing:
            return PoPIdentity(
                confidence="best_effort",
                raw_header=server_timing,
            )

        return PoPIdentity(confidence="unknown", raw_header=x_cache or None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("x-cache", "x-cache-key", "x-true-cache-key", "server-timing"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
