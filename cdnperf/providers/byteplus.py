"""BytePlus CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class BytePlusProvider(CDNProvider):
    """BytePlus CDN detection via response headers.

    BytePlus (ByteDance/TikTok's cloud CDN) has 1,300+ PoPs
    with a focus on high-performance video delivery.  Edge nodes
    pass through standard cache headers by default.
    """

    @property
    def name(self) -> str:
        return "BytePlus"

    @property
    def slug(self) -> str:
        return "byteplus"

    @property
    def probe_url(self) -> str:
        return "https://www.byteplus.com/"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        via = response.headers.get("via", "")
        if via:
            return PoPIdentity(
                confidence="inferred",
                raw_header=via,
            )
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cache", "x-response-cache", "via", "x-tt-trace-tag"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
