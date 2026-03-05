"""Blazing CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class BlazingCDNProvider(CDNProvider):
    """Blazing CDN detection via response headers.

    BlazingCDN does not expose PoP identity in response headers.
    Detection relies on server and cache-related headers.
    """

    @property
    def name(self) -> str:
        return "Blazing CDN"

    @property
    def slug(self) -> str:
        return "blazingcdn"

    @property
    def probe_url(self) -> str:
        return "https://panel.blazingcdn.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        cdn_host = response.headers.get("x-cdn-host-id", "")
        if cdn_host:
            return PoPIdentity(confidence="inferred", raw_header=cdn_host)
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-proxy-cache", "x-cdn-host-id", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
