"""Beluga CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class BelugaCDNProvider(CDNProvider):
    """Beluga CDN detection via response headers.

    BelugaCDN is a smaller CDN provider with 28+ PoPs.
    It does not expose detailed PoP identity in response headers,
    so detection relies on generic cache and server headers.
    """

    @property
    def name(self) -> str:
        return "Beluga CDN"

    @property
    def slug(self) -> str:
        return "belugacdn"

    @property
    def probe_url(self) -> str:
        return "https://www.belugacdn.com/"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cache", "x-cdn", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
