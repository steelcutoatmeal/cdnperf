"""CDNetworks CDN provider."""

from __future__ import annotations

import httpx

from cdnprobe.models import PoPIdentity
from cdnprobe.providers.base import CDNProvider


class CDNetworksProvider(CDNProvider):
    """CDNetworks detection via response headers.

    CDNetworks is a major Asia-Pacific CDN with 2,800+ PoPs.
    It exposes cache status via standard ``x-cache`` and ``via``
    headers.  PoP detection relies on these headers where available.
    """

    @property
    def name(self) -> str:
        return "CDNetworks"

    @property
    def slug(self) -> str:
        return "cdnetworks"

    @property
    def probe_url(self) -> str:
        return "https://www.cdnetworks.com/favicon.ico"

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
        for header in ("server", "x-cache", "x-cdn", "via", "x-powered-by"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
