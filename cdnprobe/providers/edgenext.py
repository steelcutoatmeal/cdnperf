"""EdgeNext CDN provider."""

from __future__ import annotations

import httpx

from cdnprobe.models import PoPIdentity
from cdnprobe.providers.base import CDNProvider


class EdgeNextProvider(CDNProvider):
    """EdgeNext CDN detection via response headers.

    EdgeNext is a growing Asia-focused CDN with 1,700+ PoPs across
    34 countries, with strong presence in APAC, China, MENA, and
    North America.
    """

    @property
    def name(self) -> str:
        return "EdgeNext"

    @property
    def slug(self) -> str:
        return "edgenext"

    @property
    def probe_url(self) -> str:
        return "https://www.edgenext.com/favicon.ico"

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
        for header in ("server", "x-cache", "x-cdn", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
