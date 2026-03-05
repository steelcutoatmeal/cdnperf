"""Medianova CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class MedianovaProvider(CDNProvider):
    """Medianova CDN detection via the ``x-cdn`` response header.

    Medianova is a Turkey/EMEA-focused CDN specializing in streaming
    and video delivery.  When enabled, the ``x-cdn`` header confirms
    content is served from Medianova's edge servers.  CDN Planet's
    performance checker can also extract PoP identifiers from
    Medianova response headers.
    """

    @property
    def name(self) -> str:
        return "Medianova"

    @property
    def slug(self) -> str:
        return "medianova"

    @property
    def probe_url(self) -> str:
        return "https://www.medianova.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        x_cdn = response.headers.get("x-cdn", "")
        if x_cdn:
            return PoPIdentity(
                confidence="inferred",
                raw_header=x_cdn,
            )
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cdn", "x-cache", "x-cache-status", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
