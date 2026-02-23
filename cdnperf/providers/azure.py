"""Azure CDN (Microsoft Edge Network) provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class AzureProvider(CDNProvider):
    """Azure CDN detection via the ``x-msedge-ref`` response header.

    The ``x-msedge-ref`` value is an opaque, Base64-style encoded
    string that does not directly expose a PoP code.  The raw header
    is preserved so that IP-based geolocation can infer the serving
    edge location in a later processing step.
    """

    @property
    def name(self) -> str:
        return "Azure CDN"

    @property
    def slug(self) -> str:
        return "azure"

    @property
    def probe_url(self) -> str:
        return "https://www.microsoft.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        raw = response.headers.get("x-msedge-ref", "")
        if raw:
            return PoPIdentity(
                confidence="inferred",
                raw_header=raw,
            )
        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("x-msedge-ref", "x-cache", "x-azure-ref"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
