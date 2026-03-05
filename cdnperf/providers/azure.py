"""Azure CDN (Azure Front Door) provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class AzureProvider(CDNProvider):
    """Azure Front Door detection via the ``x-msedge-ref`` response header.

    The ``x-msedge-ref`` header contains a ``Ref B:`` field with an
    encoded edge node identifier (e.g. ``CO1EDGE2922``) from which a
    3-letter PoP code can sometimes be extracted.

    Note: ``www.microsoft.com`` is served by Fastly, not Azure.
    ``www.bing.com`` is served by Azure Front Door.
    """

    @property
    def name(self) -> str:
        return "Azure CDN"

    @property
    def slug(self) -> str:
        return "azure"

    @property
    def probe_url(self) -> str:
        return "https://www.bing.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        raw = response.headers.get("x-msedge-ref", "")
        if raw:
            # Extract edge node from "Ref B: CO1EDGE2922" pattern
            match = re.search(r"Ref B:\s*([A-Z]{2,3})\w*EDGE", raw)
            if match:
                return PoPIdentity(
                    code=match.group(1),
                    confidence="inferred",
                    raw_header=raw,
                )
            return PoPIdentity(
                confidence="inferred",
                raw_header=raw,
            )
        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("x-msedge-ref", "x-cache", "x-azure-ref", "x-cdn-traceid"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
