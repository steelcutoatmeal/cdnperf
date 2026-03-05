"""CDN77 provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class CDN77Provider(CDNProvider):
    """CDN77 detection via the ``x-77-pop`` and ``x-cache`` headers.

    CDN77 may expose the serving PoP code in the ``x-77-pop`` header
    or in the ``x-cache`` header which can contain PoP identifiers.
    """

    @property
    def name(self) -> str:
        return "CDN77"

    @property
    def slug(self) -> str:
        return "cdn77"

    @property
    def probe_url(self) -> str:
        return "https://www.cdn77.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        # CDN77 uses x-77-pop or embeds PoP info in x-cache
        pop_header = response.headers.get("x-77-pop", "")
        if pop_header:
            code = pop_header.strip().upper()
            if len(code) >= 3:
                return PoPIdentity(
                    code=code[:3],
                    confidence="confirmed",
                    raw_header=pop_header,
                )

        x_cache = response.headers.get("x-cache", "")
        if x_cache:
            match = re.search(r"\b([A-Z]{3})\b", x_cache)
            if match:
                return PoPIdentity(
                    code=match.group(1),
                    confidence="inferred",
                    raw_header=x_cache,
                )

        return PoPIdentity(confidence="unknown", raw_header=pop_header or x_cache or None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cache", "x-77-pop", "x-77-cache", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
