"""Imperva (formerly Incapsula) CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class ImpervaProvider(CDNProvider):
    """Imperva CDN detection via the ``x-iinfo`` and ``x-cdn`` headers.

    Imperva (formerly Incapsula) proxies traffic through its global
    network of PoPs.  The ``x-iinfo`` header contains internal routing
    metadata but does not directly expose a PoP IATA code.
    """

    @property
    def name(self) -> str:
        return "Imperva"

    @property
    def slug(self) -> str:
        return "imperva"

    @property
    def probe_url(self) -> str:
        return "https://www.imperva.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        x_iinfo = response.headers.get("x-iinfo", "")
        x_cdn = response.headers.get("x-cdn", "")
        raw = x_iinfo or x_cdn or None
        if x_iinfo or x_cdn:
            return PoPIdentity(
                confidence="inferred",
                raw_header=raw,
            )
        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("x-iinfo", "x-cdn", "x-cache", "server", "x-incap-sess"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
