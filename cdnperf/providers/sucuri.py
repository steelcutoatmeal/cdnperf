"""Sucuri CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class SucuriProvider(CDNProvider):
    """Sucuri CDN detection via the ``x-sucuri-id`` and ``x-sucuri-cache`` headers.

    Sucuri's Website Firewall and CDN proxy traffic through their
    global Anycast network.  The ``x-sucuri-id`` header contains
    internal routing info but no standard IATA code.
    """

    @property
    def name(self) -> str:
        return "Sucuri"

    @property
    def slug(self) -> str:
        return "sucuri"

    @property
    def probe_url(self) -> str:
        return "https://sucuri.net/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        sucuri_id = response.headers.get("x-sucuri-id", "")
        if sucuri_id:
            return PoPIdentity(
                confidence="inferred",
                raw_header=sucuri_id,
            )
        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-sucuri-id", "x-sucuri-cache", "x-cache"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
