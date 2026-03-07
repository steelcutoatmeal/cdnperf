"""KeyCDN provider."""

from __future__ import annotations

import re

import httpx

from cdnprobe.models import PoPIdentity
from cdnprobe.providers.base import CDNProvider


class KeyCDNProvider(CDNProvider):
    """KeyCDN detection via the ``x-edge-location`` response header.

    KeyCDN exposes the serving edge PoP via the ``x-edge-location``
    header, which contains a location identifier like ``fran`` (Frankfurt)
    or ``lond`` (London).
    """

    @property
    def name(self) -> str:
        return "KeyCDN"

    @property
    def slug(self) -> str:
        return "keycdn"

    @property
    def probe_url(self) -> str:
        return "https://www.keycdn.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        edge_loc = response.headers.get("x-edge-location", "")
        if edge_loc:
            # KeyCDN uses short location names (e.g. "fran", "lond")
            # not standard IATA codes, but we record them as-is
            code = edge_loc.strip().upper()[:4]
            return PoPIdentity(
                code=code,
                confidence="inferred",
                raw_header=edge_loc,
            )
        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cache", "x-edge-location", "x-shield"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
