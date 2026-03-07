"""Bunny.net CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnprobe.models import PoPIdentity
from cdnprobe.providers.base import CDNProvider


class BunnyProvider(CDNProvider):
    """Bunny.net CDN detection via the ``CDN-PullZone`` and ``server`` headers.

    Bunny.net identifies itself via ``server: BunnyCDN`` and exposes
    cache information in the ``cdn-cache`` and ``cdn-cachedat`` headers.
    The ``cdn-proxyver`` and ``cdn-requestpull`` headers may also be present.
    PoP location can sometimes be inferred from the ``cdn-edgestorageid``
    or ``cdn-requestid`` headers.
    """

    @property
    def name(self) -> str:
        return "Bunny.net"

    @property
    def slug(self) -> str:
        return "bunny"

    @property
    def probe_url(self) -> str:
        return "https://bunny.net/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        # Bunny.net may expose PoP info in cdn-requestid or similar headers
        req_id = response.headers.get("cdn-requestid", "")
        if req_id:
            # cdn-requestid may contain PoP prefix like "DE-FRA-..."
            match = re.match(r"^([A-Z]{2})-([A-Z]{3})-", req_id)
            if match:
                return PoPIdentity(
                    code=match.group(2),
                    confidence="inferred",
                    raw_header=req_id,
                )

        return PoPIdentity(confidence="unknown", raw_header=req_id or None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in (
            "server", "cdn-cache", "cdn-cachedat", "cdn-pullzone",
            "cdn-requestid", "cdn-proxyver", "cdn-uid",
        ):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
