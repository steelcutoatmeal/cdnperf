"""Cloudflare CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class CloudflareProvider(CDNProvider):
    """Cloudflare detection via the /cdn-cgi/trace endpoint.

    The trace endpoint returns a plain-text body with key=value pairs
    including ``colo`` (the 3-letter IATA code of the serving PoP).
    """

    @property
    def name(self) -> str:
        return "Cloudflare"

    @property
    def slug(self) -> str:
        return "cloudflare"

    @property
    def probe_url(self) -> str:
        return "https://speed.cloudflare.com/cdn-cgi/trace"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        body = response.text
        match = re.search(r"^colo=([A-Z]{3})$", body, re.MULTILINE)
        if match:
            return PoPIdentity(
                code=match.group(1),
                confidence="confirmed",
                raw_header=match.group(0),
            )
        return PoPIdentity(confidence="unknown", raw_header=body[:200])

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        body = response.text
        for key in ("tls", "http", "loc", "warp"):
            match = re.search(rf"^{key}=(.+)$", body, re.MULTILINE)
            if match:
                metadata[key] = match.group(1).strip()
        return metadata
