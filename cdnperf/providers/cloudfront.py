"""Amazon CloudFront CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class CloudFrontProvider(CDNProvider):
    """CloudFront detection via the ``x-amz-cf-pop`` response header.

    The header value looks like ``DFW55-C1`` where the first 3 characters
    are the IATA airport code of the edge location.
    """

    @property
    def name(self) -> str:
        return "CloudFront"

    @property
    def slug(self) -> str:
        return "cloudfront"

    @property
    def probe_url(self) -> str:
        return "https://d1.awsstatic.com/"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        raw = response.headers.get("x-amz-cf-pop", "")
        if raw:
            match = re.match(r"^([A-Z]{3})", raw)
            if match:
                return PoPIdentity(
                    code=match.group(1),
                    confidence="confirmed",
                    raw_header=raw,
                )
        return PoPIdentity(confidence="unknown", raw_header=raw or None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        x_cache = response.headers.get("x-cache")
        if x_cache:
            metadata["x-cache"] = x_cache
        return metadata
