"""Alibaba Cloud CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class AlibabaProvider(CDNProvider):
    """Alibaba Cloud CDN detection via response headers.

    Alibaba Cloud CDN exposes edge information through the
    ``eagleid`` and ``via`` response headers.  The ``eagleid``
    header may contain a PoP identifier prefix.
    """

    @property
    def name(self) -> str:
        return "Alibaba Cloud"

    @property
    def slug(self) -> str:
        return "alibaba"

    @property
    def probe_url(self) -> str:
        return "https://www.alibabacloud.com/"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        eagleid = response.headers.get("eagleid", "")
        if eagleid:
            return PoPIdentity(
                confidence="inferred",
                raw_header=eagleid,
            )

        via = response.headers.get("via", "")
        if via:
            # Via header may contain cache node identifiers
            match = re.search(r"\b([a-z]{3})\d+\.", via, re.IGNORECASE)
            if match:
                return PoPIdentity(
                    code=match.group(1).upper(),
                    confidence="inferred",
                    raw_header=via,
                )

        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "eagleid", "x-cache", "via", "x-swift-cachetime"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
