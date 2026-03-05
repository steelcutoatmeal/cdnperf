"""Alibaba Cloud CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class AlibabaProvider(CDNProvider):
    """Alibaba Cloud CDN detection via response headers.

    Alibaba Cloud CDN (Tengine-based) exposes edge information through
    ``via`` headers containing ``ens-cache`` node identifiers and
    ``x-cache`` headers.  Assets on ``img.alicdn.com`` are served
    directly by Alibaba CDN infrastructure.

    Note: ``www.alibabacloud.com`` is fronted by Akamai, not Alibaba CDN.
    """

    @property
    def name(self) -> str:
        return "Alibaba Cloud"

    @property
    def slug(self) -> str:
        return "alibaba"

    @property
    def probe_url(self) -> str:
        return "https://img.alicdn.com/tfs/TB1_uT8a5ERMeJjSspiXXbZLFXa-143-59.png"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        via = response.headers.get("via", "")
        if via:
            # Alibaba CDN via headers contain cache node IDs like
            # "ens-cache29.l2us4[231,230,404-1280,M]" where "us4"
            # indicates the region.
            match = re.search(r"ens-cache\d+\.l2?([a-z]{2}\d+)", via, re.IGNORECASE)
            if match:
                return PoPIdentity(
                    confidence="inferred",
                    raw_header=via,
                )
            return PoPIdentity(
                confidence="inferred",
                raw_header=via,
            )

        eagleid = response.headers.get("eagleid", "")
        if eagleid:
            return PoPIdentity(
                confidence="inferred",
                raw_header=eagleid,
            )

        return PoPIdentity(confidence="unknown", raw_header=None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "eagleid", "x-cache", "via", "x-swift-cachetime", "x-swift-savetime"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
