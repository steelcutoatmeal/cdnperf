"""Tencent Cloud CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class TencentProvider(CDNProvider):
    """Tencent Cloud CDN detection via response headers.

    Tencent Cloud CDN uses a proprietary NWS node architecture.
    Cache status is exposed via the ``x-cache-lookup`` header
    (e.g., ``Hit From MemCache``, ``Hit From Disktank``).
    The ``x-nws-log-uuid`` header may also be present.
    """

    @property
    def name(self) -> str:
        return "Tencent Cloud"

    @property
    def slug(self) -> str:
        return "tencent"

    @property
    def probe_url(self) -> str:
        return "https://www.tencentcloud.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        nws_uuid = response.headers.get("x-nws-log-uuid", "")
        if nws_uuid:
            return PoPIdentity(
                confidence="inferred",
                raw_header=nws_uuid,
            )
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in (
            "server", "x-cache-lookup", "x-nws-log-uuid",
            "x-cache", "via", "x-daa-tunnel",
        ):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
