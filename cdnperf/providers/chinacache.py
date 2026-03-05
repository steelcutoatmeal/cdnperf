"""ChinaCache CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class ChinaCacheProvider(CDNProvider):
    """ChinaCache CDN detection via response headers.

    ChinaCache, founded in 1998 and publicly traded on NASDAQ (CCIH),
    is the first CDN in China.  It specializes in content delivery
    within mainland China and to global audiences.
    """

    @property
    def name(self) -> str:
        return "ChinaCache"

    @property
    def slug(self) -> str:
        return "chinacache"

    @property
    def probe_url(self) -> str:
        return "https://en.chinacache.com/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        powered_by = response.headers.get("x-powered-by", "")
        if powered_by and "chinacache" in powered_by.lower():
            return PoPIdentity(
                confidence="inferred",
                raw_header=powered_by,
            )
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cache", "x-powered-by", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
