"""Generic provider for custom probe URLs (``--url``)."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class GenericProvider(CDNProvider):
    """A generic provider that probes an arbitrary URL.

    Used when the user supplies ``--url`` to measure a custom endpoint
    that is not one of the built-in CDN providers.  PoP detection always
    returns ``confidence="unknown"`` since there is no provider-specific
    header parsing.
    """

    def __init__(self, url: str) -> None:
        self._url = url

    @property
    def name(self) -> str:
        return "Custom"

    @property
    def slug(self) -> str:
        return "custom"

    @property
    def probe_url(self) -> str:
        return self._url

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-cache", "cf-cache-status", "x-cdn-cache", "via"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
