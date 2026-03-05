"""QUIC.cloud CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class QuicCloudProvider(CDNProvider):
    """QUIC.cloud CDN detection via the ``x-qc-pop`` response header.

    QUIC.cloud is the only CDN that caches both static and dynamic
    WordPress content, built by LiteSpeed Technologies.  It uses
    native HTTP/3 (QUIC protocol) and exposes PoP identity via
    the ``x-qc-pop`` header and cache status via ``x-qc-cache``.
    """

    @property
    def name(self) -> str:
        return "QUIC.cloud"

    @property
    def slug(self) -> str:
        return "quiccloud"

    @property
    def probe_url(self) -> str:
        return "https://www.quic.cloud/favicon.ico"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        qc_pop = response.headers.get("x-qc-pop", "")
        if qc_pop:
            code = qc_pop.strip().upper()
            return PoPIdentity(
                code=code if len(code) >= 3 else None,
                confidence="confirmed",
                raw_header=qc_pop,
            )
        return PoPIdentity(confidence="unknown")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "x-qc-pop", "x-qc-cache", "x-cache", "x-litespeed-cache"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
