"""Fastly CDN provider."""

from __future__ import annotations

import re

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class FastlyProvider(CDNProvider):
    """Fastly detection via the ``X-Served-By`` response header.

    The header contains cache node identifiers such as
    ``cache-dfw18681-DFW``.  When shielding is active, multiple
    comma-separated entries may be present; the *last* entry is the
    edge node closest to the client.  The trailing 3-letter suffix
    (after the final hyphen) is the IATA code.
    """

    @property
    def name(self) -> str:
        return "Fastly"

    @property
    def slug(self) -> str:
        return "fastly"

    @property
    def probe_url(self) -> str:
        return "https://www.fastly.com/"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        raw = response.headers.get("x-served-by", "")
        if raw:
            # Take the last entry (edge closest to client) when shielding
            # produces multiple comma-separated values.
            entries = [e.strip() for e in raw.split(",")]
            last_entry = entries[-1]
            match = re.search(r"-([A-Z]{3})$", last_entry)
            if match:
                return PoPIdentity(
                    code=match.group(1),
                    confidence="confirmed",
                    raw_header=raw,
                )
        return PoPIdentity(confidence="unknown", raw_header=raw or None)

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("x-cache", "x-cache-hits", "x-served-by"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
