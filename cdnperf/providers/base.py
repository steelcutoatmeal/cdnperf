"""Abstract base class for CDN providers."""

from __future__ import annotations

import abc
from typing import Optional

import httpx

from cdnperf.models import PoPIdentity


class CDNProvider(abc.ABC):
    """Base class that each CDN provider must implement."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable provider name (e.g. 'Cloudflare')."""

    @property
    @abc.abstractmethod
    def slug(self) -> str:
        """Short identifier (e.g. 'cloudflare')."""

    @property
    @abc.abstractmethod
    def probe_url(self) -> str:
        """URL used for latency probing and PoP detection."""

    @property
    def extra_headers(self) -> dict[str, str]:
        """Extra headers to send with the probe request."""
        return {}

    @abc.abstractmethod
    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        """Extract PoP identity from the probe response.

        Implementations should parse headers/body and return a PoPIdentity
        with at least the `code` field set if detection succeeds.
        """

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        """Extract additional metadata from the response (cache status, etc.)."""
        return {}
