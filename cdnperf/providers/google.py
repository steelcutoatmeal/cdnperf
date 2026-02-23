"""Google Global Cache / CDN provider."""

from __future__ import annotations

import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider


class GoogleProvider(CDNProvider):
    """Google CDN detection via the ``/generate_204`` endpoint.

    Google does not expose PoP information in response headers.
    The actual edge location must be determined by reverse DNS
    lookup on the resolved IP address (handled elsewhere).  The
    confidence level is ``"best_effort"`` to reflect this limitation.
    """

    @property
    def name(self) -> str:
        return "Google"

    @property
    def slug(self) -> str:
        return "google"

    @property
    def probe_url(self) -> str:
        return "https://www.google.com/generate_204"

    def detect_pop(self, response: httpx.Response) -> PoPIdentity:
        # Google does not expose PoP details in response headers.
        # Reverse DNS of the resolved IP (e.g. dfw25s42-in-f4.1e100.net)
        # can reveal the IATA code, but that happens in a separate step.
        return PoPIdentity(confidence="best_effort")

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "alt-svc"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
