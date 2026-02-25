"""Google Global Cache / CDN provider."""

from __future__ import annotations

import logging
import re
from typing import Optional

import dns.asyncresolver
import dns.reversename
import httpx

from cdnperf.models import PoPIdentity
from cdnperf.providers.base import CDNProvider

logger = logging.getLogger(__name__)

# Pattern: 3-letter IATA prefix from Google rDNS hostnames like
# "dfw25s42-in-f4.1e100.net" or "lhr48s27-in-f14.1e100.net"
_GOOGLE_RDNS_RE = re.compile(r"^([a-z]{3})\d+s\d+-in-", re.IGNORECASE)


class GoogleProvider(CDNProvider):
    """Google CDN detection via the ``/generate_204`` endpoint.

    Google does not expose PoP information in response headers.
    The actual edge location is determined by reverse DNS lookup on the
    resolved IP address (e.g. ``dfw25s42-in-f4.1e100.net`` -> ``DFW``).
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
        # can reveal the IATA code, but that happens via detect_pop_by_ip.
        return PoPIdentity(confidence="best_effort")

    async def detect_pop_by_ip(self, ip: str) -> Optional[PoPIdentity]:
        """Detect Google PoP via reverse DNS of the resolved IP.

        Google edge IPs typically resolve to hostnames like
        ``dfw25s42-in-f4.1e100.net`` where the first 3 letters are
        the IATA airport code of the PoP.
        """
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = 3.0
            rev_name = dns.reversename.from_address(ip)
            answers = await resolver.resolve(rev_name, "PTR")
            hostname = str(answers[0]).rstrip(".")

            match = _GOOGLE_RDNS_RE.match(hostname)
            if match:
                iata_code = match.group(1).upper()
                return PoPIdentity(
                    code=iata_code,
                    confidence="inferred",
                    raw_header=hostname,
                )
        except Exception:
            logger.debug("Google rDNS PoP detection failed for %s", ip)

        return None

    def extract_metadata(self, response: httpx.Response) -> dict[str, str]:
        metadata: dict[str, str] = {}
        for header in ("server", "alt-svc"):
            value = response.headers.get(header)
            if value:
                metadata[header] = value
        return metadata
