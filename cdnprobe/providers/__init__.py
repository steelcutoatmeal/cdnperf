"""CDN provider registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cdnprobe.providers.base import CDNProvider

_PROVIDER_MAP: dict[str, type[CDNProvider]] | None = None


def _load_providers() -> dict[str, type[CDNProvider]]:
    from cdnprobe.providers.akamai import AkamaiProvider
    from cdnprobe.providers.alibaba import AlibabaProvider
    from cdnprobe.providers.azure import AzureProvider
    from cdnprobe.providers.belugacdn import BelugaCDNProvider
    from cdnprobe.providers.blazingcdn import BlazingCDNProvider
    from cdnprobe.providers.bunny import BunnyProvider
    from cdnprobe.providers.byteplus import BytePlusProvider
    from cdnprobe.providers.cachefly import CacheFlyProvider
    from cdnprobe.providers.cdn77 import CDN77Provider
    from cdnprobe.providers.cdnetworks import CDNetworksProvider
    from cdnprobe.providers.cloudflare import CloudflareProvider
    from cdnprobe.providers.cloudfront import CloudFrontProvider
    from cdnprobe.providers.edgenext import EdgeNextProvider
    from cdnprobe.providers.fastly import FastlyProvider
    from cdnprobe.providers.gcore import GcoreProvider
    from cdnprobe.providers.google import GoogleProvider
    from cdnprobe.providers.imperva import ImpervaProvider
    from cdnprobe.providers.keycdn import KeyCDNProvider
    from cdnprobe.providers.kingsoft import KingsoftProvider
    from cdnprobe.providers.medianova import MedianovaProvider
    from cdnprobe.providers.quiccloud import QuicCloudProvider
    from cdnprobe.providers.sucuri import SucuriProvider
    from cdnprobe.providers.tencent import TencentProvider

    return {
        "cloudflare": CloudflareProvider,
        "cloudfront": CloudFrontProvider,
        "fastly": FastlyProvider,
        "akamai": AkamaiProvider,
        "azure": AzureProvider,
        "google": GoogleProvider,
        "blazingcdn": BlazingCDNProvider,
        "gcore": GcoreProvider,
        "imperva": ImpervaProvider,
        "cachefly": CacheFlyProvider,
        "keycdn": KeyCDNProvider,
        "cdn77": CDN77Provider,
        "sucuri": SucuriProvider,
        "bunny": BunnyProvider,
        "alibaba": AlibabaProvider,
        "belugacdn": BelugaCDNProvider,
        "cdnetworks": CDNetworksProvider,
        "tencent": TencentProvider,
        "byteplus": BytePlusProvider,
        "kingsoft": KingsoftProvider,
        "medianova": MedianovaProvider,
        "edgenext": EdgeNextProvider,
        "quiccloud": QuicCloudProvider,
    }


def get_provider_map() -> dict[str, type[CDNProvider]]:
    """Return the mapping of slug → provider class, loading lazily."""
    global _PROVIDER_MAP
    if _PROVIDER_MAP is None:
        _PROVIDER_MAP = _load_providers()
    return _PROVIDER_MAP


def get_provider(slug: str) -> CDNProvider:
    """Instantiate a provider by slug."""
    pmap = get_provider_map()
    if slug not in pmap:
        raise ValueError(f"Unknown provider: {slug!r}. Available: {list(pmap)}")
    return pmap[slug]()


def list_providers() -> list[str]:
    """Return sorted list of available provider slugs."""
    return sorted(get_provider_map())


def create_generic_provider(url: str) -> CDNProvider:
    """Create a :class:`GenericProvider` for a custom probe URL.

    This is not registered in the static provider map — it is created
    dynamically when the user passes ``--url``.
    """
    from cdnprobe.providers.generic import GenericProvider

    return GenericProvider(url)
