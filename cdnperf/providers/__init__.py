"""CDN provider registry."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cdnperf.providers.base import CDNProvider

_PROVIDER_MAP: dict[str, type[CDNProvider]] | None = None


def _load_providers() -> dict[str, type[CDNProvider]]:
    from cdnperf.providers.akamai import AkamaiProvider
    from cdnperf.providers.azure import AzureProvider
    from cdnperf.providers.cloudflare import CloudflareProvider
    from cdnperf.providers.cloudfront import CloudFrontProvider
    from cdnperf.providers.fastly import FastlyProvider
    from cdnperf.providers.google import GoogleProvider

    return {
        "cloudflare": CloudflareProvider,
        "cloudfront": CloudFrontProvider,
        "fastly": FastlyProvider,
        "akamai": AkamaiProvider,
        "azure": AzureProvider,
        "google": GoogleProvider,
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
    from cdnperf.providers.generic import GenericProvider

    return GenericProvider(url)
