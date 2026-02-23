"""Core measurement engine for cdnperf.

Measures five connection phases independently:
  DNS -> TCP -> TLS -> TTFB -> Transfer

Each phase is timed with time.perf_counter() for monotonic,
high-resolution measurements.

Public API:
    measure_provider  -- run all samples for a single CDN provider
    measure_all       -- run measurements for all providers concurrently
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from typing import Callable, Optional
from urllib.parse import urlparse

import dns.asyncresolver
import dns.rdatatype
import httpx

from cdnperf.config import USER_AGENT
from cdnperf.models import (
    MeasurementConfig,
    PoPIdentity,
    ProviderResult,
    SampleResult,
    TimingBreakdown,
)
from cdnperf.providers import get_provider, get_provider_map
from cdnperf.providers.base import CDNProvider
from cdnperf.stats import aggregate_provider_stats

logger = logging.getLogger(__name__)

# Type alias for the progress callback.
# Signature: (provider_slug, sample_index, total_samples, sample_result_or_none)
ProgressCallback = Callable[[str, int, int, Optional[SampleResult]], None]

# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

async def _resolve_dns(
    hostname: str,
    config: MeasurementConfig,
) -> tuple[str, float]:
    """Resolve *hostname* via dnspython and return (ip, elapsed_ms).

    Respects ``config.dns_server``, ``config.ipv4_only`` and
    ``config.ipv6_only``.  Falls back from AAAA to A (or vice-versa) when
    the preferred record type yields no results.

    Raises
    ------
    dns.exception.DNSException
        On resolution failure (caller catches and records the error).
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = config.timeout

    if config.dns_server:
        resolver.nameservers = [config.dns_server]

    # Choose record type based on address-family preference.
    if config.ipv6_only:
        rdtypes = [dns.rdatatype.AAAA]
    elif config.ipv4_only:
        rdtypes = [dns.rdatatype.A]
    else:
        # Prefer A, fall back to AAAA.
        rdtypes = [dns.rdatatype.A, dns.rdatatype.AAAA]

    last_error: Exception | None = None
    for rdtype in rdtypes:
        try:
            t0 = time.perf_counter()
            answer = await resolver.resolve(hostname, rdtype)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            ip = str(answer[0])
            return ip, round(elapsed_ms, 3)
        except Exception as exc:
            last_error = exc
            continue

    # All record types failed -- propagate the last error.
    raise last_error  # type: ignore[misc]


# ---------------------------------------------------------------------------
# TCP connect
# ---------------------------------------------------------------------------

async def _measure_tcp(
    ip: str,
    port: int,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter, float]:
    """Open a raw TCP connection to *ip*:*port* and return (reader, writer, ms).

    The caller is responsible for closing the writer when done.
    """
    t0 = time.perf_counter()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port),
        timeout=timeout,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return reader, writer, round(elapsed_ms, 3)


# ---------------------------------------------------------------------------
# TLS upgrade
# ---------------------------------------------------------------------------

def _build_ssl_context(hostname: str) -> ssl.SSLContext:
    """Build a standard SSL context that validates the server certificate."""
    ctx = ssl.create_default_context()
    # server_hostname is set when the context is used, not here.
    return ctx


async def _measure_tls(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    hostname: str,
    timeout: float,
) -> tuple[float, Optional[str]]:
    """Upgrade an existing TCP connection to TLS via ``start_tls``.

    Returns (elapsed_ms, tls_version_string | None).

    If ``start_tls`` is not available on the writer's transport, the
    caller should fall back to the combined TCP+TLS measurement path.
    """
    ctx = _build_ssl_context(hostname)

    t0 = time.perf_counter()
    transport = writer.transport

    # asyncio.StreamWriter.start_tls was added in Python 3.11.
    if hasattr(writer, "start_tls"):
        await asyncio.wait_for(
            writer.start_tls(ctx, server_hostname=hostname),
            timeout=timeout,
        )
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        tls_version = _extract_tls_version(writer)
        return round(elapsed_ms, 3), tls_version

    # Fallback: use the loop-level start_tls (Python 3.10 compatible).
    loop = asyncio.get_running_loop()
    new_transport = await asyncio.wait_for(
        loop.start_tls(transport, ctx, server_hostname=hostname),
        timeout=timeout,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # Re-bind the writer to the new transport.
    writer._transport = new_transport  # type: ignore[attr-defined]
    tls_version = _extract_tls_version_from_transport(new_transport)
    return round(elapsed_ms, 3), tls_version


def _extract_tls_version(writer: asyncio.StreamWriter) -> Optional[str]:
    """Best-effort extraction of TLS version from writer transport."""
    return _extract_tls_version_from_transport(writer.transport)


def _extract_tls_version_from_transport(transport: object) -> Optional[str]:
    """Extract TLS version string from a transport object."""
    ssl_obj = getattr(transport, "get_extra_info", lambda _: None)("ssl_object")
    if ssl_obj is not None:
        return ssl_obj.version()
    return None


# ---------------------------------------------------------------------------
# Combined TCP + TLS (fallback when start_tls is unavailable / fails)
# ---------------------------------------------------------------------------

async def _measure_tcp_tls_combined(
    ip: str,
    port: int,
    hostname: str,
    tcp_ms: float,
    timeout: float,
) -> tuple[float, Optional[str]]:
    """Open a single SSL connection to measure TCP+TLS together.

    TLS time is estimated by subtracting a previously measured *tcp_ms*.
    Returns (tls_ms, tls_version).
    """
    ctx = _build_ssl_context(hostname)

    t0 = time.perf_counter()
    _reader, writer = await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=hostname),
        timeout=timeout,
    )
    combined_ms = (time.perf_counter() - t0) * 1000.0
    tls_ms = max(combined_ms - tcp_ms, 0.0)

    tls_version = _extract_tls_version(writer)

    writer.close()
    await writer.wait_closed()

    return round(tls_ms, 3), tls_version


# ---------------------------------------------------------------------------
# TTFB + Transfer via httpx
# ---------------------------------------------------------------------------

class _PinnedTransport(httpx.AsyncHTTPTransport):
    """Transport that pins DNS resolution to a specific IP.

    Rewrites the request URL to target the pre-resolved IP while
    preserving the original hostname via the ``sni_hostname`` extension
    so that TLS SNI and certificate validation work correctly.
    """

    def __init__(self, target_ip: str, **kwargs):
        self._target_ip = target_ip
        super().__init__(**kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        pinned_url = url.copy_with(host=self._target_ip)
        request = httpx.Request(
            method=request.method,
            url=pinned_url,
            headers=request.headers,
            stream=request.stream,
            extensions={**request.extensions, "sni_hostname": url.host.encode()},
        )
        return await super().handle_async_request(request)


async def _measure_http(
    ip: str,
    hostname: str,
    path: str,
    port: int,
    extra_headers: dict[str, str],
    timeout: float,
) -> tuple[float, float, httpx.Response, bytes]:
    """Send an HTTP request to the resolved *ip* and measure TTFB + Transfer.

    The URL uses the original hostname for correct TLS SNI / certificate
    validation.  A ``_PinnedTransport`` rewrites the connection to target
    the pre-resolved IP, avoiding a redundant DNS lookup.

    Returns (ttfb_ms, transfer_ms, response, body).
    """
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{hostname}{path}" if path else f"{scheme}://{hostname}/"

    headers = {
        "User-Agent": USER_AGENT,
        **extra_headers,
    }

    transport = _PinnedTransport(target_ip=ip, http2=True, verify=True)

    # Per-sample fresh client — prevents connection reuse.
    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
    ) as client:
        t_send = time.perf_counter()

        async with client.stream("GET", url, headers=headers) as response:
            # TTFB: time until we can read the first chunk.
            chunks: list[bytes] = []
            aiter = response.aiter_bytes().__aiter__()
            try:
                first_chunk = await aiter.__anext__()
                t_first_byte = time.perf_counter()
                ttfb_ms = (t_first_byte - t_send) * 1000.0
                chunks.append(first_chunk)
            except StopAsyncIteration:
                t_first_byte = time.perf_counter()
                ttfb_ms = (t_first_byte - t_send) * 1000.0

            # Transfer: read remaining body.
            async for chunk in aiter:
                chunks.append(chunk)
            t_done = time.perf_counter()
            transfer_ms = (t_done - t_first_byte) * 1000.0

    body = b"".join(chunks)

    return round(ttfb_ms, 3), round(transfer_ms, 3), response, body


# ---------------------------------------------------------------------------
# Single sample
# ---------------------------------------------------------------------------

async def _run_single_sample(
    provider: CDNProvider,
    sample_index: int,
    config: MeasurementConfig,
) -> SampleResult:
    """Execute one complete measurement sample for *provider*.

    Phases are measured independently in sequence:
        DNS -> TCP -> TLS -> TTFB -> Transfer

    If an early phase fails the remaining phases are skipped and the
    sample is marked with an error string.
    """
    timing = TimingBreakdown()
    parsed = urlparse(provider.probe_url)
    hostname = parsed.hostname or ""
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    resolved_ip: Optional[str] = None
    tls_version: Optional[str] = None
    http_version: Optional[str] = None
    status_code: Optional[int] = None
    cache_status: Optional[str] = None
    error: Optional[str] = None

    # ---- Phase 1: DNS ----
    try:
        resolved_ip, dns_ms = await _resolve_dns(hostname, config)
        timing.dns_ms = dns_ms
    except Exception as exc:
        error = f"DNS resolution failed: {exc}"
        logger.debug("DNS failed for %s: %s", hostname, exc)
        return SampleResult(
            sample_index=sample_index,
            timing=timing,
            error=error,
        )

    # ---- Phase 2: TCP ----
    tcp_reader: asyncio.StreamReader | None = None
    tcp_writer: asyncio.StreamWriter | None = None
    try:
        tcp_reader, tcp_writer, tcp_ms = await _measure_tcp(
            resolved_ip, port, config.timeout,
        )
        timing.tcp_ms = tcp_ms
    except Exception as exc:
        error = f"TCP connect failed: {exc}"
        logger.debug("TCP failed for %s:%d: %s", resolved_ip, port, exc)
        return SampleResult(
            sample_index=sample_index,
            timing=timing,
            resolved_ip=resolved_ip,
            error=error,
        )

    # ---- Phase 3: TLS ----
    if parsed.scheme == "https":
        try:
            tls_ms, tls_version = await _measure_tls(
                tcp_reader, tcp_writer, hostname, config.timeout,
            )
            timing.tls_ms = tls_ms
        except Exception:
            # Fallback: combined TCP+TLS measurement.
            logger.debug(
                "start_tls failed for %s, falling back to combined measurement",
                hostname,
            )
            try:
                tls_ms, tls_version = await _measure_tcp_tls_combined(
                    resolved_ip, port, hostname, timing.tcp_ms, config.timeout,
                )
                timing.tls_ms = tls_ms
            except Exception as exc:
                error = f"TLS handshake failed: {exc}"
                logger.debug("TLS failed for %s: %s", hostname, exc)
                _safe_close_writer(tcp_writer)
                return SampleResult(
                    sample_index=sample_index,
                    timing=timing,
                    resolved_ip=resolved_ip,
                    error=error,
                )

    # We no longer need the raw socket -- httpx will open its own connection.
    _safe_close_writer(tcp_writer)

    # ---- Phases 4 & 5: TTFB + Transfer ----
    try:
        ttfb_ms, transfer_ms, response, _body = await _measure_http(
            resolved_ip,
            hostname,
            path,
            port,
            provider.extra_headers,
            config.timeout,
        )
        timing.ttfb_ms = ttfb_ms
        timing.transfer_ms = transfer_ms

        status_code = response.status_code
        http_version = response.http_version

        # Extract cache status from common CDN headers.
        for hdr in ("x-cache", "cf-cache-status", "x-cache-status", "x-cdn-cache"):
            val = response.headers.get(hdr)
            if val:
                cache_status = val
                break

    except httpx.TimeoutException as exc:
        error = f"HTTP timeout: {exc}"
        logger.debug("HTTP timeout for %s: %s", hostname, exc)
    except httpx.HTTPStatusError as exc:
        error = f"HTTP error: {exc.response.status_code}"
        status_code = exc.response.status_code
        logger.debug("HTTP status error for %s: %s", hostname, exc)
    except Exception as exc:
        error = f"HTTP request failed: {exc}"
        logger.debug("HTTP failed for %s: %s", hostname, exc)

    return SampleResult(
        sample_index=sample_index,
        timing=timing,
        resolved_ip=resolved_ip,
        tls_version=tls_version,
        http_version=http_version,
        status_code=status_code,
        error=error,
        cache_status=cache_status,
    )


def _safe_close_writer(writer: asyncio.StreamWriter | None) -> None:
    """Close a stream writer without raising on already-closed transports."""
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Rate-limit backoff
# ---------------------------------------------------------------------------

async def _run_sample_with_backoff(
    provider: CDNProvider,
    sample_index: int,
    config: MeasurementConfig,
) -> SampleResult:
    """Run a single sample, retrying once on HTTP 429 with exponential backoff."""
    result = await _run_single_sample(provider, sample_index, config)
    if result.status_code == 429:
        backoff_s = 2.0
        logger.info(
            "Rate-limited (429) by %s, backing off %.1fs before retry",
            provider.slug,
            backoff_s,
        )
        await asyncio.sleep(backoff_s)
        result = await _run_single_sample(provider, sample_index, config)
    return result


# ---------------------------------------------------------------------------
# Provider-level measurement
# ---------------------------------------------------------------------------

async def measure_provider(
    provider: CDNProvider,
    config: MeasurementConfig,
    progress_callback: ProgressCallback | None = None,
) -> ProviderResult:
    """Run all measurement samples for a single provider.

    Warmup samples are executed and discarded first, followed by the
    configured number of recorded samples.  Each sample uses a fresh
    connection to avoid connection-reuse bias.

    Parameters
    ----------
    provider:
        The CDN provider to measure.
    config:
        Measurement parameters (sample count, warmup, delays, etc.).
    progress_callback:
        Optional callable invoked after each sample completes.
        Signature: ``(provider_slug, sample_index, total_samples, result)``
    """
    total_samples = config.warmup + config.samples
    delay_s = config.delay_ms / 1000.0

    result = ProviderResult(
        provider_name=provider.name,
        provider_slug=provider.slug,
        probe_url=provider.probe_url,
    )

    # Track the first successful response for PoP detection and metadata.
    first_response: httpx.Response | None = None

    for i in range(total_samples):
        is_warmup = i < config.warmup
        sample_idx = i - config.warmup  # negative during warmup

        if progress_callback and not is_warmup:
            progress_callback(provider.slug, sample_idx, config.samples, None)

        try:
            sample = await asyncio.wait_for(
                _run_sample_with_backoff(provider, sample_idx, config),
                timeout=config.timeout + 5.0,  # generous outer timeout
            )
        except asyncio.TimeoutError:
            sample = SampleResult(
                sample_index=sample_idx,
                timing=TimingBreakdown(),
                error="Overall sample timeout exceeded",
            )

        if not is_warmup:
            result.samples.append(sample)

            if progress_callback:
                progress_callback(
                    provider.slug, sample_idx, config.samples, sample,
                )

        # Keep first good sample for metadata extraction.
        if sample.error is None and result.resolved_ip is None:
            result.resolved_ip = sample.resolved_ip
            result.tls_version = sample.tls_version
            result.http_version = sample.http_version

        # Inter-sample delay (skip after last sample).
        if i < total_samples - 1 and delay_s > 0:
            await asyncio.sleep(delay_s)

    # ---- PoP detection and metadata via a lightweight extra request ----
    # We make one additional request specifically for PoP detection so the
    # provider's detect_pop / extract_metadata methods can inspect a real
    # httpx.Response object.  This request is *not* included in timing stats.
    try:
        pop, metadata = await _detect_pop_and_metadata(provider, result, config)
        result.pop = pop
        result.extra_metadata = metadata
    except Exception as exc:
        logger.debug("PoP detection failed for %s: %s", provider.slug, exc)

    # Aggregate phase statistics.
    aggregate_provider_stats(result)

    return result


async def _detect_pop_and_metadata(
    provider: CDNProvider,
    result: ProviderResult,
    config: MeasurementConfig,
) -> tuple[PoPIdentity, dict[str, str]]:
    """Make a lightweight request to detect PoP identity and extract metadata.

    Uses the resolved IP from prior samples when available so DNS cost
    is not incurred again.
    """
    parsed = urlparse(provider.probe_url)
    hostname = parsed.hostname or ""
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    scheme = parsed.scheme or "https"

    # Prefer pre-resolved IP to skip DNS via pinned transport.
    ip = result.resolved_ip
    url = f"{scheme}://{hostname}{path}" if hostname else provider.probe_url
    headers = {
        "User-Agent": USER_AGENT,
        **provider.extra_headers,
    }

    if ip:
        transport = _PinnedTransport(target_ip=ip, http2=True, verify=True)
        async with httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(config.timeout),
        ) as client:
            response = await client.get(url, headers=headers)
    else:
        async with httpx.AsyncClient(
            http2=True,
            verify=True,
            timeout=httpx.Timeout(config.timeout),
        ) as client:
            response = await client.get(url, headers=headers)

    pop = provider.detect_pop(response)
    metadata = provider.extract_metadata(response)

    # Propagate cache status into result if not already set.
    for sample in result.samples:
        if sample.cache_status is None:
            for hdr in ("x-cache", "cf-cache-status", "x-cache-status", "x-cdn-cache"):
                val = response.headers.get(hdr)
                if val:
                    sample.cache_status = val
                    break

    return pop, metadata


# ---------------------------------------------------------------------------
# Multi-provider orchestration
# ---------------------------------------------------------------------------

async def measure_all(
    config: MeasurementConfig,
    progress_callback: ProgressCallback | None = None,
) -> list[ProviderResult]:
    """Run measurements for all configured providers concurrently.

    If ``config.providers`` is empty, every registered provider is measured.
    Providers are measured concurrently via ``asyncio.gather``; within each
    provider, samples run sequentially.

    Parameters
    ----------
    config:
        Measurement configuration.
    progress_callback:
        Optional callable forwarded to each ``measure_provider`` call.

    Returns
    -------
    list[ProviderResult]
        One result per provider, in the same order as the provider list.
    """
    provider_map = get_provider_map()

    if config.providers:
        slugs = config.providers
    else:
        slugs = sorted(provider_map.keys())

    providers: list[CDNProvider] = []
    errors: list[ProviderResult] = []

    for slug in slugs:
        try:
            providers.append(get_provider(slug))
        except ValueError as exc:
            errors.append(
                ProviderResult(
                    provider_name=slug,
                    provider_slug=slug,
                    probe_url="",
                    error=str(exc),
                )
            )

    async def _safe_measure(p: CDNProvider) -> ProviderResult:
        """Wrapper that catches unexpected fatal errors per provider."""
        try:
            return await measure_provider(p, config, progress_callback)
        except Exception as exc:
            logger.exception("Fatal error measuring %s", p.slug)
            return ProviderResult(
                provider_name=p.name,
                provider_slug=p.slug,
                probe_url=p.probe_url,
                error=f"Fatal measurement error: {exc}",
            )

    tasks = [_safe_measure(p) for p in providers]
    results = await asyncio.gather(*tasks)

    return list(results) + errors
