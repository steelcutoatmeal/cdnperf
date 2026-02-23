"""User IP geolocation via free APIs."""

from __future__ import annotations

import asyncio
import math
from typing import Optional

import httpx

from cdnperf.config import GEO_APIS, USER_AGENT
from cdnperf.models import GeoLocation


async def get_geolocation(timeout: float = 5.0) -> GeoLocation:
    """Determine user's geolocation using a fallback chain of free APIs."""
    for api_url in GEO_APIS:
        try:
            geo = await _query_api(api_url, timeout)
            if geo and geo.ip:
                return geo
        except Exception:
            continue

    return GeoLocation(error="All geolocation APIs failed")


async def _query_api(url: str, timeout: float) -> Optional[GeoLocation]:
    """Query a single geolocation API."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        data = resp.json()

    if "ipinfo.io" in url:
        return _parse_ipinfo(data)
    elif "ipapi.co" in url:
        return _parse_ipapi(data)
    elif "ip-api.com" in url:
        return _parse_ipapi_com(data)
    return None


def _parse_ipinfo(data: dict) -> GeoLocation:
    """Parse ipinfo.io response."""
    lat, lon = None, None
    loc = data.get("loc", "")
    if loc and "," in loc:
        parts = loc.split(",")
        try:
            lat, lon = float(parts[0]), float(parts[1])
        except (ValueError, IndexError):
            pass

    asn = None
    org = data.get("org", "")
    if org and org.startswith("AS"):
        parts = org.split(" ", 1)
        try:
            asn = int(parts[0][2:])
        except ValueError:
            pass

    return GeoLocation(
        ip=data.get("ip"),
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country"),
        lat=lat,
        lon=lon,
        isp=org,
        org=org,
        asn=asn,
    )


def _parse_ipapi(data: dict) -> GeoLocation:
    """Parse ipapi.co response."""
    if data.get("error"):
        return GeoLocation(error=str(data.get("reason", "ipapi.co error")))

    asn_str = data.get("asn", "")
    asn = None
    if asn_str and asn_str.startswith("AS"):
        try:
            asn = int(asn_str[2:])
        except ValueError:
            pass

    return GeoLocation(
        ip=data.get("ip"),
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country_code"),
        lat=data.get("latitude"),
        lon=data.get("longitude"),
        isp=data.get("org"),
        org=data.get("org"),
        asn=asn,
    )


def _parse_ipapi_com(data: dict) -> GeoLocation:
    """Parse ip-api.com response."""
    if data.get("status") == "fail":
        return GeoLocation(error=data.get("message", "ip-api.com error"))

    asn = None
    as_field = data.get("as", "")
    if as_field and as_field.startswith("AS"):
        parts = as_field.split(" ", 1)
        try:
            asn = int(parts[0][2:])
        except ValueError:
            pass

    return GeoLocation(
        ip=data.get("query"),
        city=data.get("city"),
        region=data.get("regionName"),
        country=data.get("country"),
        lat=data.get("lat"),
        lon=data.get("lon"),
        isp=data.get("isp"),
        org=data.get("org"),
        asn=asn,
    )


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute distance in km between two lat/lon points using the Haversine formula."""
    R = 6371.0  # Earth radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c
