#!/usr/bin/env python3
"""Isolated Scrapling worker for ToadAid Adaptive Web Intelligence P9.

One JSON request is read from stdin and one JSON response is written to stdout.
The worker never receives capability-authority objects; the TypeScript host must gate
requests before invoking this process.

Runtime expectation: Python 3.10+ with Scrapling fetch/browser extras installed.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import sys
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

MAX_REDIRECTS = 8
MAX_RESOLVED_ADDRESSES = 64


def _fail(message: str) -> None:
    print(json.dumps({"schemaVersion": "toadaid.scrapling-worker.error.v1", "error": message}, separators=(",", ":")))
    raise SystemExit(2)


def _origin(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must use http/https and include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("URL credentials are forbidden")
    default_port = 80 if parsed.scheme == "http" else 443
    port = parsed.port or default_port
    suffix = "" if port == default_port else f":{port}"
    return f"{parsed.scheme}://{parsed.hostname.lower()}{suffix}"


def _persisted_url(url: str) -> str:
    parsed = urlparse(url)
    return f"{_origin(url)}{parsed.path or '/'}"


def _public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _resolve(host: str, allow_private: bool, cache: dict[str, list[str]]) -> list[str]:
    normalized = host.strip("[]").lower()
    if normalized in cache:
        return cache[normalized]
    addresses: set[str] = set()
    try:
        literal = ipaddress.ip_address(normalized)
        addresses.add(str(literal))
    except ValueError:
        for info in socket.getaddrinfo(normalized, None, type=socket.SOCK_STREAM):
            address = info[4][0]
            addresses.add(str(ipaddress.ip_address(address)))
    if not addresses:
        raise ValueError(f"hostname did not resolve: {normalized}")
    if not allow_private:
        rejected = sorted(address for address in addresses if not _public_address(address))
        if rejected:
            raise ValueError(f"private/local address resolution refused for {normalized}: {','.join(rejected)}")
    values = sorted(addresses)
    cache[normalized] = values
    return values


def _validate_url(
    url: str,
    allowed_origins: set[str],
    allow_private: bool,
    dns_cache: dict[str, list[str]],
) -> str:
    origin = _origin(url)
    if origin not in allowed_origins:
        raise ValueError(f"origin is not authorized: {origin}")
    host = urlparse(url).hostname
    if host is None:
        raise ValueError("URL hostname missing")
    _resolve(host, allow_private, dns_cache)
    return url


def _resolved_evidence(cache: dict[str, list[str]]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for host in sorted(cache):
        for address in cache[host]:
            rows.append({"host": host, "address": address})
            if len(rows) >= MAX_RESOLVED_ADDRESSES:
                return rows
    return rows


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _headers_get(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    try:
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        return None if value is None else str(value)
    except Exception:
        return None


def _http_fetch(url: str, policy: dict[str, Any], dns_cache: dict[str, list[str]]):
    from scrapling.fetchers import Fetcher

    allowed = set(policy["allowedTopLevelOrigins"])
    allow_private = bool(policy.get("allowPrivateNetwork", False))
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        _validate_url(current, allowed, allow_private, dns_cache)
        page = Fetcher.get(current, follow_redirects=False)
        status = int(page.status)
        if 300 <= status < 400:
            location = _headers_get(page.headers, "location")
            if not location:
                return page
            current = urljoin(current, location)
            continue
        return page
    raise ValueError(f"redirect limit exceeded ({MAX_REDIRECTS})")


def _route_guard(policy: dict[str, Any], dns_cache: dict[str, list[str]]):
    top_level = set(policy["allowedTopLevelOrigins"])
    resources = top_level | set(policy.get("allowedResourceOrigins", []))
    allow_private = bool(policy.get("allowPrivateNetwork", False))

    def setup(page) -> None:
        def handle(route) -> None:
            request = route.request
            if request.method.upper() not in ("GET", "HEAD"):
                route.abort()
                return
            parsed = urlparse(request.url)
            if parsed.scheme in ("data", "blob"):
                route.continue_()
                return
            allowed = top_level if request.is_navigation_request() else resources
            try:
                _validate_url(request.url, allowed, allow_private, dns_cache)
            except Exception:
                route.abort()
                return
            route.continue_()

        page.route("**/*", handle)
        if hasattr(page, "route_web_socket"):
            try:
                page.route_web_socket("**/*", lambda ws: ws.close())
            except Exception:
                pass

    return setup


def _browser_fetch(url: str, request: dict[str, Any], dns_cache: dict[str, list[str]]):
    mode = request["fetchMode"]
    policy = request["policy"]
    allowed = set(policy["allowedTopLevelOrigins"])
    _validate_url(url, allowed, bool(policy.get("allowPrivateNetwork", False)), dns_cache)
    kwargs: dict[str, Any] = {
        "headless": True,
        "google_search": False,
        "network_idle": True,
        "timeout": 30_000,
        "page_setup": _route_guard(policy, dns_cache),
    }
    if request["operation"] == "XHR_CAPTURE":
        kwargs["capture_xhr"] = request["xhr"]["pattern"]
    if mode == "STEALTH":
        from scrapling.fetchers import StealthyFetcher

        page = StealthyFetcher.fetch(url, **kwargs)
    else:
        from scrapling.fetchers import DynamicFetcher

        page = DynamicFetcher.fetch(url, **kwargs)
    _validate_url(str(page.url), allowed, bool(policy.get("allowPrivateNetwork", False)), dns_cache)
    return page


def _fetch(request: dict[str, Any], dns_cache: dict[str, list[str]]):
    if request["fetchMode"] == "HTTP":
        return _http_fetch(request["url"], request["policy"], dns_cache)
    return _browser_fetch(request["url"], request, dns_cache)


def _selection(page, selector_kind: str, selector: str):
    if selector_kind == "CSS":
        return page.css(selector)
    if selector_kind == "XPATH":
        return page.xpath(selector)
    raise ValueError(f"unsupported selector kind: {selector_kind}")


def _element_text(element) -> str:
    try:
        value = element.text
        if value:
            return str(value)
    except Exception:
        pass
    try:
        return str(element.get_all_text(strip=True))
    except Exception:
        return str(element.get())


def _extract(page, request: dict[str, Any]) -> dict[str, list[str]]:
    max_value_chars = int(request["policy"]["maxValueChars"])
    result: dict[str, list[str]] = {}
    for field in request["fields"]:
        selection = _selection(page, field["selectorKind"], field["selector"])
        values: list[str] = []
        maximum = int(field.get("maxItems", 1))
        for element in selection:
            if field["valueKind"] == "TEXT":
                value = _element_text(element)
            elif field["valueKind"] == "HTML":
                value = str(element.html_content)
            elif field["valueKind"] == "ATTRIBUTE":
                value = str(element.attrib.get(field["attribute"], ""))
            else:
                raise ValueError(f"unsupported value kind: {field['valueKind']}")
            values.append(value[:max_value_chars])
            if len(values) >= maximum:
                break
        result[field["name"]] = values
    return result


def _safe_attrs(element) -> dict[str, str]:
    try:
        return {str(k)[:128]: str(v)[:1000] for k, v in dict(element.attrib).items()}
    except Exception:
        return {}


def _candidate_fingerprint(element) -> dict[str, Any]:
    try:
        parent = element.parent
    except Exception:
        parent = None
    try:
        siblings = [str(item.tag).lower()[:128] for item in element.siblings[:32]]
    except Exception:
        siblings = []
    try:
        path = [str(item.tag).lower()[:128] for item in element.path[-32:]]
    except Exception:
        path = []
    raw = {
        "tag": str(getattr(element, "tag", "unknown")).lower()[:128],
        "text": _element_text(element)[:4000],
        "attributes": _safe_attrs(element),
        "parent": {
            "tag": None if parent is None else str(getattr(parent, "tag", "unknown")).lower()[:128],
            "text": "" if parent is None else _element_text(parent)[:2000],
            "attributes": {} if parent is None else _safe_attrs(parent),
        },
        "siblingTags": siblings,
        "pathTags": path,
    }
    identity = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"id": f"candidate:{identity}", **raw}


def _candidates(page, request: dict[str, Any]) -> list[dict[str, Any]]:
    spec = request["candidateSelector"]
    selection = _selection(page, spec["selectorKind"], spec["selector"])
    output: list[dict[str, Any]] = []
    for element in selection:
        output.append(_candidate_fingerprint(element))
        if len(output) >= int(spec["maxCandidates"]):
            break
    return output


def _xhr(page, request: dict[str, Any]) -> list[dict[str, Any]]:
    body_mode = request["xhr"]["bodyMode"]
    max_value_chars = int(request["policy"]["maxValueChars"])
    output: list[dict[str, Any]] = []
    for response in getattr(page, "captured_xhr", [])[:2000]:
        body = bytes(response.body)
        row: dict[str, Any] = {
            "url": str(response.url),
            "status": int(response.status),
            "bytes": len(body),
            "sha256": _sha256(body),
            "contentType": _headers_get(response.headers, "content-type"),
        }
        if body_mode == "BOUNDED_TEXT":
            text = body.decode(getattr(response, "encoding", None) or "utf-8", errors="replace")
            row["textExcerpt"] = text[:max_value_chars]
            row["textTruncated"] = len(text) > max_value_chars
        output.append(row)
    return output


def _validate_request(request: dict[str, Any]) -> None:
    if request.get("schemaVersion") != "toadaid.scrapling-worker.request.v1":
        raise ValueError("unsupported request schemaVersion")
    if request.get("operation") not in ("EXTRACT", "CANDIDATES", "XHR_CAPTURE"):
        raise ValueError("unsupported operation")
    if request.get("fetchMode") not in ("HTTP", "BROWSER", "STEALTH"):
        raise ValueError("unsupported fetchMode")
    policy = request.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    top = policy.get("allowedTopLevelOrigins")
    resource = policy.get("allowedResourceOrigins")
    if not isinstance(top, list) or not top or not isinstance(resource, list):
        raise ValueError("allowed origin lists are invalid")
    policy["allowedTopLevelOrigins"] = sorted({_origin(str(value)) for value in top})
    policy["allowedResourceOrigins"] = sorted({_origin(str(value)) for value in resource})
    _validate_url(str(request.get("url", "")), set(policy["allowedTopLevelOrigins"]), bool(policy.get("allowPrivateNetwork", False)), {})
    if request["operation"] == "XHR_CAPTURE" and request["fetchMode"] == "HTTP":
        raise ValueError("XHR_CAPTURE requires browser fetch mode")


def main() -> None:
    raw = sys.stdin.buffer.read()
    if len(raw) > 4 * 1024 * 1024:
        _fail("request exceeds 4 MiB")
    try:
        request = json.loads(raw.decode("utf-8"))
        if not isinstance(request, dict):
            raise ValueError("request must be a JSON object")
        _validate_request(request)
        dns_cache: dict[str, list[str]] = {}
        page = _fetch(request, dns_cache)
        body = bytes(page.body)
        max_response = int(request["policy"]["maxResponseBytes"])
        if len(body) > max_response:
            raise ValueError(f"response exceeds maxResponseBytes ({max_response})")
        operation = request["operation"]
        response: dict[str, Any] = {
            "schemaVersion": "toadaid.scrapling-worker.response.v1",
            "requestId": str(request["requestId"]),
            "operation": operation,
            "status": "OK",
            "requestedUrl": _persisted_url(str(request["url"])),
            "finalUrl": _persisted_url(str(page.url)),
            "httpStatus": int(page.status),
            "responseBytes": len(body),
            "responseSha256": _sha256(body),
            "resolvedAddresses": _resolved_evidence(dns_cache),
        }
        if operation == "EXTRACT":
            response["extracted"] = _extract(page, request)
        elif operation == "CANDIDATES":
            response["candidates"] = _candidates(page, request)
        else:
            response["xhr"] = _xhr(page, request)
        print(json.dumps(response, separators=(",", ":"), ensure_ascii=False))
    except SystemExit:
        raise
    except Exception as exc:
        _fail(f"{type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
