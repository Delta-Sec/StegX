from __future__ import annotations

import ipaddress
import logging
import os
import socket
import tempfile
from http.client import HTTPConnection, HTTPSConnection
from typing import Optional, Tuple
from urllib.parse import urlparse, urlunparse

from PIL import Image, UnidentifiedImageError

from .exceptions import StegXError

MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024
CONNECT_TIMEOUT_S = 5
READ_TIMEOUT_S = 30
MAX_REDIRECTS = 3
ALLOWED_SCHEMES = {"http", "https"}
_USER_AGENT = "StegX/2.0 (+cover-fetch)"

_CLOUD_IMDS_V4 = ipaddress.ip_network("169.254.169.254/32")
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


_IPV6_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_IPV6_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")
_IPV6_6TO4 = ipaddress.ip_network("2002::/16")
_IPV6_TEREDO = ipaddress.ip_network("2001::/32")
_IPV6_IPV4_TRANSLATED = ipaddress.ip_network("::ffff:0:0:0/96")

class UrlPolicyViolation(StegXError, ValueError):
    pass

def is_url(path: str) -> bool:
    try:
        parsed = urlparse(path)
    except ValueError:
        return False
    return parsed.scheme.lower() in ALLOWED_SCHEMES and bool(parsed.netloc)

def _is_safe_ip(ip: ipaddress._BaseAddress) -> bool:
    if not getattr(ip, "is_global", None):
        return False


    if isinstance(ip, ipaddress.IPv4Address):
        if ip in _CLOUD_IMDS_V4 or ip in _CGNAT_V4:
            return False
    if isinstance(ip, ipaddress.IPv6Address):


        if ip.ipv4_mapped is not None and not _is_safe_ip(ip.ipv4_mapped):
            return False
        if ip in _IPV6_IPV4_TRANSLATED:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            if not _is_safe_ip(embedded):
                return False


        if (
            ip in _IPV6_NAT64
            or ip in _IPV6_NAT64_LOCAL
            or ip in _IPV6_6TO4
            or ip in _IPV6_TEREDO
        ):
            return False
    return True

def _resolve_safe(host: str, port: int) -> Tuple[str, int]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise UrlPolicyViolation(f"DNS resolution failed for {host!r}: {e}")
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_safe_ip(ip):
            return ip_str, port
    raise UrlPolicyViolation(
        f"URL host {host!r} resolves only to disallowed addresses"
    )

class _PinnedHTTPConnection(HTTPConnection):
    def __init__(self, host, pinned_ip, port=None, timeout=None):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), timeout=CONNECT_TIMEOUT_S,
        )
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)

class _PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, host, pinned_ip, port=None, timeout=None, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection(
            (self._pinned_ip, self.port), timeout=CONNECT_TIMEOUT_S,
        )
        if self.timeout is not None:
            self.sock.settimeout(self.timeout)
        if self._tunnel_host:
            self._tunnel()
        self.sock = self._context.wrap_socket(
            self.sock, server_hostname=self.host
        )

def _http_get_once(url: str, timeout: int):
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlPolicyViolation(f"Unsupported URL scheme: {scheme!r}")
    if not parsed.hostname:
        raise UrlPolicyViolation("URL is missing a host component.")
    port = parsed.port or (443 if scheme == "https" else 80)
    pinned_ip, pinned_port = _resolve_safe(parsed.hostname, port)

    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    if scheme == "https":
        import ssl
        ctx = ssl.create_default_context()
        conn: HTTPConnection = _PinnedHTTPSConnection(
            parsed.hostname, pinned_ip=pinned_ip, port=pinned_port,
            timeout=timeout, context=ctx,
        )
    else:
        conn = _PinnedHTTPConnection(
            parsed.hostname, pinned_ip=pinned_ip, port=pinned_port,
            timeout=timeout,
        )

    conn.request("GET", path, headers={
        "User-Agent": _USER_AGENT,
        "Host": parsed.hostname,
        "Accept": "image/*",
    })
    resp = conn.getresponse()
    return resp.status, dict(resp.getheaders()), resp

def fetch_cover_to_tempfile(url: str) -> str:
    current_url = url
    for _ in range(MAX_REDIRECTS + 1):
        status, headers, resp = _http_get_once(current_url, timeout=READ_TIMEOUT_S)
        if 300 <= status < 400:
            loc = _header_ci(headers, "Location")
            resp.close()
            if not loc:
                raise UrlPolicyViolation(f"Redirect {status} with no Location header")


            parsed_loc = urlparse(loc)
            if not parsed_loc.scheme:
                base = urlparse(current_url)
                parsed_loc = parsed_loc._replace(
                    scheme=base.scheme, netloc=base.netloc
                )
                loc = urlunparse(parsed_loc)
            current_url = loc
            continue

        if status != 200:
            resp.close()
            raise ValueError(f"Cover fetch returned HTTP {status}")


        ctype_lower = _header_ci(headers, "Content-Type")
        ctype = ctype_lower.split(";", 1)[0].strip().lower()
        if not ctype or not ctype.startswith("image/"):
            resp.close()
            raise ValueError(
                f"Refusing to fetch non-image response: Content-Type={ctype!r}. "
                f"Only image/* responses are accepted."
            )

        suffix = _suffix_for_content_type(ctype)
        fd, tmp_path = tempfile.mkstemp(prefix="stegx_cover_", suffix=suffix)
        total = 0
        try:
            with os.fdopen(fd, "wb") as f:
                while True:
                    chunk = resp.read(64 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise ValueError(
                            f"Remote cover exceeds {MAX_DOWNLOAD_BYTES} byte limit."
                        )
                    f.write(chunk)
        except Exception:
            _silent_unlink(tmp_path)
            raise
        finally:


            resp.close()


        clean_path = tmp_path + ".clean"
        try:
            with Image.open(tmp_path) as img:
                img.verify()
            with Image.open(tmp_path) as img:
                img.load()


                clean_format = (img.format or "PNG").upper()
                img.save(clean_path, format=clean_format)
            os.replace(clean_path, tmp_path)
        except UnidentifiedImageError as e:
            _silent_unlink(clean_path)
            _silent_unlink(tmp_path)
            raise ValueError(f"Downloaded bytes are not a recognised image: {e}")
        except Exception as e:
            _silent_unlink(clean_path)
            _silent_unlink(tmp_path)
            raise ValueError(f"Downloaded file failed image verification: {e}")

        logging.info("Fetched %d-byte cover from %s -> %s", total, current_url, tmp_path)
        return tmp_path

    raise UrlPolicyViolation(f"Too many redirects ({MAX_REDIRECTS})")

def _header_ci(headers: dict, name: str) -> str:
    target = name.lower()
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == target:
            return value or ""
    return ""

def _suffix_for_content_type(ctype: str) -> str:
    if "png" in ctype:
        return ".png"
    if "jpeg" in ctype or "jpg" in ctype:
        return ".jpg"
    if "bmp" in ctype:
        return ".bmp"
    if "webp" in ctype:
        return ".webp"
    return ".img"

def _silent_unlink(path: Optional[str]) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass
