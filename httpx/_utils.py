from __future__ import annotations

import ipaddress
import os
import re
import typing
from urllib.request import getproxies

from ._types import PrimitiveData
from ._urlparse import AUTHORITY_REGEX, DEFAULT_PORTS, URL_REGEX

if typing.TYPE_CHECKING:  # pragma: no cover
    from ._urls import URL


def _explicit_pattern_port(pattern: str) -> int | None:
    """
    Return the port written explicitly in a URL pattern string, or `None`
    if the pattern does not include a port.

    Unlike `URL(pattern).port` this does not normalize the scheme's default
    port (eg. 80 for http, 443 for https) to `None`, which lets us tell
    "https://example.com" apart from "https://example.com:443".
    """
    url_match = URL_REGEX.match(pattern)
    assert url_match is not None
    authority = url_match.groupdict()["authority"] or ""
    authority_match = AUTHORITY_REGEX.match(authority)
    assert authority_match is not None
    port = authority_match.groupdict()["port"]
    return int(port) if port else None


def primitive_value_to_str(value: PrimitiveData) -> str:
    """
    Coerce a primitive data type into a string value.

    Note that we prefer JSON-style 'true'/'false' for boolean values here.
    """
    if value is True:
        return "true"
    elif value is False:
        return "false"
    elif value is None:
        return ""
    return str(value)


def get_environment_proxies() -> dict[str, str | None]:
    """Gets proxy information from the environment"""

    # urllib.request.getproxies() falls back on System
    # Registry and Config for proxies on Windows and macOS.
    # We don't want to propagate non-HTTP proxies into
    # our configuration such as 'TRAVIS_APT_PROXY'.
    proxy_info = getproxies()
    mounts: dict[str, str | None] = {}

    for scheme in ("http", "https", "all"):
        if proxy_info.get(scheme):
            hostname = proxy_info[scheme]
            mounts[f"{scheme}://"] = (
                hostname if "://" in hostname else f"http://{hostname}"
            )

    no_proxy_hosts = [host.strip() for host in proxy_info.get("no", "").split(",")]
    for hostname in no_proxy_hosts:
        # See https://curl.haxx.se/libcurl/c/CURLOPT_NOPROXY.html for details
        # on how names in `NO_PROXY` are handled.
        if hostname == "*":
            # If NO_PROXY=* is used or if "*" occurs as any one of the comma
            # separated hostnames, then we should just bypass any information
            # from HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, and always ignore
            # proxies.
            return {}
        elif hostname:
            # NO_PROXY=.google.com is marked as "all://*.google.com,
            #   which disables "www.google.com" but not "google.com"
            # NO_PROXY=google.com is marked as "all://*google.com,
            #   which disables "www.google.com" and "google.com".
            #   (But not "wwwgoogle.com")
            # NO_PROXY can include domains, IPv6, IPv4 addresses and "localhost"
            #   NO_PROXY=example.com,::1,localhost,192.168.0.0/16
            if "://" in hostname:
                mounts[hostname] = None
            elif is_ipv4_hostname(hostname):
                mounts[f"all://{hostname}"] = None
            elif is_ipv6_hostname(hostname):
                mounts[f"all://[{hostname}]"] = None
            elif hostname.lower() == "localhost":
                mounts[f"all://{hostname}"] = None
            else:
                mounts[f"all://*{hostname}"] = None

    return mounts


def to_bytes(value: str | bytes, encoding: str = "utf-8") -> bytes:
    return value.encode(encoding) if isinstance(value, str) else value


def to_str(value: str | bytes, encoding: str = "utf-8") -> str:
    return value if isinstance(value, str) else value.decode(encoding)


def to_bytes_or_str(value: str, match_type_of: typing.AnyStr) -> typing.AnyStr:
    return value if isinstance(match_type_of, str) else value.encode()


def unquote(value: str) -> str:
    return value[1:-1] if value[0] == value[-1] == '"' else value


def peek_filelike_length(stream: typing.Any) -> int | None:
    """
    Given a file-like stream object, return its length in number of bytes
    without reading it into memory.
    """
    try:
        # Is it an actual file?
        fd = stream.fileno()
        # Yup, seems to be an actual file.
        length = os.fstat(fd).st_size
    except (AttributeError, OSError):
        # No... Maybe it's something that supports random access, like `io.BytesIO`?
        try:
            # Assuming so, go to end of stream to figure out its length,
            # then put it back in place.
            offset = stream.tell()
            length = stream.seek(0, os.SEEK_END)
            stream.seek(offset)
        except (AttributeError, OSError):
            # Not even that? Sorry, we're doomed...
            return None

    return length


class URLPattern:
    """
    A utility class currently used for making lookups against proxy keys...

    # Wildcard matching...
    >>> pattern = URLPattern("all://")
    >>> pattern.matches(httpx.URL("http://example.com"))
    True

    # Witch scheme matching...
    >>> pattern = URLPattern("https://")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("http://example.com"))
    False

    # With domain matching...
    >>> pattern = URLPattern("https://example.com")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("http://example.com"))
    False
    >>> pattern.matches(httpx.URL("https://other.com"))
    False

    # Wildcard scheme, with domain matching...
    >>> pattern = URLPattern("all://example.com")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("http://example.com"))
    True
    >>> pattern.matches(httpx.URL("https://other.com"))
    False

    # With port matching...
    >>> pattern = URLPattern("https://example.com:1234")
    >>> pattern.matches(httpx.URL("https://example.com:1234"))
    True
    >>> pattern.matches(httpx.URL("https://example.com"))
    False

    # An omitted port matches any port...
    >>> pattern = URLPattern("https://example.com")
    >>> pattern.matches(httpx.URL("https://example.com:8443"))
    True

    # An explicitly given default port only matches the default port form,
    # which the URL class normalizes to having no port...
    >>> pattern = URLPattern("https://example.com:443")
    >>> pattern.matches(httpx.URL("https://example.com"))
    True
    >>> pattern.matches(httpx.URL("https://example.com:8443"))
    False
    """

    def __init__(self, pattern: str) -> None:
        from ._urls import URL

        if pattern and ":" not in pattern:
            raise ValueError(
                f"Proxy keys should use proper URL forms rather "
                f"than plain scheme strings. "
                f'Instead of "{pattern}", use "{pattern}://"'
            )

        url = URL(pattern)
        self.pattern = pattern
        self.scheme = "" if url.scheme == "all" else url.scheme
        self.host = "" if url.host == "*" else url.host
        # `URL` normalizes a scheme's default port to `None`, so inspect the
        # raw pattern string to distinguish a pattern without any port
        # (which should match on any port) from a pattern that explicitly
        # gives the scheme's default port (which should only match that
        # port).
        self.port = _explicit_pattern_port(pattern)
        if not url.host or url.host == "*":
            # No host constraint, eg. "all://" or "http://*".
            self.host_regex: typing.Pattern[str] | None = None
            self._host_priority = (3, 0)
        elif url.host.startswith("*."):
            # *.example.com should match "www.example.com", but not "example.com"
            domain = re.escape(url.host[2:])
            self.host_regex = re.compile(f"^.+\\.{domain}$")
            self._host_priority = (1, -len(self.host))
        elif url.host.startswith("*"):
            # *example.com should match "www.example.com" and "example.com"
            domain = re.escape(url.host[1:])
            self.host_regex = re.compile(f"^(.+\\.)?{domain}$")
            self._host_priority = (2, -len(self.host))
        else:
            # example.com should match "example.com" but not "www.example.com"
            domain = re.escape(url.host)
            self.host_regex = re.compile(f"^{domain}$")
            self._host_priority = (0, -len(self.host))

    def matches(self, other: URL) -> bool:
        if self.scheme and self.scheme != other.scheme:
            return False
        if (
            self.host
            and self.host_regex is not None
            and not self.host_regex.match(other.host)
        ):
            return False
        if self.port is not None:
            # The pattern constrains the origin port exactly. Request URLs
            # have their scheme's default port normalized to `None`, so use
            # the request URL's effective port when comparing.
            other_port = other.port
            if other_port is None:
                other_port = DEFAULT_PORTS.get(other.scheme)
            if self.port != other_port:
                return False
        return True

    @property
    def priority(self) -> tuple[int, int, int, int]:
        """
        The priority allows URLPattern instances to be sortable, so that
        we can match from most specific to least specific.
        """
        # Patterns with an explicit port should take priority over patterns
        # without a port. Note this includes explicitly written default
        # ports such as "http://example.com:80".
        port_priority = 0 if self.port is not None else 1
        # Exact hosts match before wildcard hosts, and longer hosts match
        # before shorter hosts. "*.example.com" is more specific than
        # "*example.com", since the latter also matches the apex domain.
        host_kind_priority, host_length_priority = self._host_priority
        # A concrete scheme matches before "all".
        scheme_priority = 0 if self.scheme else 1
        return (
            port_priority,
            host_kind_priority,
            host_length_priority,
            scheme_priority,
        )

    def __hash__(self) -> int:
        return hash(self.pattern)

    def __lt__(self, other: URLPattern) -> bool:
        return self.priority < other.priority

    def __eq__(self, other: typing.Any) -> bool:
        return isinstance(other, URLPattern) and self.pattern == other.pattern


def is_ipv4_hostname(hostname: str) -> bool:
    try:
        ipaddress.IPv4Address(hostname.split("/")[0])
    except Exception:
        return False
    return True


def is_ipv6_hostname(hostname: str) -> bool:
    try:
        ipaddress.IPv6Address(hostname.split("/")[0])
    except Exception:
        return False
    return True
