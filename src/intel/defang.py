"""Pure string operations: never DNS, HTTP requests, or connections to indicators."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit


def refang(value: str) -> str:
    return (
        value.strip()
        .replace("[.]", ".")
        .replace("[:]", ":")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def normalize(kind: str, value: str) -> str:
    v = refang(value)
    if kind == "IP":
        return str(ipaddress.ip_address(v))
    if kind == "Domain":
        v = v.rstrip(".").lower().encode("idna").decode("ascii")
        if (
            len(v) > 253
            or "." not in v
            or not all(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in v.split(".")
            )
        ):
            raise ValueError("Invalid domain")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            return v
        raise ValueError("IP supplied as domain")
    if kind == "URL":
        u = urlsplit(v)
        if u.scheme not in {"http", "https"} or not u.hostname or u.username or u.password:
            raise ValueError("Invalid HTTP(S) URL")
        try:
            host = normalize("IP", u.hostname)
            if ":" in host:
                host = f"[{host}]"
        except ValueError:
            host = normalize("Domain", u.hostname)
        port = u.port
        return urlunsplit(
            (u.scheme, host + (f":{port}" if port else ""), u.path, u.query, u.fragment)
        )
    if kind == "FileHash":
        v = v.lower()
        if len(v) not in {32, 40, 64} or not re.fullmatch(r"[0-9a-f]+", v):
            raise ValueError("Invalid MD5/SHA1/SHA256 hash")
        return v
    raise ValueError("Unknown indicator kind")


def defang(value: str) -> str:
    return (
        value.replace("https://", "hxxps://")
        .replace("http://", "hxxp://")
        .replace(".", "[.]")
        .replace(":", "[:]")
    )
