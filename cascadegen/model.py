from __future__ import annotations

from dataclasses import dataclass, asdict, field
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse
import re

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")

DEFAULT_SNI_POOL = [
    "www.microsoft.com",
    "www.apple.com",
    "www.amazon.com",
    "www.bing.com",
]


@dataclass(slots=True)
class Server:
    name: str
    ip: str
    panel_url: str = ""
    auth_mode: str = "auto"  # auto | token | legacy
    api_token: str = ""
    username: str = ""
    password: str = ""
    two_factor_code: str = ""
    verify_tls: bool = False

    def validate(self) -> None:
        if not self.name or not NAME_RE.fullmatch(self.name):
            raise ValueError(f"invalid server name: {self.name!r}")
        try:
            ip_address(self.ip)
        except ValueError as exc:
            raise ValueError(f"invalid IP for {self.name}: {self.ip!r}") from exc
        if self.auth_mode not in {"auto", "token", "legacy"}:
            raise ValueError(f"invalid auth mode for {self.name}: {self.auth_mode!r}")
        if self.panel_url:
            parsed = urlparse(self.panel_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                raise ValueError(f"invalid panel URL for {self.name}: {self.panel_url!r}")
        if self.auth_mode == "token" and self.panel_url and not self.api_token:
            raise ValueError(f"API token is required for token auth on {self.name}")
        if self.auth_mode == "legacy" and self.panel_url and (not self.username or not self.password):
            raise ValueError(f"username/password are required for legacy auth on {self.name}")

    def has_panel_credentials(self) -> bool:
        if not self.panel_url:
            return False
        if self.auth_mode == "token":
            return bool(self.api_token)
        if self.auth_mode == "legacy":
            return bool(self.username and self.password)
        return bool(self.api_token or (self.username and self.password))


@dataclass(slots=True)
class Topology:
    servers: list[Server]
    routes: list[list[str]]
    port_pool: list[int]
    sni_pool: list[str] = field(default_factory=lambda: DEFAULT_SNI_POOL.copy())
    fingerprint: str = "chrome"
    profile: str = "legacy"
    transport: str = "tcp"  # inter-server transport: xhttp | tcp
    transport_locked: bool = False  # True only after user explicitly changes inter-server transport
    inter_server_protocol: str = "auto"  # auto | reality | shadowsocks
    dual_entry: bool = True  # expose both XHTTP and TCP/RAW client inbounds on route entry
    xhttp_mode: str = "auto"
    xhttp_padding: str = "100-1000"
    cascade_id: str = "c1"
    block_private: bool = True
    block_bittorrent: bool = True

    def validate(self) -> None:
        if not self.servers:
            raise ValueError("at least one server is required")
        names: set[str] = set()
        for server in self.servers:
            server.validate()
            if server.name in names:
                raise ValueError(f"duplicate server name: {server.name}")
            names.add(server.name)

        if not self.routes:
            raise ValueError("at least one route is required")
        for i, route in enumerate(self.routes, start=1):
            if not route:
                raise ValueError(f"route {i} is empty")
            unknown = [name for name in route if name not in names]
            if unknown:
                raise ValueError(f"route {i} has unknown servers: {', '.join(unknown)}")
            if len(route) != len(set(route)):
                raise ValueError(f"route {i} contains a loop/repeated server")

        if not self.port_pool:
            raise ValueError("port pool is empty")
        for port in self.port_pool:
            if not (1 <= int(port) <= 65535):
                raise ValueError(f"invalid port: {port}")
        if len(set(self.port_pool)) != len(self.port_pool):
            raise ValueError("port pool contains duplicates")

        if not self.sni_pool:
            raise ValueError("SNI pool is empty")
        for host in self.sni_pool:
            if not HOST_RE.fullmatch(host):
                raise ValueError(f"invalid SNI hostname: {host!r}")

        if self.profile not in {"modern", "legacy"}:
            raise ValueError("profile must be 'modern' or 'legacy'")
        if self.transport not in {"xhttp", "tcp"}:
            raise ValueError("transport must be 'xhttp' or 'tcp'")
        if self.inter_server_protocol not in {"auto", "reality", "shadowsocks"}:
            raise ValueError("inter_server_protocol must be auto, reality or shadowsocks")
        if self.xhttp_mode not in {"auto", "packet-up", "stream-up", "stream-one"}:
            raise ValueError("invalid XHTTP mode")
        if not self.cascade_id or not NAME_RE.fullmatch(self.cascade_id):
            raise ValueError("cascade_id must contain only letters, digits, _, . or -")

    def server_map(self) -> dict[str, Server]:
        return {s.name: s for s in self.servers}

    def to_dict(self, include_secrets: bool = True) -> dict[str, Any]:
        servers: list[dict[str, Any]] = []
        for s in self.servers:
            item = asdict(s)
            if not include_secrets:
                item["api_token"] = ""
                item["password"] = ""
                item["two_factor_code"] = ""
            servers.append(item)
        return {
            "servers": servers,
            "routes": self.routes,
            "port_pool": self.port_pool,
            "sni_pool": self.sni_pool,
            "fingerprint": self.fingerprint,
            "profile": self.profile,
            "transport": self.transport,
            "transport_locked": self.transport_locked,
            "inter_server_protocol": self.inter_server_protocol,
            "dual_entry": self.dual_entry,
            "xhttp_mode": self.xhttp_mode,
            "xhttp_padding": self.xhttp_padding,
            "cascade_id": self.cascade_id,
            "block_private": self.block_private,
            "block_bittorrent": self.block_bittorrent,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Topology":
        server_fields = set(Server.__dataclass_fields__)
        servers: list[Server] = []
        for raw in data.get("servers", []):
            clean = {k: v for k, v in raw.items() if k in server_fields}
            servers.append(Server(**clean))
        topo = cls(
            servers=servers,
            routes=[list(x) for x in data.get("routes", [])],
            port_pool=[int(x) for x in data.get("port_pool", [])],
            sni_pool=list(data.get("sni_pool") or DEFAULT_SNI_POOL),
            fingerprint=str(data.get("fingerprint", "chrome")),
            profile=str(data.get("profile", "legacy")),
            transport=str(data.get("transport", "tcp")),
            transport_locked=bool(data.get("transport_locked", False)),
            inter_server_protocol=str(data.get("inter_server_protocol", "auto")),
            dual_entry=bool(data.get("dual_entry", True)),
            xhttp_mode=str(data.get("xhttp_mode", "auto")),
            xhttp_padding=str(data.get("xhttp_padding", "100-1000")),
            cascade_id=str(data.get("cascade_id", "c1")),
            block_private=bool(data.get("block_private", True)),
            block_bittorrent=bool(data.get("block_bittorrent", True)),
        )
        topo.validate()
        return topo


def parse_port_pool(text: str) -> list[int]:
    """Parse '443,8443,20000-20010' preserving order and removing duplicates."""
    result: list[int] = []
    seen: set[int] = set()
    for token in (x.strip() for x in text.split(",")):
        if not token:
            continue
        if "-" in token:
            a, b = token.split("-", 1)
            lo, hi = int(a), int(b)
            if lo > hi:
                lo, hi = hi, lo
            values = range(lo, hi + 1)
        else:
            values = [int(token)]
        for port in values:
            if not (1 <= port <= 65535):
                raise ValueError(f"port out of range: {port}")
            if port not in seen:
                result.append(port)
                seen.add(port)
    if not result:
        raise ValueError("empty port pool")
    return result


def parse_routes(text: str) -> list[list[str]]:
    """Parse 'entry>middle>exit; backup>exit2'."""
    routes: list[list[str]] = []
    for route_text in text.split(";"):
        route_text = route_text.strip()
        if not route_text:
            continue
        parts = [x.strip() for x in route_text.replace("->", ">").split(">") if x.strip()]
        if not parts:
            continue
        routes.append(parts)
    if not routes:
        raise ValueError("no routes parsed")
    return routes
