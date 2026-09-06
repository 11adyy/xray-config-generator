from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse, urlsplit

from .crypto import RealityCredentials, generate_reality_credentials, public_key_from_private
from .generator import build, render_routes
from .model import Topology
from .panel import PanelClient, PanelError, PanelStatus


@dataclass(slots=True)
class DeployServerResult:
    server: str
    auth: str
    api_style: str
    created_inbounds: list[int] = field(default_factory=list)
    created_tags: list[str] = field(default_factory=list)
    runtime_verified: bool = False


@dataclass(slots=True)
class DeployResult:
    manifest: dict[str, Any]
    servers: list[DeployServerResult]
    output_dir: Path
    remote_sni_pool: list[str] = field(default_factory=list)
    remote_sni_report: dict[str, Any] = field(default_factory=dict)


def _cascade_prefix(topo: Topology) -> str:
    return f"cascade-{topo.cascade_id}-"


def _safe_client_label(text: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-")
    return value[:40] or "cascade"


def _panel_payload(inbound: dict[str, Any], remark: str, *, include_tag: bool = False, extended: bool = False) -> dict[str, Any]:
    """Build a conservative 3x-ui inbound payload.

    The panel API has changed shape several times.  The fields common to old
    and new releases are deliberately emitted first; newer bookkeeping fields
    are opt-in and are only used by the final compatibility attempt.
    """
    settings = json.loads(json.dumps(inbound.get("settings", {})))
    protocol = str(inbound.get("protocol", "vless"))
    if protocol == "vless":
        if "users" in settings and "clients" not in settings:
            settings["clients"] = settings.pop("users")
        settings.setdefault("decryption", "none")
        # Old panels commonly accept fallbacks but do not require the key.
        if settings.get("fallbacks") == []:
            settings.pop("fallbacks", None)

        base_label = _safe_client_label(remark)
        for idx, client in enumerate(settings.get("clients", []), start=1):
            if not isinstance(client, dict):
                continue
            client["email"] = f"cg-{base_label}-{idx}-{secrets.token_hex(3)}"[:64]
            client.setdefault("flow", "")
            client.setdefault("limitIp", 0)
            client.setdefault("totalGB", 0)
            client.setdefault("expiryTime", 0)
            client.setdefault("enable", True)
            client.setdefault("tgId", 0)
            client["subId"] = client.get("subId") or secrets.token_hex(8)
            client.setdefault("comment", "managed by config-generator")
            client.setdefault("reset", 0)
            client.pop("encryption", None)
    elif protocol == "shadowsocks":
        # Single-user classic AEAD Shadowsocks is the compatibility transport
        # for inter-server links. Do not inject VLESS-only fields into it.
        settings.pop("decryption", None)
        settings.pop("clients", None)
        settings.pop("users", None)
        settings.setdefault("network", "tcp")
        settings.setdefault("method", "aes-256-gcm")

    stream = json.loads(json.dumps(inbound.get("streamSettings", {})))
    if "method" in stream and "network" not in stream:
        method = stream.pop("method")
        stream["network"] = "tcp" if method == "raw" else method
        if "rawSettings" in stream and "tcpSettings" not in stream:
            stream["tcpSettings"] = stream.pop("rawSettings")

    sniffing = {
        "enabled": True,
        "destOverride": ["http", "tls", "quic", "fakedns"],
        "metadataOnly": False,
        "routeOnly": False,
    }
    payload: dict[str, Any] = {
        "up": 0,
        "down": 0,
        "total": 0,
        "remark": remark,
        "enable": True,
        "expiryTime": 0,
        # Empty listen is the panel's canonical "all interfaces" value and is
        # understood by significantly older 3x-ui builds than 0.0.0.0 here.
        "listen": "",
        "port": int(inbound["port"]),
        "protocol": inbound.get("protocol", "vless"),
        "settings": json.dumps(settings, separators=(",", ":"), ensure_ascii=False),
        "streamSettings": json.dumps(stream, separators=(",", ":"), ensure_ascii=False),
        "sniffing": json.dumps(sniffing, separators=(",", ":"), ensure_ascii=False),
        # Very old x-ui/3x-ui payloads carried this harmless empty object.
        "allocate": "{}",
    }
    if include_tag:
        payload["tag"] = inbound.get("tag", "")
    if extended:
        payload.update({
            "trafficReset": "never",
            "trafficResetDay": 1,
            "lastTrafficResetTime": 0,
            "shareAddrStrategy": "node",
            "shareAddr": "",
            "subSortIndex": 1,
        })
    return payload


def _json_obj(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return json.loads(json.dumps(value))
    if isinstance(value, str):
        try:
            obj = json.loads(value)
            return obj if isinstance(obj, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _first_vless_client(settings: dict[str, Any]) -> dict[str, Any] | None:
    clients = settings.get("clients") or settings.get("users") or []
    if not isinstance(clients, list):
        return None
    for client in clients:
        if isinstance(client, dict) and client.get("id"):
            return client
    return None


def _first_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str) and item:
                return item
    return ""


def _receiver_material_from_row(row: dict[str, Any], fingerprint: str) -> dict[str, Any]:
    """Extract the live receiver material persisted by 3x-ui.

    Supports VLESS+REALITY and the classic-AEAD Shadowsocks compatibility
    transport used between VPSes when a legacy/mixed panel is detected.
    """
    protocol = str(row.get("protocol", "") or "")
    if row.get("enable") is False:
        raise PanelError(f"existing inbound id={row.get('id')} is disabled and cannot be reused safely")

    settings = _json_obj(row.get("settings", {}))
    stream = _json_obj(row.get("streamSettings", {}))

    if protocol == "shadowsocks":
        method = str(settings.get("method", "") or "")
        password = str(settings.get("password", "") or "")
        network = str(settings.get("network", "tcp") or "tcp")
        if not method or not password:
            raise PanelError(f"existing Shadowsocks inbound id={row.get('id')} lacks method/password")
        return {
            "id": int(row.get("id", 0) or 0),
            "tag": str(row.get("tag", "") or ""),
            "port": int(row.get("port", 0) or 0),
            "protocol": "shadowsocks",
            "network": network,
            "method": method,
            "password": password,
            "server_settings": settings,
            "server_stream": stream,
            "client_stream": {},
        }

    if protocol != "vless":
        raise PanelError(f"existing inbound id={row.get('id')} is neither VLESS nor Shadowsocks")

    client = _first_vless_client(settings)
    if client is None:
        raise PanelError(f"existing inbound id={row.get('id')} has no VLESS client UUID")

    reality = stream.get("realitySettings")
    if not isinstance(reality, dict):
        raise PanelError(f"existing inbound id={row.get('id')} is not REALITY")
    private_key = str(reality.get("privateKey", "") or "")
    if not private_key:
        raise PanelError(f"existing inbound id={row.get('id')} has no REALITY privateKey")
    try:
        public_key = public_key_from_private(private_key)
    except Exception as exc:
        raise PanelError(f"existing inbound id={row.get('id')} has invalid REALITY privateKey: {exc}") from exc

    sni = _first_string(reality.get("serverNames")) or str(reality.get("serverName", "") or "")
    short_id = _first_string(reality.get("shortIds")) or str(reality.get("shortId", "") or "")
    if not sni or not short_id:
        raise PanelError(f"existing inbound id={row.get('id')} lacks REALITY serverName/shortId")

    network = str(stream.get("network") or stream.get("method") or "tcp")
    xhttp = _json_obj(stream.get("xhttpSettings", {}))
    tcp = _json_obj(stream.get("tcpSettings", {}))
    raw = _json_obj(stream.get("rawSettings", {}))
    flow = str(client.get("flow", "") or "")

    client_reality: dict[str, Any] = {
        "serverName": sni,
        "fingerprint": fingerprint,
        "shortId": short_id,
        "spiderX": "/",
        "password": public_key,
        "publicKey": public_key,
    }
    client_stream: dict[str, Any] = {
        "network": network,
        "security": "reality",
        "realitySettings": client_reality,
    }
    if network == "xhttp":
        client_stream["xhttpSettings"] = xhttp
        flow = ""
    elif network == "raw":
        client_stream["rawSettings"] = raw or {"header": {"type": "none"}}
    else:
        client_stream["network"] = "tcp"
        client_stream["tcpSettings"] = tcp or {"header": {"type": "none"}}

    return {
        "id": int(row.get("id", 0) or 0),
        "tag": str(row.get("tag", "") or ""),
        "port": int(row.get("port", 0) or 0),
        "protocol": "vless",
        "uuid": str(client.get("id")),
        "flow": flow,
        "sni": sni,
        "short_id": short_id,
        "public_key": public_key,
        "network": client_stream["network"],
        "server_stream": stream,
        "server_settings": settings,
        "client_stream": client_stream,
    }


def _patch_vless_outbound_for_receiver(
    outbound: dict[str, Any], desired_key: str, receiver: dict[str, Any], target_ip: str
) -> bool:
    """Patch an outbound to the receiver persisted by the panel.

    desired_key is the generated VLESS UUID or Shadowsocks password, used only
    to correlate the outbound before replacing it with the panel-authoritative
    receiver values.
    """
    protocol = str(receiver.get("protocol", "vless"))
    if protocol == "shadowsocks":
        if str(outbound.get("protocol", "")) != "shadowsocks":
            return False
        settings = outbound.get("settings")
        if not isinstance(settings, dict) or str(settings.get("password", "")) != desired_key:
            return False
        settings["address"] = target_ip
        settings["port"] = int(receiver["port"])
        settings["method"] = receiver["method"]
        settings["password"] = receiver["password"]
        outbound.pop("streamSettings", None)
        return True

    if str(outbound.get("protocol", "")) != "vless":
        return False
    settings = outbound.get("settings")
    if not isinstance(settings, dict):
        return False
    vnext = settings.get("vnext")
    if isinstance(vnext, list) and vnext and isinstance(vnext[0], dict):
        users = vnext[0].get("users")
        if not isinstance(users, list) or not users or not isinstance(users[0], dict):
            return False
        if str(users[0].get("id", "")) != desired_key:
            return False
        vnext[0]["address"] = target_ip
        vnext[0]["port"] = int(receiver["port"])
        users[0]["id"] = receiver["uuid"]
        users[0]["encryption"] = "none"
        users[0]["flow"] = receiver["flow"]
    else:
        if str(settings.get("id", "")) != desired_key:
            return False
        settings["address"] = target_ip
        settings["port"] = int(receiver["port"])
        settings["id"] = receiver["uuid"]
        settings["encryption"] = "none"
        settings["flow"] = receiver["flow"]
    outbound["streamSettings"] = json.loads(json.dumps(receiver["client_stream"]))
    return True


def _receiver_share_uri(receiver: dict[str, Any], target_ip: str, fingerprint: str, label: str) -> str:
    network = str(receiver["network"])
    if network == "xhttp":
        xh = receiver["client_stream"].get("xhttpSettings", {})
        host = str(xh.get("host") or receiver["sni"])
        path = str(xh.get("path") or "/")
        mode = str(xh.get("mode") or "auto")
        padding = str(xh.get("xPaddingBytes") or "100-1000")
        extra = json.dumps({
            "headers": xh.get("headers") or {"User-Agent": "Mozilla/5.0"},
            "mode": mode,
            "xPaddingBytes": padding,
        }, separators=(",", ":"))
        query = (
            f"encryption=none&security=reality&pbk={quote(receiver['public_key'])}"
            f"&fp={quote(fingerprint)}&sni={quote(receiver['sni'])}"
            f"&sid={quote(receiver['short_id'])}&type=xhttp"
            f"&host={quote(host)}&path={quote(path)}&mode={quote(mode)}"
            f"&x_padding_bytes={quote(padding)}&extra={quote(extra)}"
        )
    else:
        query = (
            f"type=tcp&security=reality&pbk={quote(receiver['public_key'])}"
            f"&fp={quote(fingerprint)}&sni={quote(receiver['sni'])}"
            f"&sid={quote(receiver['short_id'])}&flow={quote(receiver['flow'])}"
        )
    return (
        f"vless://{receiver['uuid']}@{target_ip}:{receiver['port']}?{query}#{quote(label)}"
    )


def _reuse_existing_receiver(
    *,
    configs: dict[str, dict[str, Any]],
    client_profiles: dict[str, dict[str, Any]],
    manifest: dict[str, Any],
    server_name: str,
    server_ip: str,
    generated_inbound: dict[str, Any],
    existing_row: dict[str, Any],
    fingerprint: str,
) -> dict[str, Any]:
    """Adapt predecessors to the receiver actually persisted by 3x-ui."""
    generated_protocol = str(generated_inbound.get("protocol", "vless"))
    generated_port = int(generated_inbound.get("port", 0) or 0)
    gen_settings = generated_inbound.get("settings", {})
    if not isinstance(gen_settings, dict):
        raise PanelError("generated inbound has invalid settings")

    if generated_protocol == "vless":
        gen_client = _first_vless_client(gen_settings)
        if gen_client is None:
            raise PanelError("generated inbound has no VLESS client")
        desired_key = str(gen_client.get("id", ""))
    elif generated_protocol == "shadowsocks":
        desired_key = str(gen_settings.get("password", "") or "")
        if not desired_key:
            raise PanelError("generated Shadowsocks inbound has no password")
    else:
        raise PanelError(f"unsupported generated receiver protocol {generated_protocol!r}")

    receiver = _receiver_material_from_row(existing_row, fingerprint)
    if str(receiver.get("protocol")) != generated_protocol:
        raise PanelError(
            f"existing inbound id={receiver['id']} protocol {receiver.get('protocol')!r} "
            f"does not match requested {generated_protocol!r}; refusing immutable reuse"
        )

    if generated_protocol == "vless":
        generated_stream = _json_obj(generated_inbound.get("streamSettings", {}))
        desired_network = str(generated_stream.get("network") or generated_stream.get("method") or "tcp")
        actual_network = str(receiver.get("network") or "tcp")
        normalize_network = lambda value: "tcp" if value == "raw" else value
        if normalize_network(desired_network) != normalize_network(actual_network):
            raise PanelError(
                f"existing inbound id={receiver['id']} transport {actual_network!r} "
                f"does not match requested {desired_network!r}; refusing immutable reuse"
            )

    patched = 0
    for cfg in configs.values():
        for outbound in cfg.get("outbounds", []):
            if isinstance(outbound, dict) and _patch_vless_outbound_for_receiver(
                outbound, desired_key, receiver, server_ip
            ):
                patched += 1
    for profile in client_profiles.values():
        for outbound in profile.get("outbounds", []):
            if isinstance(outbound, dict) and _patch_vless_outbound_for_receiver(
                outbound, desired_key, receiver, server_ip
            ):
                patched += 1

    generated_inbound.clear()
    generated_inbound.update({
        "listen": existing_row.get("listen") or "0.0.0.0",
        "port": receiver["port"],
        "protocol": receiver["protocol"],
        "tag": receiver["tag"],
        "settings": json.loads(json.dumps(receiver["server_settings"])),
        "streamSettings": json.loads(json.dumps(receiver["server_stream"])),
    })

    for route in manifest.get("routes", []):
        if not isinstance(route, dict):
            continue
        route_name = str(route.get("name", "route"))
        for hop in route.get("hops", []):
            if not isinstance(hop, dict):
                continue
            # Internal Shadowsocks hops have no UUID correlation; destination
            # server + originally allocated port is unique on that VPS.
            match = False
            if generated_protocol == "vless" and str(hop.get("uuid", "")) == desired_key:
                match = True
            elif generated_protocol == "shadowsocks" and str(hop.get("to", "")) == server_name and int(hop.get("port", 0) or 0) == generated_port:
                match = True
            if not match:
                continue
            hop.update({
                "to": server_name,
                "ip": server_ip,
                "port": receiver["port"],
                "protocol": receiver["protocol"],
                "transport": receiver.get("network", "tcp"),
                "reused_existing_inbound": receiver["id"],
            })
            if receiver["protocol"] == "vless":
                hop.update({
                    "sni": receiver["sni"],
                    "uuid": receiver["uuid"],
                    "short_id": receiver["short_id"],
                    "public_key": receiver["public_key"],
                })
            else:
                hop.update({"sni": "", "uuid": "", "short_id": "", "public_key": ""})

        # Client entries are always VLESS/REALITY and therefore only need the
        # VLESS branch here.
        if generated_protocol == "vless":
            entries = route.get("client_entries")
            if not isinstance(entries, list):
                entry = route.get("client_entry")
                entries = [entry] if isinstance(entry, dict) else []
            for entry in entries:
                if isinstance(entry, dict) and str(entry.get("uuid", "")) == desired_key:
                    label = str(entry.get("profile") or f"{route_name}-{receiver['network']}")
                    entry.update({
                        "server": server_name,
                        "ip": server_ip,
                        "port": receiver["port"],
                        "uuid": receiver["uuid"],
                        "sni": receiver["sni"],
                        "short_id": receiver["short_id"],
                        "public_key": receiver["public_key"],
                        "transport": receiver["network"],
                        "reused_existing_inbound": receiver["id"],
                        "uri": _receiver_share_uri(receiver, server_ip, fingerprint, label),
                    })
            if isinstance(route.get("client_entries"), list) and route["client_entries"]:
                route["client_entry"] = route["client_entries"][0]

    if patched == 0:
        raise PanelError(
            f"cannot correlate existing inbound id={receiver['id']} with generated predecessor/client"
        )
    return receiver


def _row_client_email(row: dict[str, Any], uuid: str = "") -> str:
    settings = _json_obj(row.get("settings", {}))
    clients = settings.get("clients") or settings.get("users") or []
    if not isinstance(clients, list):
        return ""
    for client in clients:
        if not isinstance(client, dict):
            continue
        if uuid and str(client.get("id", "")) != uuid:
            continue
        email = str(client.get("email", "") or "")
        if email:
            return email
    return ""


def _row_for_entry(rows: list[dict[str, Any]], entry: dict[str, Any]) -> dict[str, Any] | None:
    uuid = str(entry.get("uuid", ""))
    port = int(entry.get("port", 0) or 0)
    for row in rows:
        if int(row.get("port", -1) or -1) != port:
            continue
        settings = _json_obj(row.get("settings", {}))
        client = _first_vless_client(settings)
        if client is not None and str(client.get("id", "")) == uuid:
            return row
    return None


def _reality_metadata_is_sane(row: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
    stream = _json_obj(row.get("streamSettings", {}))
    reality = stream.get("realitySettings") if isinstance(stream, dict) else None
    if not isinstance(reality, dict):
        return False, "REALITY settings missing", {}
    private = str(reality.get("privateKey", "") or "")
    if not private:
        return False, "privateKey is empty", reality
    try:
        expected_public = public_key_from_private(private)
    except Exception as exc:
        return False, f"privateKey cannot be converted to public key: {exc}", reality
    names = reality.get("serverNames") or []
    if not isinstance(names, list) or not names or not isinstance(names[0], str) or not names[0]:
        return False, "serverNames is empty", reality
    for value in [str(reality.get("target", "") or ""), str(reality.get("dest", "") or "")] + [str(x) for x in names]:
        low = value.lower()
        if "http://" in low or "https://" in low or "](" in value or "[" in value or "]" in value:
            return False, f"REALITY target/serverName was mangled by panel: {value!r}", reality
    ids = reality.get("shortIds") or []
    if not isinstance(ids, list) or not ids or not isinstance(ids[0], str):
        return False, "shortIds is empty", reality
    sid = ids[0]
    if len(sid) > 16 or len(sid) % 2 or any(ch not in "0123456789abcdefABCDEF" for ch in sid):
        return False, f"invalid shortId {sid!r}", reality
    meta = reality.get("settings")
    got_public = str(meta.get("publicKey", "") or "") if isinstance(meta, dict) else ""
    if got_public != expected_public:
        return False, f"QR publicKey mismatch: stored={got_public or '<empty>'}, derived={expected_public}", reality
    return True, "ok", reality


def _repair_entry_qr_metadata(client: PanelClient, row: dict[str, Any], server_ip: str, fingerprint: str) -> dict[str, Any]:
    """Make 3x-ui's own QR metadata match the REALITY private key it runs."""
    stream = _json_obj(row.get("streamSettings", {}))
    reality = stream.get("realitySettings") if isinstance(stream, dict) else None
    if not isinstance(reality, dict):
        raise PanelError(f"inbound id={row.get('id')}: REALITY settings missing")
    private = str(reality.get("privateKey", "") or "")
    public = public_key_from_private(private)
    sni = _first_string(reality.get("serverNames")) or str(reality.get("serverName", "") or "")
    meta = reality.get("settings")
    if not isinstance(meta, dict):
        meta = {}
        reality["settings"] = meta
    meta["publicKey"] = public
    meta["fingerprint"] = fingerprint
    meta["serverName"] = sni
    meta.setdefault("spiderX", "/")
    payload = _restore_payload_from_row(row)
    payload["streamSettings"] = json.dumps(stream, separators=(",", ":"), ensure_ascii=False)
    payload["shareAddrStrategy"] = "custom"
    payload["shareAddr"] = server_ip
    inbound_id = int(row.get("id", 0) or 0)
    if not inbound_id:
        raise PanelError("cannot repair QR metadata: inbound id missing")
    client.update_inbound(inbound_id, payload)
    rows = client.list_inbounds()
    fixed = next((r for r in rows if int(r.get("id", -1) or -1) == inbound_id), None)
    if not isinstance(fixed, dict):
        raise PanelError(f"cannot repair QR metadata: inbound id={inbound_id} disappeared")
    return fixed


def _validate_vless_uri(link: str, entry: dict[str, Any], server_ip: str) -> list[str]:
    errors: list[str] = []
    try:
        parsed = urlsplit(link)
    except Exception as exc:
        return [f"cannot parse vless URI: {exc}"]
    if parsed.scheme.lower() != "vless":
        return ["not a vless:// URI"]
    uuid = parsed.username or ""
    if uuid != str(entry.get("uuid", "")):
        errors.append(f"uuid mismatch ({uuid} != {entry.get('uuid')})")
    if (parsed.hostname or "") != server_ip:
        errors.append(f"host mismatch ({parsed.hostname} != {server_ip})")
    if int(parsed.port or 0) != int(entry.get("port", 0) or 0):
        errors.append(f"port mismatch ({parsed.port} != {entry.get('port')})")
    qs = parse_qs(parsed.query, keep_blank_values=True)
    one = lambda key: (qs.get(key) or [""])[0]
    if one("security") != "reality":
        errors.append(f"security={one('security')!r}, expected reality")
    if one("pbk") != str(entry.get("public_key", "")):
        errors.append("pbk does not match public key derived from server privateKey")
    if one("sni") != str(entry.get("sni", "")):
        errors.append(f"sni mismatch ({one('sni')!r} != {entry.get('sni')!r})")
    if one("sid") != str(entry.get("short_id", "")):
        errors.append(f"sid mismatch ({one('sid')!r} != {entry.get('short_id')!r})")
    expected_transport = str(entry.get("transport", "tcp"))
    got_type = one("type") or "tcp"
    if expected_transport == "xhttp" and got_type != "xhttp":
        errors.append(f"type mismatch ({got_type!r} != 'xhttp')")
    if expected_transport in {"tcp", "raw"} and got_type not in {"tcp", "raw"}:
        errors.append(f"type mismatch ({got_type!r} is not TCP/RAW)")
    if expected_transport == "xhttp" and one("flow"):
        errors.append("XHTTP QR unexpectedly contains a non-empty flow")
    return errors


def _outbound_from_vless_uri(link: str) -> dict[str, Any]:
    p = urlsplit(link)
    if p.scheme.lower() != "vless" or not p.hostname or not p.port or not p.username:
        raise PanelError("cannot build outbound from malformed vless URI")
    qs = parse_qs(p.query, keep_blank_values=True)
    one = lambda key, default="": (qs.get(key) or [default])[0]
    transport = one("type", "tcp") or "tcp"
    flow = one("flow", "")
    user = {"id": p.username, "encryption": one("encryption", "none") or "none", "flow": flow}
    outbound: dict[str, Any] = {
        "protocol": "vless",
        "tag": "cascadegen-qr-probe",
        "settings": {"vnext": [{"address": p.hostname, "port": int(p.port), "users": [user]}]},
        "streamSettings": {
            "network": "xhttp" if transport == "xhttp" else "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": one("sni"),
                "fingerprint": one("fp", "chrome") or "chrome",
                "shortId": one("sid"),
                "spiderX": one("spx", "/") or "/",
                "password": one("pbk"),
                "publicKey": one("pbk"),
            },
        },
    }
    if transport == "xhttp":
        xh: dict[str, Any] = {
            "host": one("host") or one("sni"),
            "path": one("path", "/") or "/",
            "mode": one("mode", "auto") or "auto",
        }
        padding = one("x_padding_bytes")
        if padding:
            xh["xPaddingBytes"] = padding
        extra = one("extra")
        if extra:
            try:
                obj = json.loads(extra)
                if isinstance(obj, dict):
                    for key in ("headers", "mode", "xPaddingBytes"):
                        if key in obj:
                            xh[key] = obj[key]
            except json.JSONDecodeError:
                pass
        outbound["streamSettings"]["xhttpSettings"] = xh
        user["flow"] = ""
    else:
        outbound["streamSettings"]["tcpSettings"] = {"header": {"type": "none"}}
    return outbound


def _panel_qr_preflight(
    topo: Topology,
    manifest: dict[str, Any],
    clients: dict[str, PanelClient],
    output_dir: Path,
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    """Validate the exact URLs that the 3x-ui QR/Copy URL UI will export."""
    report: list[dict[str, Any]] = []
    qr_links: dict[str, list[str]] = {}
    server_map = {s.name: s for s in topo.servers}
    for route in manifest.get("routes", []):
        if not isinstance(route, dict):
            continue
        for entry in route.get("client_entries", []) or []:
            if not isinstance(entry, dict):
                continue
            server_name = str(entry.get("server", ""))
            server = server_map.get(server_name)
            if server is None:
                continue
            panel = clients[server_name]
            rows = panel.list_inbounds()
            row = _row_for_entry(rows, entry)
            if row is None:
                raise PanelError(f"{server_name}: cannot locate entry inbound for panel QR verification")
            sane, reason, _ = _reality_metadata_is_sane(row)
            repaired = False
            if not sane and "QR publicKey mismatch" in reason:
                try:
                    row = _repair_entry_qr_metadata(panel, row, server.ip, topo.fingerprint)
                    repaired = True
                    sane, reason, _ = _reality_metadata_is_sane(row)
                except Exception as exc:
                    raise PanelError(f"{server_name}: panel QR metadata is wrong and repair failed: {reason}; {exc}") from exc
            if not sane:
                raise PanelError(f"{server_name}: unsafe/broken REALITY metadata before QR export: {reason}")
            email = _row_client_email(row, str(entry.get("uuid", "")))
            if not email:
                # Old panel rows may predate email-based client links API.
                report.append({"server": server_name, "transport": entry.get("transport"), "status": "skipped", "reason": "client email unavailable"})
                continue
            links = panel.get_client_links(email)
            if links is None:
                report.append({"server": server_name, "transport": entry.get("transport"), "email": email, "status": "skipped", "reason": "panel links API unavailable"})
                continue
            candidates = [u for u in links if isinstance(u, str) and u.startswith("vless://")]
            valid: list[str] = []
            failures: list[dict[str, Any]] = []
            for link in candidates:
                errs = _validate_vless_uri(link, entry, server.ip)
                if not errs:
                    valid.append(link)
                else:
                    failures.append({"link": link, "errors": errs})
            report.append({
                "server": server_name,
                "transport": entry.get("transport"),
                "email": email,
                "repaired_metadata": repaired,
                "status": "pass" if valid else "fail",
                "links_returned": len(candidates),
                "failures": failures,
            })
            if not valid:
                raise PanelError(
                    f"{server_name}: 3x-ui QR/Copy URL does not match the live REALITY inbound "
                    f"for {entry.get('transport')}; see PANEL_QR_CHECKS.json"
                )
            key = str(entry.get("profile") or f"{route.get('name','route')}-{entry.get('transport','client')}")
            qr_links[key] = valid
    (output_dir / "PANEL_QR_CHECKS.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report, qr_links



def _static_chain_consistency(
    topo: Topology,
    manifest: dict[str, Any],
    clients: dict[str, PanelClient],
    configs: dict[str, dict[str, Any]],
    output_dir: Path,
) -> list[dict[str, Any]]:
    """Compare every installed hop outbound with the destination panel row."""
    report: list[dict[str, Any]] = []
    failures: list[str] = []
    server_map = topo.server_map()
    rows_cache: dict[str, list[dict[str, Any]]] = {
        name: client.list_inbounds() for name, client in clients.items()
    }

    def outbound_fields(ob: dict[str, Any]) -> dict[str, Any]:
        protocol = str(ob.get("protocol", "") or "")
        settings = ob.get("settings") if isinstance(ob.get("settings"), dict) else {}
        if protocol == "shadowsocks":
            return {
                "protocol": "shadowsocks",
                "address": str(settings.get("address", "") or ""),
                "port": int(settings.get("port", 0) or 0),
                "method": str(settings.get("method", "") or ""),
                "password": str(settings.get("password", "") or ""),
                "network": "tcp",
            }

        address = ""
        port = 0
        uuid = ""
        flow = ""
        if isinstance(settings.get("vnext"), list) and settings["vnext"]:
            node = settings["vnext"][0] if isinstance(settings["vnext"][0], dict) else {}
            address = str(node.get("address", "") or "")
            port = int(node.get("port", 0) or 0)
            users = node.get("users") if isinstance(node.get("users"), list) else []
            user = users[0] if users and isinstance(users[0], dict) else {}
            uuid = str(user.get("id", "") or "")
            flow = str(user.get("flow", "") or "")
        else:
            address = str(settings.get("address", "") or "")
            port = int(settings.get("port", 0) or 0)
            uuid = str(settings.get("id", "") or "")
            flow = str(settings.get("flow", "") or "")
        stream = _json_obj(ob.get("streamSettings", {}))
        network = str(stream.get("network") or stream.get("method") or "tcp")
        reality = stream.get("realitySettings") if isinstance(stream.get("realitySettings"), dict) else {}
        return {
            "protocol": "vless",
            "address": address,
            "port": port,
            "uuid": uuid,
            "flow": flow,
            "network": "tcp" if network == "raw" else network,
            "sni": str(reality.get("serverName", "") or ""),
            "short_id": str(reality.get("shortId", "") or ""),
            "public_key": str(reality.get("password") or reality.get("publicKey") or ""),
        }

    for route in manifest.get("routes", []):
        if not isinstance(route, dict):
            continue
        route_name = str(route.get("name", "route"))
        hops = route.get("hops") if isinstance(route.get("hops"), list) else []
        for hop in hops:
            if not isinstance(hop, dict):
                continue
            source = str(hop.get("from", ""))
            dest = str(hop.get("to", ""))
            if source == "client" or source not in configs or dest not in clients:
                continue

            expected_suffix = f"-to-{dest}"
            outbound = next((
                ob for ob in configs[source].get("outbounds", [])
                if isinstance(ob, dict)
                and str(ob.get("tag", "")).startswith(f"cascade-{topo.cascade_id}-")
                and str(ob.get("tag", "")).endswith(expected_suffix)
            ), None)
            if outbound is None:
                failures.append(f"{source}->{dest}: outbound missing")
                report.append({"route": route_name, "source": source, "dest": dest, "status": "fail", "error": "outbound missing"})
                continue

            fields = outbound_fields(outbound)
            dest_rows = rows_cache.get(dest, [])
            receiver_row = None
            for row in dest_rows:
                if not isinstance(row, dict) or row.get("enable") is False:
                    continue
                try:
                    if int(row.get("port", -1) or -1) != int(fields["port"]):
                        continue
                except Exception:
                    continue
                if str(row.get("protocol", "")) != fields["protocol"]:
                    continue
                row_settings = _json_obj(row.get("settings", {}))
                if fields["protocol"] == "shadowsocks":
                    if str(row_settings.get("method", "")) == fields["method"] and str(row_settings.get("password", "")) == fields["password"]:
                        receiver_row = row
                        break
                else:
                    client = _first_vless_client(row_settings)
                    if client is not None and str(client.get("id", "")) == fields["uuid"]:
                        receiver_row = row
                        break

            if receiver_row is None:
                failures.append(f"{source}->{dest}: no matching live receiver on port={fields['port']}")
                report.append({
                    "route": route_name, "source": source, "dest": dest, "status": "fail",
                    "outbound": {k: ("***" if k == "password" else v) for k, v in fields.items()},
                    "error": "matching destination inbound not found",
                })
                continue

            try:
                receiver = _receiver_material_from_row(receiver_row, topo.fingerprint)
            except Exception as exc:
                failures.append(f"{source}->{dest}: cannot parse live receiver: {exc}")
                report.append({"route": route_name, "source": source, "dest": dest, "status": "fail", "error": str(exc)})
                continue

            expected_ip = server_map[dest].ip
            if fields["protocol"] == "shadowsocks":
                checks = {
                    "address": fields["address"] == expected_ip,
                    "port": int(fields["port"]) == int(receiver["port"]),
                    "protocol": receiver.get("protocol") == "shadowsocks",
                    "method": fields["method"] == receiver["method"],
                    "password": fields["password"] == receiver["password"],
                }
                outbound_report = {k: ("***" if k == "password" else v) for k, v in fields.items()}
                receiver_report = {
                    "id": receiver["id"], "tag": receiver["tag"], "port": receiver["port"],
                    "protocol": receiver["protocol"], "network": receiver["network"],
                    "method": receiver["method"], "password": "***",
                }
            else:
                checks = {
                    "address": fields["address"] == expected_ip,
                    "port": int(fields["port"]) == int(receiver["port"]),
                    "uuid": fields["uuid"] == receiver["uuid"],
                    "flow": fields["flow"] == receiver["flow"],
                    "transport": fields["network"] == ("tcp" if receiver["network"] == "raw" else receiver["network"]),
                    "sni": fields["sni"] == receiver["sni"],
                    "short_id": fields["short_id"] == receiver["short_id"],
                    "public_key": fields["public_key"] == receiver["public_key"],
                }
                outbound_report = fields
                receiver_report = {
                    "id": receiver["id"], "tag": receiver["tag"], "port": receiver["port"],
                    "protocol": receiver["protocol"], "uuid": receiver["uuid"], "flow": receiver["flow"],
                    "network": receiver["network"], "sni": receiver["sni"],
                    "short_id": receiver["short_id"], "public_key": receiver["public_key"],
                }
            ok = all(checks.values())
            report.append({
                "route": route_name, "source": source, "dest": dest,
                "status": "pass" if ok else "fail", "checks": checks,
                "outbound": outbound_report, "receiver": receiver_report,
            })
            if not ok:
                bad = ", ".join(k for k, value in checks.items() if not value)
                failures.append(f"{source}->{dest}: static mismatch: {bad}")

    (output_dir / "STATIC_CHAIN_AUDIT.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if failures:
        raise PanelError("static cascade pairing failed: " + " | ".join(failures))
    return report


def _probe_result_ok(obj: Any) -> tuple[bool, str]:
    """Interpret 3x-ui OutboundTestResult rather than only the outer API envelope.

    /xray/testOutbound can return HTTP/API success while obj.success is false.
    Treat the nested result as authoritative; older panels that return a
    scalar/object without a success field are accepted for compatibility.
    """
    if isinstance(obj, dict) and "success" in obj:
        ok = bool(obj.get("success"))
        return ok, str(obj.get("error", "") or "")
    return True, ""


def _audit_chain_suffixes(
    topo: Topology,
    manifest: dict[str, Any],
    clients: dict[str, PanelClient],
    configs: dict[str, dict[str, Any]],
    output_dir: Path,
) -> list[dict[str, Any]]:
    """Probe exit egress and each installed cascade suffix from the owning VPS.

    A source->destination outbound test reaches the destination's live inbound,
    whose routing then continues through the rest of the cascade.  Testing from
    the tail backwards therefore localizes the first broken suffix without
    requiring verbose Xray logs.
    """
    report: list[dict[str, Any]] = []
    failures: list[str] = []

    # First prove plain Internet egress on every route exit.  Backend supports
    # freedom even though the 3x-ui frontend normally skips it in Test All.
    seen_exits: set[str] = set()
    for route in manifest.get("routes", []):
        if not isinstance(route, dict):
            continue
        path = [str(x) for x in route.get("path", [])]
        if not path:
            continue
        exit_name = path[-1]
        if exit_name not in seen_exits and exit_name in clients:
            seen_exits.add(exit_name)
            direct = {"tag": "cascadegen-diagnostic-direct", "protocol": "freedom", "settings": {"domainStrategy": "AsIs"}}
            try:
                obj = clients[exit_name].test_outbound(direct, all_outbounds=[direct], mode="real")
                if obj is None:
                    report.append({"stage": "exit-direct", "server": exit_name, "status": "skipped", "reason": "testOutbound unavailable"})
                else:
                    ok, err = _probe_result_ok(obj)
                    # Current 3x-ui explicitly refuses to test freedom/DNS
                    # outbounds and returns success=false with this message.
                    # That is a diagnostic API limitation, not a broken exit.
                    unsupported_direct = (
                        not ok
                        and "direct/dns outbound cannot be tested" in err.lower()
                    )
                    if unsupported_direct:
                        report.append({
                            "stage": "exit-direct",
                            "server": exit_name,
                            "status": "skipped",
                            "reason": "3x-ui testOutbound does not support freedom/direct; egress is verified transitively by the tail hop",
                            "result": obj,
                        })
                    else:
                        report.append({"stage": "exit-direct", "server": exit_name, "status": "pass" if ok else "fail", "result": obj})
                        if not ok:
                            failures.append(f"{exit_name} direct egress: {err or 'probe returned success=false'}")
            except PanelError as exc:
                # Some panel versions reject freedom/direct at the HTTP layer.
                # Treat only that known capability limitation as skipped.
                msg = str(exc)
                if "direct/dns outbound cannot be tested" in msg.lower():
                    report.append({
                        "stage": "exit-direct",
                        "server": exit_name,
                        "status": "skipped",
                        "reason": "3x-ui testOutbound does not support freedom/direct; egress is verified transitively by the tail hop",
                        "error": msg,
                    })
                else:
                    report.append({"stage": "exit-direct", "server": exit_name, "status": "fail", "error": msg})
                    failures.append(f"{exit_name} direct egress: {exc}")

        # Probe each suffix from tail to head.  Example: middle->exit first,
        # then entry->middle.  The first failing suffix identifies the hop.
        for i in range(len(path) - 2, -1, -1):
            source, dest = path[i], path[i + 1]
            panel = clients.get(source)
            if panel is None:
                report.append({"stage": "hop", "source": source, "dest": dest, "status": "skipped", "reason": "panel unavailable"})
                continue
            cfg = configs.get(source, {})
            outbound = None
            expected_suffix = f"-to-{dest}"
            for ob in cfg.get("outbounds", []) if isinstance(cfg, dict) else []:
                if not isinstance(ob, dict):
                    continue
                tag = str(ob.get("tag", ""))
                if tag.startswith(f"cascade-{topo.cascade_id}-") and tag.endswith(expected_suffix):
                    outbound = ob
                    break
            if outbound is None:
                report.append({"stage": "hop", "source": source, "dest": dest, "status": "fail", "error": "generated cascade outbound not found"})
                failures.append(f"{source}->{dest}: generated outbound not found")
                continue
            try:
                all_obs = [ob for ob in cfg.get("outbounds", []) if isinstance(ob, dict)]
                obj = panel.test_outbound(outbound, all_outbounds=all_obs, mode="real")
                if obj is None:
                    report.append({"stage": "hop", "source": source, "dest": dest, "tag": outbound.get("tag"), "status": "skipped", "reason": "testOutbound unavailable"})
                    continue
                ok, err = _probe_result_ok(obj)
                report.append({"stage": "hop", "source": source, "dest": dest, "tag": outbound.get("tag"), "status": "pass" if ok else "fail", "result": obj})
                if not ok:
                    failures.append(f"{source}->{dest}: {err or 'probe returned success=false'}")
            except PanelError as exc:
                report.append({"stage": "hop", "source": source, "dest": dest, "tag": outbound.get("tag"), "status": "fail", "error": str(exc)})
                failures.append(f"{source}->{dest}: {exc}")

    # If direct testing was unsupported but the final upstream hop reached
    # HTTP 204 through the exit, then the exit's direct egress has in fact
    # been exercised successfully. Upgrade the diagnostic entry to PASS.
    for item in report:
        if item.get("stage") != "exit-direct" or item.get("status") != "skipped":
            continue
        exit_name = str(item.get("server", ""))
        proven = False
        for hop in report:
            if hop.get("stage") != "hop" or hop.get("dest") != exit_name or hop.get("status") != "pass":
                continue
            result = hop.get("result") if isinstance(hop.get("result"), dict) else {}
            status_code = result.get("httpStatus", result.get("statusCode"))
            if result.get("success") is True and status_code == 204:
                proven = True
                break
        if proven:
            item["status"] = "pass"
            item["inferred"] = True
            item["reason"] = "3x-ui cannot test freedom/direct directly; successful tail-hop HTTP 204 proves exit egress"

    (output_dir / "CHAIN_AUDIT.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if failures:
        raise PanelError("cascade chain audit failed: " + " | ".join(failures))
    return report


def _probe_qr_links_end_to_end(
    topo: Topology,
    manifest: dict[str, Any],
    clients: dict[str, PanelClient],
    qr_links: dict[str, list[str]],
    output_dir: Path,
) -> list[dict[str, Any]]:
    """Run the exact panel QR outbound through a remote 3x-ui/Xray probe."""
    report: list[dict[str, Any]] = []
    for route in manifest.get("routes", []):
        if not isinstance(route, dict):
            continue
        path = [str(x) for x in route.get("path", [])]
        entry_server = path[0] if path else ""
        for entry in route.get("client_entries", []) or []:
            if not isinstance(entry, dict):
                continue
            profile = str(entry.get("profile") or f"{route.get('name','route')}-{entry.get('transport','client')}")
            links = qr_links.get(profile) or []
            if not links:
                report.append({"route": route.get("name"), "transport": entry.get("transport"), "status": "skipped", "reason": "panel QR links API unavailable"})
                continue
            outbound = _outbound_from_vless_uri(links[0])
            candidates = [name for name in reversed(path) if name != entry_server]
            candidates += [name for name in path if name not in candidates]
            tested = False
            for source in candidates:
                panel = clients.get(source)
                if panel is None:
                    continue
                try:
                    obj = panel.test_outbound(outbound, all_outbounds=[outbound], mode="real")
                except PanelError as exc:
                    report.append({"route": route.get("name"), "transport": entry.get("transport"), "source": source, "status": "fail", "error": str(exc)})
                    (output_dir / "HOP_TESTS.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    raise PanelError(
                        f"end-to-end QR probe failed for {route.get('name')} {entry.get('transport')} from {source}: {exc}"
                    ) from exc
                if obj is None:
                    continue
                tested = True
                ok, err = _probe_result_ok(obj)
                report.append({"route": route.get("name"), "transport": entry.get("transport"), "source": source, "status": "pass" if ok else "fail", "result": obj})
                if not ok:
                    (output_dir / "HOP_TESTS.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                    raise PanelError(
                        f"end-to-end QR probe failed for {route.get('name')} {entry.get('transport')} from {source}: "
                        f"{err or 'testOutbound returned success=false'}"
                    )
                break
            if not tested:
                report.append({"route": route.get("name"), "transport": entry.get("transport"), "status": "skipped", "reason": "no panel with testOutbound capability"})
    (output_dir / "HOP_TESTS.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return report


def _restore_payload_from_row(row: dict[str, Any]) -> dict[str, Any]:
    """Convert a list-inbounds row back to an add-inbound payload.

    Used only for rollback after replacing an older deployment with the same
    cascade id.  Keeping this small whitelist also avoids replaying read-only
    traffic/statistics fields from newer panel versions into older ones.
    """
    payload: dict[str, Any] = {
        "up": int(row.get("up", 0) or 0),
        "down": int(row.get("down", 0) or 0),
        "total": int(row.get("total", 0) or 0),
        "remark": str(row.get("remark", "")),
        "enable": bool(row.get("enable", True)),
        "expiryTime": int(row.get("expiryTime", 0) or 0),
        "trafficReset": str(row.get("trafficReset", "never") or "never"),
        "trafficResetDay": int(row.get("trafficResetDay", 1) or 1),
        "lastTrafficResetTime": int(row.get("lastTrafficResetTime", 0) or 0),
        "listen": row.get("listen") or "",
        "port": int(row.get("port", 0) or 0),
        "protocol": str(row.get("protocol", "vless")),
        "tag": str(row.get("tag", "")),
        "shareAddrStrategy": str(row.get("shareAddrStrategy", "node") or "node"),
        "shareAddr": str(row.get("shareAddr", "") or ""),
        "subSortIndex": int(row.get("subSortIndex", 1) or 1),
    }
    for key in ("settings", "streamSettings", "sniffing"):
        value = row.get(key, {})
        payload[key] = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return payload


def _extract_created_row(
    response: dict[str, Any],
    inbounds: list[dict[str, Any]],
    *,
    desired_tag: str,
    port: int,
    remark: str,
) -> dict[str, Any] | None:
    obj = response.get("obj") if isinstance(response, dict) else None
    created_id: int | None = None
    if isinstance(obj, int):
        created_id = obj
    elif isinstance(obj, dict) and isinstance(obj.get("id"), int):
        created_id = int(obj["id"])
    if created_id is not None:
        for row in inbounds:
            if row.get("id") == created_id:
                return row
    for row in inbounds:
        if desired_tag and row.get("tag") == desired_tag:
            return row
    for row in inbounds:
        if row.get("remark") == remark and int(row.get("port", -1) or -1) == int(port):
            return row
    matches = [row for row in inbounds if int(row.get("port", -1) or -1) == int(port)]
    return matches[0] if len(matches) == 1 else None


def _rewrite_local_inbound_tags(config: dict[str, Any], tag_map: dict[str, str]) -> None:
    if not tag_map:
        return
    for rule in config.get("routing", {}).get("rules", []):
        tags = rule.get("inboundTag")
        if isinstance(tags, str):
            rule["inboundTag"] = tag_map.get(tags, tags)
        elif isinstance(tags, list):
            rule["inboundTag"] = [tag_map.get(str(tag), str(tag)) for tag in tags]


def _merge_xray_config(
    existing: dict[str, Any],
    generated: dict[str, Any],
    prefix: str,
    *,
    managed_inbound_tags: set[str] | None = None,
    previous_inbound_tags: set[str] | None = None,
    template_inbounds: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    cfg = json.loads(json.dumps(existing))
    managed_inbound_tags = managed_inbound_tags or set()
    previous_inbound_tags = previous_inbound_tags or set()
    template_inbounds = template_inbounds or []
    inbounds = cfg.setdefault("inbounds", [])
    # Xray Settings already contains panel-owned utility inbounds (API/metrics
    # bridges). Preserve them, remove only older template-managed receivers of
    # this cascade, then append the new internal receivers.
    inbounds[:] = [
        item for item in inbounds
        if not (isinstance(item, dict) and str(item.get("tag", "")).startswith(prefix))
    ]
    inbounds.extend(json.loads(json.dumps(template_inbounds)))
    outbounds = cfg.setdefault("outbounds", [])
    routing = cfg.setdefault("routing", {})
    rules = routing.setdefault("rules", [])

    # Remove only objects belonging to an older deployment of the same cascade.
    # Current 3x-ui may replace our requested inbound tag with a panel-generated
    # one, so old real tags must be supplied explicitly as well as the prefix.
    outbounds[:] = [o for o in outbounds if not str(o.get("tag", "")).startswith(prefix)]
    kept_rules: list[dict[str, Any]] = []
    for rule in rules:
        out_tag = str(rule.get("outboundTag", ""))
        in_tags = rule.get("inboundTag", [])
        if isinstance(in_tags, str):
            in_tags = [in_tags]
        if (
            out_tag.startswith(prefix)
            or any(str(t).startswith(prefix) for t in in_tags)
            or any(str(t) in previous_inbound_tags for t in in_tags)
        ):
            continue
        kept_rules.append(rule)
    rules[:] = kept_rules

    for outbound in generated.get("outbounds", []):
        if str(outbound.get("tag", "")).startswith(prefix):
            outbounds.append(outbound)
    for rule in generated.get("routing", {}).get("rules", []):
        out_tag = str(rule.get("outboundTag", ""))
        in_tags = rule.get("inboundTag", [])
        if isinstance(in_tags, str):
            in_tags = [in_tags]
        if (
            out_tag.startswith(prefix)
            or any(str(t).startswith(prefix) for t in in_tags)
            or any(str(t) in managed_inbound_tags for t in in_tags)
        ):
            rules.append(rule)
    return cfg

def _remove_from_xray_config(existing: dict[str, Any], prefix: str, inbound_tags: set[str] | None = None) -> dict[str, Any]:
    cfg = json.loads(json.dumps(existing))
    inbound_tags = inbound_tags or set()
    cfg.setdefault("inbounds", [])[:] = [
        item for item in cfg.get("inbounds", [])
        if not (isinstance(item, dict) and str(item.get("tag", "")).startswith(prefix))
    ]
    cfg.setdefault("outbounds", [])[:] = [
        o for o in cfg.get("outbounds", []) if not str(o.get("tag", "")).startswith(prefix)
    ]
    routing = cfg.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    kept: list[dict[str, Any]] = []
    for rule in rules:
        out_tag = str(rule.get("outboundTag", ""))
        in_tags = rule.get("inboundTag", [])
        if isinstance(in_tags, str):
            in_tags = [in_tags]
        if out_tag.startswith(prefix) or any(str(t).startswith(prefix) or str(t) in inbound_tags for t in in_tags):
            continue
        kept.append(rule)
    routing["rules"] = kept
    return cfg


def _remote_sni_preflight(
    topo: Topology, clients: dict[str, PanelClient]
) -> tuple[list[str], dict[str, Any]]:
    """Return SNI candidates feasible from every panel that supports scanning.

    Legacy panels simply report scanner_supported=false and do not constrain
    the pool.  A modern panel exposing the scanner does constrain it: if none
    of the candidates is feasible there, deployment stops before mutation.
    """
    allowed = set(topo.sni_pool)
    report: dict[str, Any] = {"servers": {}, "selected_pool": []}
    constrained = False
    for server in topo.servers:
        client = clients[server.name]
        rows: dict[str, Any] = {}
        scanner_supported = False
        feasible: set[str] = set()
        for host in topo.sni_pool:
            result = client.scan_reality_target(host)
            if result is None:
                rows[host] = {"available": False}
                continue
            scanner_supported = True
            ok = result.get("feasible") is True
            if ok:
                feasible.add(host)
            rows[host] = {"available": True, **result}
        report["servers"][server.name] = {
            "scanner_supported": scanner_supported,
            "targets": rows,
        }
        if scanner_supported:
            constrained = True
            if not feasible:
                raise PanelError(f"{server.name}: no configured SNI target passed remote REALITY scan")
            allowed &= feasible
    if constrained and not allowed:
        raise PanelError("no SNI target passed the remote REALITY scan on every scanner-capable server")
    selected = [host for host in topo.sni_pool if host in allowed] if constrained else list(topo.sni_pool)

    # If at least one destination is a legacy panel without scanRealityTarget,
    # prefer conservative REALITY targets observed with plain X25519 on every
    # scanner-capable node. Current Xray automatically negotiates
    # X25519MLKEM768 when the target advertises it; an old core on the
    # unscannable receiver may not implement that path. We therefore avoid
    # hybrid-only candidates for mixed-generation cascades when alternatives
    # exist, then rank by worst observed latency for deterministic deployment.
    has_unscanned = any(
        not bool(info.get("scanner_supported"))
        for info in report["servers"].values()
        if isinstance(info, dict)
    )
    if selected:
        def observations(host: str) -> list[dict[str, Any]]:
            out: list[dict[str, Any]] = []
            for info in report["servers"].values():
                if not isinstance(info, dict) or not info.get("scanner_supported"):
                    continue
                target = (info.get("targets") or {}).get(host)
                if isinstance(target, dict) and target.get("available"):
                    out.append(target)
            return out

        if has_unscanned:
            plain = [
                host for host in selected
                if observations(host)
                and all(str(o.get("curveID", "")) == "X25519" for o in observations(host))
            ]
            if plain:
                selected = plain

        def rank(host: str) -> tuple[int, int]:
            obs = observations(host)
            worst = max((int(o.get("latencyMs", 10**9) or 10**9) for o in obs), default=10**9)
            return (worst, topo.sni_pool.index(host))

        selected = sorted(selected, key=rank)

    report["selected_pool"] = selected
    report["constrained_by_remote_scans"] = constrained
    report["compatibility_policy"] = {
        "legacy_unscanned_present": has_unscanned,
        "prefer_plain_x25519": has_unscanned,
        "selection_order": "lowest worst-case remote latency, then configured order",
    }
    return selected, report


def remote_sni_check(topo: Topology, timeout: float = 8.0) -> tuple[list[str], dict[str, Any]]:
    """Authenticate to all configured panels and run server-side REALITY scans where supported.

    New panels constrain the resulting pool. Legacy panels that do not expose
    scanRealityTarget are reported as unsupported and do not reject a host.
    """
    topo.validate()
    clients: dict[str, PanelClient] = {}
    for server in topo.servers:
        if not server.has_panel_credentials():
            raise PanelError(f"{server.name}: panel credentials are incomplete")
        client = PanelClient(server, timeout=timeout)
        client.test_connection()
        clients[server.name] = client
    return _remote_sni_preflight(topo, clients)


def test_panels(topo: Topology, timeout: float = 8.0) -> list[PanelStatus]:
    statuses: list[PanelStatus] = []
    for server in topo.servers:
        if not server.panel_url:
            statuses.append(PanelStatus(server=server.name, ok=False, message="panel URL is empty"))
            continue
        try:
            statuses.append(PanelClient(server, timeout=timeout).test_connection())
        except Exception as exc:
            statuses.append(PanelStatus(server=server.name, ok=False, message=str(exc)))
    return statuses


def deploy_cascade(topo: Topology, output_dir: Path, timeout: float = 8.0) -> DeployResult:
    topo.validate()
    for server in topo.servers:
        if not server.has_panel_credentials():
            raise PanelError(f"{server.name}: panel credentials are incomplete")

    # Topologies saved by <=0.3.12 inherited XHTTP as the inter-server default.
    # Dual-entry already gives clients XHTTP + TCP at the edge, so use the much
    # more broadly compatible TCP/REALITY between VPSes unless the user has
    # explicitly toggled the inter-server transport in a >=0.3.13 UI.
    requested_transport = topo.transport
    transport_auto_migrated = False
    if topo.dual_entry and topo.transport == "xhttp" and not getattr(topo, "transport_locked", False):
        topo = Topology.from_dict(topo.to_dict(include_secrets=True))
        topo.transport = "tcp"
        transport_auto_migrated = True

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "TRANSPORT_DECISION.json").write_text(
        json.dumps({
            "requested": requested_transport,
            "effective": topo.transport,
            "auto_migrated": transport_auto_migrated,
            "reason": (
                "dual entry keeps XHTTP+TCP for clients; legacy topology default was migrated to TCP between VPSes"
                if transport_auto_migrated else "explicit/current topology setting"
            ),
            "requested_inter_server_protocol": getattr(topo, "inter_server_protocol", "auto"),
            "effective_inter_server_protocol": "pending-panel-capability-check",
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    backup_dir = output_dir / "deploy-backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    debug_dir = output_dir / "deploy-debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    prefix = _cascade_prefix(topo)

    clients: dict[str, PanelClient] = {}
    statuses: dict[str, PanelStatus] = {}
    existing_inbounds: dict[str, list[dict[str, Any]]] = {}
    old_cascade_rows: dict[str, list[dict[str, Any]]] = {}
    old_template_inbounds: dict[str, list[dict[str, Any]]] = {}
    xray_snapshots: dict[str, tuple[dict[str, Any], str]] = {}
    occupied: dict[str, set[int]] = {}
    panel_ports: dict[str, int] = {}

    # Authenticate and snapshot first, before changing anything.
    for server in topo.servers:
        client = PanelClient(server, timeout=timeout)
        status = client.test_connection()
        clients[server.name] = client
        statuses[server.name] = status
        rows = client.list_inbounds()
        existing_inbounds[server.name] = rows
        old_rows = [
            row for row in rows
            if str(row.get("tag", "")).startswith(prefix)
            or str(row.get("remark", "")).startswith(f"cascade:{topo.cascade_id}:")
        ]
        old_cascade_rows[server.name] = old_rows
        old_ids = {int(row["id"]) for row in old_rows if isinstance(row.get("id"), int)}
        occupied[server.name] = {
            int(row["port"]) for row in rows
            if isinstance(row.get("port"), int)
            and (not isinstance(row.get("id"), int) or int(row["id"]) not in old_ids)
        }
        # A panel listener and an Xray inbound cannot bind the same socket.
        # Reserve the panel URL port per host even when an old broken cascade
        # row happens to advertise it.  Ports remain reusable on OTHER hosts.
        try:
            parsed_panel = urlparse(server.panel_url)
            panel_port = parsed_panel.port or (443 if parsed_panel.scheme == "https" else 80)
            panel_ports[server.name] = int(panel_port)
            occupied[server.name].add(int(panel_port))
        except Exception:
            pass
        xray_snapshots[server.name] = client.get_xray_settings()
        template_cfg = xray_snapshots[server.name][0]
        template_rows = [
            item for item in template_cfg.get("inbounds", [])
            if isinstance(item, dict) and str(item.get("tag", "")).startswith(prefix)
        ]
        old_template_inbounds[server.name] = template_rows
        old_template_ports = {
            int(item.get("port")) for item in template_rows
            if isinstance(item.get("port"), int)
        }
        # Non-cascade template inbounds (API bridges etc.) also occupy sockets.
        # Existing cascade template receivers are intentionally reusable on the
        # next deploy and therefore are not added to occupied here.
        for item in template_cfg.get("inbounds", []):
            if not isinstance(item, dict) or not isinstance(item.get("port"), int):
                continue
            if str(item.get("tag", "")).startswith(prefix):
                continue
            occupied[server.name].add(int(item["port"]))
        (backup_dir / f"{server.name}-inbounds.json").write_text(
            json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        (backup_dir / f"{server.name}-xray.json").write_text(
            json.dumps(xray_snapshots[server.name][0], indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    # New panels can verify REALITY targets from the VPS itself.  Use the
    # intersection of feasible targets; old panels without the scanner do not
    # constrain the already-local-checked pool.
    remote_sni_pool, remote_sni_report = _remote_sni_preflight(topo, clients)
    (output_dir / "REMOTE_SNI_CHECKS.json").write_text(
        json.dumps(remote_sni_report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # Panel storage is most compatible with the canonical/legacy Xray keys.
    data = topo.to_dict()
    data["profile"] = "legacy"
    data["sni_pool"] = remote_sni_pool
    requested_inter_protocol = str(data.get("inter_server_protocol", "auto") or "auto")
    has_legacy_or_unscanned = any(
        not bool(info.get("scanner_supported"))
        for info in remote_sni_report.get("servers", {}).values()
        if isinstance(info, dict)
    )
    if requested_inter_protocol == "auto":
        # REALITY remains the public entry security. Between VPSes, however,
        # a legacy/unscannable panel is exactly where mixed Xray generations
        # have been producing silent TCP resets despite byte-perfect keys.
        # Use longstanding encrypted classic-AEAD Shadowsocks for those hops.
        effective_inter_protocol = "shadowsocks" if has_legacy_or_unscanned else "reality"
    else:
        effective_inter_protocol = requested_inter_protocol
    data["inter_server_protocol"] = effective_inter_protocol
    panel_topo = Topology.from_dict(data)

    # Old panels can often read/write Xray Settings while their inbound CRUD
    # endpoints are partially broken (500 on protocol-changing update/add).
    # For INTERNAL receivers only, such panels are managed directly inside the
    # Xray Settings template.  Public entry inbounds always stay DB-managed so
    # the panel can keep generating QR/subscription links for them.
    template_fallback_servers: set[str] = {
        name for name, info in remote_sni_report.get("servers", {}).items()
        if isinstance(info, dict) and not bool(info.get("scanner_supported"))
    } if effective_inter_protocol == "shadowsocks" else set()

    # A template-managed receiver must not collide with an enabled stale DB
    # cascade row that a broken legacy panel cannot disable/update.  Put those
    # old DB ports back into the per-server occupied set before allocation.
    for server_name in template_fallback_servers:
        for row in old_cascade_rows.get(server_name, []):
            if row.get("enable") is False or not isinstance(row.get("port"), int):
                continue
            occupied.setdefault(server_name, set()).add(int(row["port"]))

    (output_dir / "TRANSPORT_DECISION.json").write_text(
        json.dumps({
            "requested_transport": requested_transport,
            "effective_transport": panel_topo.transport,
            "transport_auto_migrated": transport_auto_migrated,
            "requested_inter_server_protocol": requested_inter_protocol,
            "effective_inter_server_protocol": effective_inter_protocol,
            "legacy_or_unscanned_panel_present": has_legacy_or_unscanned,
            "reason": (
                "auto compatibility: public entry remains VLESS+REALITY; encrypted Shadowsocks aes-256-gcm is used only between VPSes because a legacy/unscannable panel is present"
                if requested_inter_protocol == "auto" and has_legacy_or_unscanned
                else "explicit/current inter-server protocol or all panels support modern REALITY scanning"
            ),
        }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    preferred_ports: dict[str, list[int]] = {}
    for server in topo.servers:
        # On JSON-template fallback servers, DB cascade rows are deliberately
        # treated as immutable/stale and their ports are NOT preferred. Reuse
        # only an earlier template-managed cascade port when one exists.
        source_rows = (
            old_template_inbounds.get(server.name, [])
            if server.name in template_fallback_servers
            else old_cascade_rows.get(server.name, [])
        )
        rows = sorted(
            source_rows,
            # Prefer the newest row for a logical receiver. Replacement rows
            # are created when an old panel cannot update an existing inbound.
            # Picking the newest ID avoids repeatedly selecting the stale,
            # immutable row on the next deploy.
            key=lambda r: (
                str(r.get("remark", "")),
                1 if r.get("enable") is False else 0,
                -int(r.get("id", 0) or 0),
            ),
        )
        preferred_ports[server.name] = [
            int(r["port"]) for r in rows
            if isinstance(r.get("port"), int) and int(r["port"]) in panel_topo.port_pool
        ]
    key_sources: dict[str, list[str]] = {s.name: [] for s in topo.servers}

    def panel_credentials(server_name: str) -> RealityCredentials:
        # Prefer the receiver panel's own Xray X25519 generator.  This removes
        # mixed-version key encoding as a possible source of REALITY verify
        # failures.  Old panels without the endpoint fall back to standard
        # local X25519 generation.
        local = generate_reality_credentials()
        try:
            cert = clients[server_name].get_new_x25519_cert()
            key_sources[server_name].append("panel")
            return RealityCredentials(
                uuid=local.uuid,
                private_key=cert["privateKey"],
                public_key=cert["publicKey"],
                short_id=local.short_id,
            )
        except Exception as exc:
            key_sources[server_name].append(f"local-fallback:{exc}")
            return local

    configs, manifest, client_profiles = build(
        panel_topo, occupied_ports=occupied, preferred_ports=preferred_ports,
        credential_factory=panel_credentials,
    )
    (output_dir / "KEY_SOURCES.json").write_text(
        json.dumps(key_sources, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    # `managed` includes both newly-created and in-place-updated receiver IDs.
    managed: dict[str, list[int]] = {s.name: [] for s in topo.servers}
    newly_created: dict[str, list[int]] = {s.name: [] for s in topo.servers}
    created_tags: dict[str, list[str]] = {s.name: [] for s in topo.servers}
    template_inbounds: dict[str, list[dict[str, Any]]] = {s.name: [] for s in topo.servers}
    template_inbound_tags: dict[str, set[str]] = {s.name: set() for s in topo.servers}
    updated_backups: dict[str, list[dict[str, Any]]] = {s.name: [] for s in topo.servers}
    changed_xray: set[str] = set()

    try:
        # Re-deploys are updated IN PLACE.  This deliberately does not depend
        # on /inbounds/del/:id because several 3x-ui releases have a broken
        # delete path (500 + row remains).  Existing cascade receivers are
        # paired with the newly generated receivers in deterministic order.
        route_counter: dict[str, int] = {}
        actual_tag_maps: dict[str, dict[str, str]] = {s.name: {} for s in topo.servers}
        active_tag_sets: dict[str, set[str]] = {s.name: set() for s in topo.servers}
        previous_tag_sets: dict[str, set[str]] = {
            s.name: (
                {str(r.get("tag")) for r in old_cascade_rows[s.name] if r.get("tag")}
                | {str(r.get("tag")) for r in old_template_inbounds.get(s.name, []) if r.get("tag")}
            )
            for s in topo.servers
        }

        for server in topo.servers:
            client = clients[server.name]
            old_rows = sorted(
                old_cascade_rows[server.name],
                # Prefer enabled/newer replacement receivers over stale rows
                # left behind by panels with broken update/delete endpoints.
                key=lambda r: (
                    str(r.get("remark", "")),
                    1 if r.get("enable") is False else 0,
                    -int(r.get("id", 0) or 0),
                ),
            )
            generated_inbounds = list(configs[server.name].get("inbounds", []))

            for idx, inbound in enumerate(generated_inbounds):
                route_counter[server.name] = route_counter.get(server.name, 0) + 1
                n = route_counter[server.name]
                remark = f"cascade:{topo.cascade_id}:{server.name}:{n}"
                requested_tag = str(inbound.get("tag", ""))
                payload = _panel_payload(inbound, remark, include_tag=True, extended=True)
                # Make panel-generated QR/subscription links advertise the
                # actual cascade VPS, never the web-panel host/address policy.
                # Current 3x-ui understands these fields; compatibility add
                # fallbacks strip them for old builds.
                payload["shareAddrStrategy"] = "custom"
                payload["shareAddr"] = server.ip
                dbg_base = debug_dir / f"{server.name}-{n:02d}"

                # Internal receivers on legacy/unscannable panels are written
                # directly into the panel's Xray Settings template.  This
                # deliberately bypasses broken /inbounds/add|update endpoints
                # while keeping 3x-ui as the process/config owner.  Public
                # entry receivers (tags containing -from-client-) stay in the
                # DB so QR/subscription generation continues to work normally.
                is_internal_receiver = "-from-client-" not in requested_tag
                if is_internal_receiver and server.name in template_fallback_servers:
                    template_row = json.loads(json.dumps(inbound))
                    template_row["listen"] = template_row.get("listen") or "0.0.0.0"
                    template_inbounds[server.name].append(template_row)
                    template_inbound_tags[server.name].add(requested_tag)
                    created_tags[server.name].append(requested_tag)
                    active_tag_sets[server.name].add(requested_tag)
                    actual_tag_maps[server.name][requested_tag] = requested_tag
                    dbg_base.with_suffix(".template-inbound.json").write_text(
                        json.dumps(template_row, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                    )
                    continue

                existing = old_rows[idx] if idx < len(old_rows) else None
                action = "add"
                if existing is not None and isinstance(existing.get("id"), int):
                    action = "update"
                    inbound_id = int(existing["id"])
                    # Preserve the panel's real tag; Xray routing will be
                    # rewritten to that tag after verification.
                    if existing.get("tag"):
                        payload["tag"] = str(existing.get("tag"))
                    updated_backups[server.name].append(json.loads(json.dumps(existing)))

                dbg_base.with_suffix(f".{action}.payload.json").write_text(
                    json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )
                try:
                    if action == "update":
                        response = client.update_inbound(inbound_id, payload)
                    else:
                        response = client.add_inbound(payload)
                except Exception as exc:
                    dbg_base.with_suffix(f".{action}.error.txt").write_text(str(exc) + "\n", encoding="utf-8")
                    if action == "update" and existing is not None:
                        # A number of old/partially-broken 3x-ui builds can
                        # LIST inbounds but return HTTP 500 for update/delete.
                        # Reusing that stale receiver was too optimistic: it
                        # may have been created by an earlier generator version
                        # with XHTTP/old REALITY metadata.  Prefer creating a
                        # fresh receiver on another free port on THIS VPS.
                        #
                        # This is also why port allocation is per-server:
                        # entry/middle/exit may all use 443, while a replacement
                        # on one host can safely take 8443.
                        replacement_error: Exception | None = None
                        original_port = int(inbound.get("port", 0) or 0)
                        try:
                            current_rows = client.list_inbounds()
                            used_here = {
                                int(r["port"]) for r in current_rows
                                if isinstance(r.get("port"), int) and r.get("enable") is not False
                            }
                            if server.name in panel_ports:
                                used_here.add(int(panel_ports[server.name]))

                            # When the protocol itself changed (e.g. old
                            # VLESS/REALITY receiver -> compatibility
                            # Shadowsocks), updating old 3x-ui often returns
                            # 500. Try to disable that stale receiver and reuse
                            # its port before claiming the pool is exhausted.
                            old_protocol = str(existing.get("protocol", "") or "")
                            new_protocol = str(inbound.get("protocol", "") or "")
                            if old_protocol != new_protocol:
                                try:
                                    client.disable_inbound(int(existing["id"]), row=existing)
                                    used_here.discard(original_port)
                                except Exception as disable_exc:
                                    dbg_base.with_suffix(".protocol-switch-disable.warning.txt").write_text(
                                        str(disable_exc) + "\n", encoding="utf-8"
                                    )
                            replacement_port = (
                                original_port if original_port in panel_topo.port_pool and original_port not in used_here
                                else next((int(p) for p in panel_topo.port_pool if int(p) not in used_here), None)
                            )
                            if replacement_port is None:
                                raise PanelError(
                                    f"{server.name}: update failed and no alternate free port exists "
                                    f"for a fresh replacement; used={sorted(used_here)}, pool={panel_topo.port_pool}"
                                )

                            inbound["port"] = replacement_port
                            replacement_payload = _panel_payload(
                                inbound, remark, include_tag=True, extended=True
                            )
                            replacement_payload["shareAddrStrategy"] = "custom"
                            replacement_payload["shareAddr"] = server.ip
                            dbg_base.with_suffix(".replacement-add.payload.json").write_text(
                                json.dumps(replacement_payload, indent=2, ensure_ascii=False) + "\n",
                                encoding="utf-8",
                            )
                            response = client.add_inbound(replacement_payload)
                            action = "replacement-add"

                            # The stale receiver is no longer part of the
                            # cascade. Disable it when the panel supports that
                            # operation, but do not make a successful fresh
                            # receiver depend on the old broken row.
                            try:
                                client.disable_inbound(int(existing["id"]), row=existing)
                            except Exception as disable_exc:
                                dbg_base.with_suffix(".stale-disable.warning.txt").write_text(
                                    str(disable_exc) + "\n", encoding="utf-8"
                                )
                        except Exception as add_exc:
                            replacement_error = add_exc
                            inbound["port"] = original_port
                            dbg_base.with_suffix(".replacement-add.error.txt").write_text(
                                str(add_exc) + "\n", encoding="utf-8"
                            )

                        if action != "replacement-add":
                            # Last-resort compatibility path.  Only if a fresh
                            # add is impossible do we adapt to the immutable
                            # receiver that is already live.
                            try:
                                receiver = _reuse_existing_receiver(
                                    configs=configs,
                                    client_profiles=client_profiles,
                                    manifest=manifest,
                                    server_name=server.name,
                                    server_ip=server.ip,
                                    generated_inbound=inbound,
                                    existing_row=existing,
                                    fingerprint=topo.fingerprint,
                                )
                            except Exception as reuse_exc:
                                raise PanelError(
                                    f"{server.name}: update inbound failed; fresh replacement failed; "
                                    f"immutable reuse also failed: update={exc}; "
                                    f"replacement={replacement_error}; reuse={reuse_exc}"
                                ) from reuse_exc
                            response = {
                                "success": True,
                                "obj": existing,
                                "_cascadegen_update_method": "immutable-reuse-last-resort",
                                "_cascadegen_original_error": str(exc),
                                "_cascadegen_replacement_error": str(replacement_error),
                                "_cascadegen_receiver": receiver,
                            }
                            action = "reuse"
                    else:
                        raise PanelError(f"{server.name}: {action} inbound failed: {exc}") from exc
                dbg_base.with_suffix(f".{action}.response.json").write_text(
                    json.dumps(response, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                )

                rows = client.list_inbounds()
                if action in {"update", "reuse"}:
                    row = next((r for r in rows if int(r.get("id", -1) or -1) == inbound_id), None)
                else:
                    row = _extract_created_row(
                        response, rows,
                        desired_tag=requested_tag,
                        port=int(inbound["port"]),
                        remark=remark,
                    )
                if row is None or not isinstance(row.get("id"), int):
                    raise PanelError(
                        f"{server.name}: {action} returned but receiver row could not be discovered "
                        f"(port={inbound['port']}, remark={remark})"
                    )
                inbound_id = int(row["id"])
                if action != "reuse":
                    # Treat the panel's persisted row as authoritative even
                    # after a nominally successful add/update.  Rebuild every
                    # predecessor outbound AND the external client profile from
                    # the actual privateKey/SNI/shortId/transport stored by the
                    # panel.  This prevents QR/client material from drifting
                    # from the receiver that Xray actually runs.
                    receiver = _reuse_existing_receiver(
                        configs=configs,
                        client_profiles=client_profiles,
                        manifest=manifest,
                        server_name=server.name,
                        server_ip=server.ip,
                        generated_inbound=inbound,
                        existing_row=row,
                        fingerprint=topo.fingerprint,
                    )
                    dbg_base.with_suffix(".effective-receiver.json").write_text(
                        json.dumps({k: v for k, v in receiver.items() if k != "server_settings" and k != "server_stream"},
                                   indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
                    )
                actual_tag = str(row.get("tag", "") or inbound.get("tag", ""))
                if not actual_tag:
                    raise PanelError(f"{server.name}: inbound {inbound_id} has no usable tag")
                if action in {"add", "replacement-add"}:
                    newly_created[server.name].append(inbound_id)
                managed[server.name].append(inbound_id)
                created_tags[server.name].append(actual_tag)
                active_tag_sets[server.name].add(actual_tag)
                actual_tag_maps[server.name][requested_tag] = actual_tag

            # If topology now needs fewer receivers, do not delete stale rows
            # on a panel whose delete endpoint may be broken. Disable them and
            # remove their routing instead. Explicit Remove can attempt delete.
            for extra in old_rows[len(generated_inbounds):]:
                if not isinstance(extra.get("id"), int):
                    continue
                updated_backups[server.name].append(json.loads(json.dumps(extra)))
                try:
                    client.disable_inbound(int(extra["id"]), row=extra)
                except Exception as exc:
                    raise PanelError(
                        f"{server.name}: cannot disable obsolete cascade inbound id={extra['id']}: {exc}"
                    ) from exc

            _rewrite_local_inbound_tags(configs[server.name], actual_tag_maps[server.name])

        # Validate the exact strings 3x-ui will expose through Copy URL / QR.
        # This catches stale/blank pbk and other metadata drift before routing
        # changes make the cascade look deployed.
        qr_report, qr_links = _panel_qr_preflight(topo, manifest, clients, output_dir)

        # Merge only cascade outbounds/rules into each panel's existing Xray Settings.
        for server in topo.servers:
            old_cfg, test_url = xray_snapshots[server.name]
            new_cfg = _merge_xray_config(
                old_cfg,
                configs[server.name],
                prefix,
                managed_inbound_tags=active_tag_sets[server.name],
                previous_inbound_tags=previous_tag_sets[server.name],
                template_inbounds=template_inbounds[server.name],
            )
            clients[server.name].update_xray_settings(new_cfg, test_url)
            changed_xray.add(server.name)

        # Verify through API. New panels expose the assembled runtime config; old panels may not.
        server_results: list[DeployServerResult] = []
        for server in topo.servers:
            client = clients[server.name]
            rows = client.list_inbounds()
            tags = {str(row.get("tag", "")) for row in rows if row.get("enable", True) is not False}
            missing = [tag for tag in created_tags[server.name] if tag not in tags]
            if missing:
                raise PanelError(f"{server.name}: deployed inbound(s) missing/disabled after reload: {', '.join(missing)}")
            runtime = client.get_runtime_config()
            runtime_verified = False
            if runtime is not None:
                rt_tags = {str(i.get("tag", "")) for i in runtime.get("inbounds", []) if isinstance(i, dict)}
                rt_out = {str(o.get("tag", "")) for o in runtime.get("outbounds", []) if isinstance(o, dict)}
                expected_in = set(created_tags[server.name])
                expected_out = {
                    str(o.get("tag")) for o in configs[server.name].get("outbounds", [])
                    if str(o.get("tag", "")).startswith(prefix)
                }
                if not expected_in.issubset(rt_tags) or not expected_out.issubset(rt_out):
                    raise PanelError(f"{server.name}: runtime config does not contain all cascade tags after deploy")
                # Verify that the REALITY material Xray actually received is
                # the same material from which we built client/outbound keys.
                runtime_by_tag = {str(i.get("tag", "")): i for i in runtime.get("inbounds", []) if isinstance(i, dict)}
                row_by_tag = {str(r.get("tag", "")): r for r in rows if isinstance(r, dict)}
                for tag in expected_in:
                    rt = runtime_by_tag.get(tag)
                    dbrow = row_by_tag.get(tag)
                    if not isinstance(rt, dict) or not isinstance(dbrow, dict):
                        raise PanelError(f"{server.name}: cannot compare runtime receiver {tag}")
                    if int(rt.get("port", -1) or -1) != int(dbrow.get("port", -2) or -2):
                        raise PanelError(f"{server.name}: runtime port mismatch for {tag}")
                    rt_protocol = str(rt.get("protocol", "") or "")
                    db_protocol = str(dbrow.get("protocol", "") or "")
                    if rt_protocol != db_protocol:
                        raise PanelError(f"{server.name}: runtime protocol mismatch for {tag}: {rt_protocol} != {db_protocol}")
                    rt_stream = _json_obj(rt.get("streamSettings", {}))
                    db_stream = _json_obj(dbrow.get("streamSettings", {}))
                    rt_settings = _json_obj(rt.get("settings", {}))
                    db_settings = _json_obj(dbrow.get("settings", {}))
                    if db_protocol == "shadowsocks":
                        for sk in ("method", "password", "network"):
                            if str(rt_settings.get(sk, "") or "") != str(db_settings.get(sk, "") or ""):
                                raise PanelError(f"{server.name}: runtime Shadowsocks {sk} mismatch for {tag}")
                    else:
                        rr = rt_stream.get("realitySettings") if isinstance(rt_stream, dict) else None
                        dr = db_stream.get("realitySettings") if isinstance(db_stream, dict) else None
                        if not isinstance(rr, dict) or not isinstance(dr, dict):
                            raise PanelError(f"{server.name}: REALITY settings missing in runtime for {tag}")
                        for rk in ("privateKey", "serverNames", "shortIds"):
                            if rr.get(rk) != dr.get(rk):
                                raise PanelError(f"{server.name}: runtime REALITY {rk} mismatch for {tag}")
                        rt_client = _first_vless_client(rt_settings)
                        db_client = _first_vless_client(db_settings)
                        if db_client is not None:
                            if rt_client is None:
                                raise PanelError(f"{server.name}: runtime VLESS client missing for {tag}")
                            for ck in ("id", "flow"):
                                if str(rt_client.get(ck, "") or "") != str(db_client.get(ck, "") or ""):
                                    raise PanelError(f"{server.name}: runtime VLESS {ck} mismatch for {tag}")
                        rt_net = str(rt_stream.get("network") or rt_stream.get("method") or "tcp")
                        db_net = str(db_stream.get("network") or db_stream.get("method") or "tcp")
                        norm = lambda value: "tcp" if value == "raw" else value
                        if norm(rt_net) != norm(db_net):
                            raise PanelError(f"{server.name}: runtime transport mismatch for {tag}: {rt_net} != {db_net}")
                        if db_net == "xhttp":
                            rx = _json_obj(rt_stream.get("xhttpSettings", {}))
                            dx = _json_obj(db_stream.get("xhttpSettings", {}))
                            for xk in ("host", "path", "mode"):
                                if str(rx.get(xk, "") or "") != str(dx.get(xk, "") or ""):
                                    raise PanelError(f"{server.name}: runtime XHTTP {xk} mismatch for {tag}")
                        public_key_from_private(str(rr.get("privateKey", "")))
                runtime_verified = True
            st = statuses[server.name]
            server_results.append(
                DeployServerResult(
                    server=server.name,
                    auth=st.auth,
                    api_style=st.api_style,
                    created_inbounds=list(managed[server.name]),
                    created_tags=list(created_tags[server.name]),
                    runtime_verified=runtime_verified,
                )
            )

        # First prove that every source outbound is paired byte-for-byte with
        # the destination panel's live receiver. This catches stale immutable
        # receivers and panel normalization before relying on testOutbound.
        _static_chain_consistency(topo, manifest, clients, configs, output_dir)

        # Diagnose the cascade tail-to-head first.  This produces a concrete
        # failing suffix (exit direct, middle->exit, entry->middle, ...), so a
        # quiet warning-level server log is no longer a dead end.
        _audit_chain_suffixes(topo, manifest, clients, configs, output_dir)

        # Final acceptance test: launch the EXACT vless:// URL that the panel
        # gives to its QR code through another VPS' own Xray.  Deployment is
        # not declared successful when the nested OutboundTestResult says
        # success=false, even if the HTTP/API request itself succeeded.
        _probe_qr_links_end_to_end(topo, manifest, clients, qr_links, output_dir)

    except Exception:
        # Best-effort rollback. Existing cascade rows are restored IN PLACE;
        # only rows created by this run are deleted, and if delete is broken
        # they are disabled so a failed deploy cannot leave a live listener.
        for server in reversed(topo.servers):
            client = clients.get(server.name)
            if not client:
                continue
            if server.name in changed_xray:
                try:
                    old_cfg, test_url = xray_snapshots[server.name]
                    client.update_xray_settings(old_cfg, test_url)
                except Exception:
                    pass
            restored_ids: set[int] = set()
            for row in reversed(updated_backups.get(server.name, [])):
                if not isinstance(row.get("id"), int):
                    continue
                inbound_id = int(row["id"])
                if inbound_id in restored_ids:
                    continue
                restored_ids.add(inbound_id)
                try:
                    client.update_inbound(inbound_id, _restore_payload_from_row(row))
                except Exception:
                    pass
            for inbound_id in reversed(newly_created.get(server.name, [])):
                try:
                    client.delete_inbound(inbound_id, disable_on_failure=True)
                except Exception:
                    pass
        raise

    # Save the exact generated material used for this deployment.
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "ROUTES.txt").write_text(render_routes(manifest), encoding="utf-8")
    link_lines: list[str] = []
    for route in manifest.get("routes", []):
        if not isinstance(route, dict):
            continue
        for entry in route.get("client_entries", []) or []:
            if isinstance(entry, dict) and entry.get("uri"):
                link_lines.append(f"[{entry.get('transport', 'client')}] {entry['uri']}")
    (output_dir / "CLIENT_LINKS.txt").write_text("\n".join(link_lines) + ("\n" if link_lines else ""), encoding="utf-8")
    (output_dir / "topology.redacted.json").write_text(
        json.dumps(topo.to_dict(include_secrets=False), indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    srv_dir = output_dir / "servers"
    cli_dir = output_dir / "clients"
    srv_dir.mkdir(exist_ok=True)
    cli_dir.mkdir(exist_ok=True)
    for name, cfg in configs.items():
        (srv_dir / f"{name}.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for name, cfg in client_profiles.items():
        (cli_dir / f"{name}.json").write_text(json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    result = DeployResult(
        manifest=manifest,
        servers=server_results,
        output_dir=output_dir,
        remote_sni_pool=remote_sni_pool,
        remote_sni_report=remote_sni_report,
    )
    (output_dir / "DEPLOY_RESULT.json").write_text(
        json.dumps({
            "cascade_id": topo.cascade_id,
            "servers": [
                {
                    "server": r.server,
                    "auth": r.auth,
                    "api_style": r.api_style,
                    "created_inbounds": r.created_inbounds,
                    "created_tags": r.created_tags,
                    "runtime_verified": r.runtime_verified,
                }
                for r in server_results
            ],
        }, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return result


def remove_cascade(topo: Topology, timeout: float = 8.0) -> list[str]:
    topo.validate()
    prefix = _cascade_prefix(topo)
    messages: list[str] = []
    for server in topo.servers:
        client = PanelClient(server, timeout=timeout)
        status = client.test_connection()
        rows = client.list_inbounds()
        deleted = 0
        cascade_tags: set[str] = set()
        for row in rows:
            belongs = (
                str(row.get("tag", "")).startswith(prefix)
                or str(row.get("remark", "")).startswith(f"cascade:{topo.cascade_id}:")
            )
            if belongs:
                if row.get("tag"):
                    cascade_tags.add(str(row.get("tag")))
                if isinstance(row.get("id"), int):
                    client.delete_inbound(int(row["id"]), disable_on_failure=True)
                    deleted += 1
        cfg, test_url = client.get_xray_settings()
        client.update_xray_settings(_remove_from_xray_config(cfg, prefix, cascade_tags), test_url)
        messages.append(f"{server.name}: removed {deleted} inbound(s), auth={status.auth}, api={status.api_style}")
    return messages
