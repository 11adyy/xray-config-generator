from __future__ import annotations

import http.cookiejar
import json
import ssl
import time
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPSHandler,
    Request,
    build_opener,
)

from .model import Server


class PanelError(RuntimeError):
    pass


@dataclass(slots=True)
class PanelStatus:
    server: str
    ok: bool
    auth: str = ""
    api_style: str = ""
    xray_state: str = ""
    xray_version: str = ""
    message: str = ""


class PanelClient:
    """Small 3x-ui client supporting both token auth and legacy cookie sessions."""

    def __init__(self, server: Server, timeout: float = 8.0) -> None:
        if not server.panel_url:
            raise PanelError(f"{server.name}: panel URL is empty")
        self.server = server
        self.timeout = timeout
        self.base = server.panel_url.rstrip("/")
        self.cookies = http.cookiejar.CookieJar()
        context = ssl.create_default_context()
        if not server.verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPCookieProcessor(self.cookies), HTTPSHandler(context=context))
        self.auth_used = ""
        self.csrf_token = ""
        self.xray_prefix = ""  # /panel/api/xray or /panel/xray

    def _url(self, path: str) -> str:
        return self.base + "/" + path.lstrip("/")

    def _headers(self, unsafe: bool = False) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "config-generator/0.3.17",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.auth_used == "token" or (not self.auth_used and self.server.api_token):
            if self.server.api_token:
                headers["Authorization"] = f"Bearer {self.server.api_token}"
        if unsafe and self.csrf_token and self.auth_used == "legacy":
            headers["X-CSRF-Token"] = self.csrf_token
        return headers

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        form: dict[str, Any] | None = None,
        expect_json: bool = True,
        auth_headers: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> Any:
        data = None
        headers = self._headers(unsafe=method.upper() not in {"GET", "HEAD", "OPTIONS"}) if auth_headers else {
            "Accept": "application/json",
            "User-Agent": "config-generator/0.3.17",
            "X-Requested-With": "XMLHttpRequest",
        }
        if extra_headers:
            headers.update(extra_headers)
        if json_body is not None:
            data = json.dumps(json_body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        elif form is not None:
            clean = {k: ("true" if v is True else "false" if v is False else str(v)) for k, v in form.items()}
            data = urlencode(clean).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = Request(self._url(path), data=data, headers=headers, method=method.upper())
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
                ctype = resp.headers.get("Content-Type", "")
        except HTTPError as exc:
            raw = exc.read()
            text = raw.decode("utf-8", "replace")
            raise PanelError(f"HTTP {exc.code} {path}: {text[:500] or exc.reason}") from exc
        except URLError as exc:
            raise PanelError(f"connection failed {path}: {exc.reason}") from exc
        except OSError as exc:
            raise PanelError(f"connection failed {path}: {exc}") from exc

        if not expect_json:
            return raw
        text = raw.decode("utf-8", "replace").strip()
        if not text:
            raise PanelError(f"empty response from {path} (HTTP {status})")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            if "text/html" in ctype or text.startswith("<"):
                raise PanelError(f"{path} returned HTML instead of JSON (probably login/base-path mismatch)") from exc
            raise PanelError(f"invalid JSON from {path}: {text[:500]}") from exc

    @staticmethod
    def _require_success(data: Any, path: str) -> Any:
        if isinstance(data, dict) and data.get("success") is False:
            raise PanelError(f"{path}: {data.get('msg') or 'panel returned success=false'}")
        return data

    def login_legacy(self) -> None:
        if not self.server.username or not self.server.password:
            raise PanelError(f"{self.server.name}: legacy auth needs username/password")

        # Current 3x-ui protects POST /login itself with CSRF.  Older builds do
        # not expose /csrf-token at all.  Fetching it first therefore gives us
        # a single flow that works on new panels and degrades cleanly on old
        # ones.  The cookie jar retains the pre-login session cookie.
        login_headers: dict[str, str] = {}
        try:
            csrf = self._request("GET", "/csrf-token", auth_headers=False)
            if isinstance(csrf, dict) and csrf.get("success") and isinstance(csrf.get("obj"), str):
                self.csrf_token = csrf["obj"]
                login_headers["X-CSRF-Token"] = self.csrf_token
        except PanelError:
            self.csrf_token = ""

        form: dict[str, Any] = {
            "username": self.server.username,
            "password": self.server.password,
        }
        if self.server.two_factor_code:
            form["twoFactorCode"] = self.server.two_factor_code
        try:
            data = self._request(
                "POST", "/login", form=form, auth_headers=False, extra_headers=login_headers
            )
        except PanelError as first:
            # A few transitional builds expose /csrf-token but still use the
            # pre-CSRF login handler.  Retry once without the header/token.
            if login_headers:
                self.csrf_token = ""
                try:
                    data = self._request("POST", "/login", form=form, auth_headers=False)
                except PanelError:
                    raise first
            else:
                raise
        self._require_success(data, "/login")
        if not isinstance(data, dict) or data.get("success") is not True:
            raise PanelError(f"{self.server.name}: legacy login failed")
        self.auth_used = "legacy"

        # The login may rotate the session.  Mint/refresh the token for unsafe
        # cookie-authenticated API calls; absence is normal on old panels.
        try:
            csrf = self._request("GET", "/csrf-token", auth_headers=False)
            if isinstance(csrf, dict) and csrf.get("success") and isinstance(csrf.get("obj"), str):
                self.csrf_token = csrf["obj"]
        except PanelError:
            self.csrf_token = ""

    def authenticate(self) -> str:
        mode = self.server.auth_mode
        errors: list[str] = []
        if mode in {"auto", "token"} and self.server.api_token:
            self.auth_used = "token"
            try:
                self._require_success(self._request("GET", "/panel/api/inbounds/list"), "/panel/api/inbounds/list")
                return self.auth_used
            except PanelError as exc:
                errors.append(f"token: {exc}")
                self.auth_used = ""
                if mode == "token":
                    raise
        if mode in {"auto", "legacy"} and self.server.username and self.server.password:
            try:
                self.login_legacy()
                self._require_success(self._request("GET", "/panel/api/inbounds/list"), "/panel/api/inbounds/list")
                return self.auth_used
            except PanelError as exc:
                errors.append(f"legacy: {exc}")
                self.auth_used = ""
                if mode == "legacy":
                    raise
        raise PanelError(f"{self.server.name}: authentication failed" + ("; " + " | ".join(errors) if errors else ""))


    def get_new_x25519_cert(self) -> dict[str, str]:
        """Ask this panel/Xray installation to generate the REALITY keypair.

        Newer 3x-ui exposes /panel/api/server/getNewX25519Cert.  Using the
        receiver's own Xray generator avoids subtle mixed-version encoding
        mismatches.  Callers may fall back to local generation when this
        endpoint is absent on an old panel.
        """
        path = "/panel/api/server/getNewX25519Cert"
        data = self._require_success(self._request("GET", path), path)
        obj = data.get("obj", {}) if isinstance(data, dict) else {}
        if not isinstance(obj, dict):
            raise PanelError(f"{path}: invalid keypair response")
        private = str(obj.get("privateKey") or obj.get("private_key") or "")
        public = str(obj.get("publicKey") or obj.get("password") or obj.get("public_key") or "")
        if not private or not public:
            raise PanelError(f"{path}: response does not contain privateKey/publicKey")
        return {"privateKey": private, "publicKey": public}

    def list_inbounds(self) -> list[dict[str, Any]]:
        data = self._require_success(self._request("GET", "/panel/api/inbounds/list"), "inbounds/list")
        obj = data.get("obj", []) if isinstance(data, dict) else []
        return obj if isinstance(obj, list) else []

    @staticmethod
    def _jsonish(value: Any) -> Any:
        if isinstance(value, str):
            text = value.strip()
            if text.startswith("{") or text.startswith("["):
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return value
        return value

    @classmethod
    def _payload_matches_row(cls, row: dict[str, Any], payload: dict[str, Any]) -> bool:
        """Check the parts that prove an add/update actually reached the DB.

        Some 3x-ui builds return HTTP 500 after mutating the DB.  Conversely,
        some older builds returned a nominal success while dropping fields.
        We therefore verify the resulting row rather than trusting status.
        """
        try:
            if int(row.get("port", -1) or -1) != int(payload.get("port", -2) or -2):
                return False
        except Exception:
            return False
        for key in ("protocol", "remark"):
            if key in payload and str(row.get(key, "")) != str(payload.get(key, "")):
                return False
        if payload.get("tag") and row.get("tag") and str(row.get("tag")) != str(payload.get("tag")):
            # Current panels are allowed to assign their own tag on add, but an
            # explicit tag is significant on update. The caller handles the
            # auto-tag add case separately by omitting tag from the payload.
            return False

        desired_settings = cls._jsonish(payload.get("settings", {}))
        actual_settings = cls._jsonish(row.get("settings", {}))
        if isinstance(desired_settings, dict) and isinstance(actual_settings, dict):
            if str(payload.get("protocol", "")) == "shadowsocks":
                for key in ("method", "password", "network"):
                    if key in desired_settings and str(actual_settings.get(key, "")) != str(desired_settings.get(key, "")):
                        return False
            want_clients = desired_settings.get("clients") or desired_settings.get("users") or []
            got_clients = actual_settings.get("clients") or actual_settings.get("users") or []
            if want_clients:
                if not got_clients or not isinstance(want_clients[0], dict) or not isinstance(got_clients[0], dict):
                    return False
                # UUID + flow are the key credentials for our VLESS receiver.
                for key in ("id", "flow"):
                    if key in want_clients[0] and str(got_clients[0].get(key, "")) != str(want_clients[0].get(key, "")):
                        return False

        desired_stream = cls._jsonish(payload.get("streamSettings", {}))
        actual_stream = cls._jsonish(row.get("streamSettings", {}))
        if isinstance(desired_stream, dict) and isinstance(actual_stream, dict):
            for key in ("network", "security"):
                if key in desired_stream and str(actual_stream.get(key, "")) != str(desired_stream.get(key, "")):
                    return False
            want_reality = desired_stream.get("realitySettings")
            got_reality = actual_stream.get("realitySettings")
            if isinstance(want_reality, dict) and isinstance(got_reality, dict):
                for key in ("privateKey", "target", "dest"):
                    if key in want_reality and str(got_reality.get(key, "")) != str(want_reality.get(key, "")):
                        return False
                for key in ("serverNames", "shortIds"):
                    if key in want_reality and list(got_reality.get(key, []) or []) != list(want_reality.get(key, []) or []):
                        return False
                # 3x-ui QR/subscription generation reads REALITY public key
                # from realitySettings.settings.publicKey. Verify that the
                # panel actually persisted it; otherwise deployment would
                # look successful but exported vless:// links have pbk=.
                want_meta = want_reality.get("settings")
                got_meta = got_reality.get("settings")
                if isinstance(want_meta, dict) and want_meta.get("publicKey"):
                    if not isinstance(got_meta, dict):
                        return False
                    for meta_key in ("publicKey", "fingerprint"):
                        if meta_key in want_meta and str(got_meta.get(meta_key, "")) != str(want_meta.get(meta_key, "")):
                            return False
            for transport_key in ("xhttpSettings", "tcpSettings", "rawSettings"):
                want = desired_stream.get(transport_key)
                got = actual_stream.get(transport_key)
                if isinstance(want, dict) and isinstance(got, dict):
                    for key in ("path", "host", "mode"):
                        if key in want and got.get(key) != want.get(key):
                            return False
        return True

    def _find_effective_inbound(self, payload: dict[str, Any], inbound_id: int | None = None) -> dict[str, Any] | None:
        rows = self.list_inbounds()
        if inbound_id is not None:
            for row in rows:
                if int(row.get("id", -1) or -1) == int(inbound_id):
                    return row if self._payload_matches_row(row, payload) else None
            return None
        remark = str(payload.get("remark", ""))
        port = int(payload.get("port", -1) or -1)
        candidates = [
            row for row in rows
            if str(row.get("remark", "")) == remark and int(row.get("port", -2) or -2) == port
        ]
        for row in candidates:
            # Add with auto-tag deliberately omitted tag, so do not let a
            # panel-generated tag invalidate postcondition verification.
            check = dict(payload)
            check.pop("tag", None)
            if self._payload_matches_row(row, check):
                return row
        return None

    def add_inbound(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Create an inbound without duplicating rows after false HTTP 500s."""
        path = "/panel/api/inbounds/add"
        attempts: list[str] = []

        def run(label: str, req_path: str, *, body: dict[str, Any], mode: str) -> dict[str, Any] | None:
            try:
                if mode == "json":
                    data = self._request("POST", req_path, json_body=body)
                elif mode == "form":
                    data = self._request("POST", req_path, form=body)
                elif mode == "import":
                    data = self._request(
                        "POST", req_path,
                        form={"data": json.dumps(body, separators=(",", ":"), ensure_ascii=False)},
                    )
                else:
                    raise AssertionError(mode)
                self._require_success(data, req_path)
                if isinstance(data, dict):
                    data.setdefault("_cascadegen_add_method", label)
                    return data
                return {"success": True, "_cascadegen_add_method": label}
            except PanelError as exc:
                attempts.append(f"{label}: {exc}")
                # Critical compatibility rule: many 3x-ui releases can return
                # 500 after DB mutation. Never try another add until we prove
                # that the row did not appear, otherwise fallbacks duplicate it.
                try:
                    row = self._find_effective_inbound(body)
                except PanelError as verify_exc:
                    attempts.append(f"{label}/verify: {verify_exc}")
                    row = None
                if row is not None:
                    return {
                        "success": True,
                        "obj": row,
                        "_cascadegen_add_method": label + "-verified-after-error",
                        "_cascadegen_original_error": str(exc),
                    }
                return None

        compact = dict(payload)
        compact.pop("tag", None)
        for k in ("trafficReset", "trafficResetDay", "lastTrafficResetTime", "subSortIndex"):
            compact.pop(k, None)
        # Current panels support per-inbound share address strategy. Keep it in
        # the first attempt so QR/subscription links advertise the actual VPS.
        result = run("json-compact-share-auto-tag", path, body=compact, mode="json")
        if result is not None:
            return result

        # Old panels predate shareAddrStrategy/shareAddr. Strip only these
        # compatibility fields before trying import/legacy add.
        legacy_compact = dict(compact)
        legacy_compact.pop("shareAddrStrategy", None)
        legacy_compact.pop("shareAddr", None)
        result = run("json-compact-legacy-auto-tag", path, body=legacy_compact, mode="json")
        if result is not None:
            return result
        result = run("import-compact-auto-tag", "/panel/api/inbounds/import", body=legacy_compact, mode="import")
        if result is not None:
            return result
        tagged = dict(payload)
        result = run("json-tagged", path, body=tagged, mode="json")
        if result is not None:
            return result
        result = run("form-tagged", path, body=tagged, mode="form")
        if result is not None:
            return result
        raise PanelError("inbound creation failed using all compatibility modes; " + " | ".join(attempts))

    def update_inbound(self, inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """Update an existing inbound in-place and verify the DB postcondition."""
        inbound_id = int(inbound_id)
        path = f"/panel/api/inbounds/update/{inbound_id}"
        attempts: list[str] = []
        variants = (
            ("json", {"json_body": payload}),
            ("form", {"form": payload}),
        )
        for label, kwargs in variants:
            try:
                data = self._request("POST", path, **kwargs)
                self._require_success(data, path)
            except PanelError as exc:
                attempts.append(f"{label}: {exc}")
            # Whether HTTP said success or 500, state is authoritative.
            for delay in (0.0, 0.20, 0.60):
                if delay:
                    time.sleep(delay)
                try:
                    row = self._find_effective_inbound(payload, inbound_id=inbound_id)
                except PanelError as exc:
                    attempts.append(f"{label}/verify: {exc}")
                    row = None
                    break
                if row is not None:
                    return {
                        "success": True,
                        "obj": row,
                        "_cascadegen_update_method": label + "-verified",
                        "_cascadegen_attempts": attempts,
                    }
        raise PanelError(
            f"{path}: update did not take effect for inbound id {inbound_id}; " + " | ".join(attempts[-6:])
        )

    def disable_inbound(self, inbound_id: int, row: dict[str, Any] | None = None) -> None:
        """Disable an inbound without requiring deletion to work on the panel."""
        inbound_id = int(inbound_id)
        path = f"/panel/api/inbounds/setEnable/{inbound_id}"
        for kwargs in ({"json_body": {"enable": False}}, {"form": {"enable": False}}):
            try:
                data = self._request("POST", path, **kwargs)
                self._require_success(data, path)
            except PanelError:
                pass
            try:
                current = next(
                    (r for r in self.list_inbounds() if int(r.get("id", -1) or -1) == inbound_id), None
                )
                if current is not None and current.get("enable") is False:
                    return
            except PanelError:
                pass
        if row is None:
            row = next((r for r in self.list_inbounds() if int(r.get("id", -1) or -1) == inbound_id), None)
        if row is None:
            return
        payload = {
            "up": int(row.get("up", 0) or 0),
            "down": int(row.get("down", 0) or 0),
            "total": int(row.get("total", 0) or 0),
            "remark": str(row.get("remark", "")),
            "enable": False,
            "expiryTime": int(row.get("expiryTime", 0) or 0),
            "listen": row.get("listen") or "",
            "port": int(row.get("port", 0) or 0),
            "protocol": str(row.get("protocol", "vless")),
            "tag": str(row.get("tag", "")),
        }
        for key in ("settings", "streamSettings", "sniffing"):
            value = row.get(key, {})
            payload[key] = value if isinstance(value, str) else json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        self.update_inbound(inbound_id, payload)

    def delete_inbound(self, inbound_id: int, *, disable_on_failure: bool = False) -> None:
        """Delete an inbound and verify the postcondition.

        If the panel's delete endpoint is broken, callers such as rollback and
        explicit cascade removal can request a safe fallback that disables the
        row instead of leaving a live stale listener.
        """
        inbound_id = int(inbound_id)
        path = f"/panel/api/inbounds/del/{inbound_id}"

        def current_row() -> dict[str, Any] | None:
            return next((row for row in self.list_inbounds() if int(row.get("id", -1) or -1) == inbound_id), None)

        row = current_row()
        if row is None:
            return
        attempts: list[str] = []
        request_variants = (
            ("post-no-body", {}),
            ("post-form-empty", {"form": {}}),
            ("post-json-empty", {"json_body": {}}),
        )
        for label, kwargs in request_variants:
            try:
                data = self._request("POST", path, **kwargs)
                self._require_success(data, path)
            except PanelError as exc:
                attempts.append(f"{label}: {exc}")
            for delay in (0.0, 0.20, 0.60):
                if delay:
                    time.sleep(delay)
                try:
                    if current_row() is None:
                        return
                except PanelError as exc:
                    attempts.append(f"{label}/verify: {exc}")
                    break
        if disable_on_failure:
            try:
                self.disable_inbound(inbound_id, row=row)
                return
            except PanelError as exc:
                attempts.append(f"disable-fallback: {exc}")
        raise PanelError(
            f"{path}: delete did not take effect; inbound id {inbound_id} is still present; "
            + " | ".join(attempts[-8:])
        )

    @staticmethod
    def _parse_xray_obj(data: Any) -> tuple[dict[str, Any], str]:
        if not isinstance(data, dict):
            raise PanelError("unexpected Xray settings response")
        obj = data.get("obj")
        if isinstance(obj, str):
            try:
                obj = json.loads(obj)
            except json.JSONDecodeError:
                # Some legacy builds return the config string directly as obj.
                try:
                    cfg = json.loads(data["obj"])
                    return cfg, ""
                except Exception as exc:
                    raise PanelError("cannot parse Xray settings response") from exc
        if isinstance(obj, dict):
            raw = obj.get("xraySetting", obj)
            test_url = str(obj.get("outboundTestUrl", "") or "")
            if isinstance(raw, str):
                try:
                    return json.loads(raw), test_url
                except json.JSONDecodeError as exc:
                    raise PanelError("xraySetting is not valid JSON") from exc
            if isinstance(raw, dict):
                return raw, test_url
        raise PanelError("Xray settings not found in panel response")

    def get_xray_settings(self) -> tuple[dict[str, Any], str]:
        candidates = [self.xray_prefix] if self.xray_prefix else ["/panel/api/xray", "/panel/xray"]
        errors: list[str] = []
        for prefix in candidates:
            if not prefix:
                continue
            path = prefix + "/"
            try:
                data = self._require_success(self._request("POST", path, form={}), path)
                cfg, test_url = self._parse_xray_obj(data)
                self.xray_prefix = prefix
                return cfg, test_url
            except PanelError as exc:
                errors.append(f"{prefix}: {exc}")
        raise PanelError("cannot read Xray Settings; " + " | ".join(errors))

    def update_xray_settings(self, config: dict[str, Any], outbound_test_url: str = "") -> None:
        if not self.xray_prefix:
            self.get_xray_settings()
        path = self.xray_prefix + "/update"
        form = {"xraySetting": json.dumps(config, separators=(",", ":"), ensure_ascii=False)}
        if outbound_test_url:
            form["outboundTestUrl"] = outbound_test_url
        data = self._request("POST", path, form=form)
        self._require_success(data, path)

    def get_runtime_config(self) -> dict[str, Any] | None:
        try:
            data = self._require_success(self._request("GET", "/panel/api/server/getConfigJson"), "server/getConfigJson")
        except PanelError:
            return None
        obj = data.get("obj") if isinstance(data, dict) else None
        if isinstance(obj, dict):
            return obj
        if isinstance(obj, str):
            try:
                parsed = json.loads(obj)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                return None
        return None

    def get_client_links(self, email: str) -> list[str] | None:
        """Return the exact share links used by the panel Copy URL / QR UI.

        Current 3x-ui exposes /panel/api/clients/links/:email.  Old panels do
        not; None means the capability is unavailable, while other API errors
        are raised so deployment does not silently trust a broken QR export.
        """
        path = f"/panel/api/clients/links/{quote(email, safe='')}"
        try:
            data = self._require_success(self._request("GET", path), path)
        except PanelError as exc:
            text = str(exc)
            if "HTTP 404" in text or "HTTP 405" in text or "returned HTML" in text:
                return None
            raise
        obj = data.get("obj") if isinstance(data, dict) else data
        if obj is None:
            return []
        if isinstance(obj, str):
            return [obj] if obj else []
        if isinstance(obj, list):
            return [str(v) for v in obj if isinstance(v, str) and v]
        if isinstance(obj, dict):
            out: list[str] = []
            for value in obj.values():
                if isinstance(value, str) and value:
                    out.append(value)
                elif isinstance(value, list):
                    out.extend(str(v) for v in value if isinstance(v, str) and v)
            return out
        raise PanelError(f"{path}: unexpected links response")

    def test_outbound(
        self, outbound: dict[str, Any], *, all_outbounds: list[dict[str, Any]] | None = None, mode: str = "real"
    ) -> Any | None:
        """Ask 3x-ui to launch its own Xray outbound probe.

        This is deliberately performed on a VPS, not on the workstation.  It
        catches REALITY key/SNI/short-id/transport mismatches before we tell
        the user that deployment succeeded.  None means an old panel without
        the testOutbound endpoint.
        """
        if not self.xray_prefix:
            try:
                self.get_xray_settings()
            except PanelError:
                return None
        path = self.xray_prefix + "/testOutbound"
        form: dict[str, Any] = {
            "outbound": json.dumps(outbound, separators=(",", ":"), ensure_ascii=False),
            "mode": mode,
        }
        if all_outbounds is not None:
            form["allOutbounds"] = json.dumps(all_outbounds, separators=(",", ":"), ensure_ascii=False)
        try:
            data = self._require_success(self._request("POST", path, form=form), path)
        except PanelError as exc:
            text = str(exc)
            if "HTTP 404" in text or "HTTP 405" in text or "returned HTML" in text:
                return None
            raise
        return data.get("obj") if isinstance(data, dict) else data

    def scan_reality_target(self, host: str, port: int = 443, xver: int = 0) -> dict[str, Any] | None:
        """Ask the panel host itself to probe a REALITY target.

        Added by newer 3x-ui versions.  Returning None means the endpoint is
        unavailable (typical for legacy panels), not that the target failed.
        """
        path = "/panel/api/server/scanRealityTarget"
        try:
            data = self._require_success(
                self._request("POST", path, form={"target": f"{host}:{port}", "xver": xver}), path
            )
        except PanelError:
            return None
        obj = data.get("obj") if isinstance(data, dict) else None
        return obj if isinstance(obj, dict) else None

    def test_connection(self) -> PanelStatus:
        auth = self.authenticate()
        xray_state = ""
        xray_version = ""
        message = "connected"
        try:
            data = self._require_success(self._request("GET", "/panel/api/server/status"), "server/status")
            obj = data.get("obj", {}) if isinstance(data, dict) else {}
            if isinstance(obj, dict):
                xr = obj.get("xray", {})
                if isinstance(xr, dict):
                    xray_state = str(xr.get("state", ""))
                    xray_version = str(xr.get("version", ""))
        except PanelError as exc:
            # Very old panels can lack server/status; list_inbounds already proved auth.
            message = f"connected; status endpoint unavailable: {exc}"
        try:
            self.get_xray_settings()
            style = "new" if self.xray_prefix == "/panel/api/xray" else "legacy"
        except PanelError as exc:
            style = "unknown"
            message += f"; Xray Settings unavailable: {exc}"
        return PanelStatus(
            server=self.server.name,
            ok=True,
            auth=auth,
            api_style=style,
            xray_state=xray_state,
            xray_version=xray_version,
            message=message,
        )
