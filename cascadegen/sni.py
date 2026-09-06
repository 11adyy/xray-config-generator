from __future__ import annotations

import concurrent.futures
import json
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(slots=True)
class SNIResult:
    host: str
    ok: bool
    dns_ok: bool = False
    tcp_ok: bool = False
    tls_ok: bool = False
    tls13: bool = False
    h2: bool = False
    certificate_ok: bool = False
    ip: str = ""
    tls_version: str = ""
    alpn: str = ""
    latency_ms: float | None = None
    error: str = ""
    xray_ok: bool | None = None
    xray_output: str = ""

    @property
    def suitable(self) -> bool:
        # REALITY's recommended baseline target: valid TLS for the hostname,
        # TLS 1.3, and HTTP/2 negotiation.
        return self.ok and self.tls13 and self.h2 and self.certificate_ok

    def to_dict(self) -> dict:
        data = asdict(self)
        data["suitable"] = self.suitable
        return data


def _short_error(exc: BaseException) -> str:
    text = str(exc).strip() or exc.__class__.__name__
    return text.replace("\n", " ")[:240]


def check_sni(host: str, timeout: float = 4.0, port: int = 443) -> SNIResult:
    result = SNIResult(host=host, ok=False)
    started = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not infos:
            result.error = "DNS returned no addresses"
            return result
        result.dns_ok = True
        result.ip = infos[0][4][0]
    except Exception as exc:
        result.error = f"DNS: {_short_error(exc)}"
        return result

    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2", "http/1.1"])

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            result.tcp_ok = True
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=host) as tls:
                result.tls_ok = True
                # create_default_context() + server_hostname verifies trust chain
                # and hostname/SAN. If wrap_socket returned, cert verification passed.
                result.certificate_ok = True
                result.tls_version = tls.version() or ""
                result.tls13 = result.tls_version == "TLSv1.3"
                result.alpn = tls.selected_alpn_protocol() or ""
                result.h2 = result.alpn == "h2"
                peer = tls.getpeername()
                if peer:
                    result.ip = str(peer[0])
    except ssl.SSLCertVerificationError as exc:
        result.error = f"certificate: {_short_error(exc)}"
        result.latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
        return result
    except ssl.SSLError as exc:
        result.error = f"TLS: {_short_error(exc)}"
        result.latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
        return result
    except Exception as exc:
        result.error = f"TCP/TLS: {_short_error(exc)}"
        result.latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
        return result

    result.latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
    result.ok = result.dns_ok and result.tcp_ok and result.tls_ok and result.certificate_ok
    if not result.tls13:
        result.error = f"negotiated {result.tls_version or 'unknown TLS'}, TLS 1.3 required"
    elif not result.h2:
        result.error = f"ALPN={result.alpn or 'none'}, h2 recommended"
    return result


def check_sni_pool(hosts: Iterable[str], timeout: float = 4.0, workers: int = 8) -> list[SNIResult]:
    ordered = list(dict.fromkeys(hosts))
    if not ordered:
        return []
    max_workers = max(1, min(workers, len(ordered)))
    by_host: dict[str, SNIResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(check_sni, host, timeout): host for host in ordered}
        for future in concurrent.futures.as_completed(future_map):
            host = future_map[future]
            try:
                by_host[host] = future.result()
            except Exception as exc:  # defensive: keep one failed host from aborting all checks
                by_host[host] = SNIResult(host=host, ok=False, error=_short_error(exc))
    return [by_host[h] for h in ordered]


def run_xray_tls_ping(results: list[SNIResult], xray_bin: str = "xray", timeout: float = 8.0) -> list[SNIResult]:
    exe = shutil.which(xray_bin) if "/" not in xray_bin else xray_bin
    if not exe or not Path(exe).exists():
        for result in results:
            result.xray_ok = None
            result.xray_output = f"xray binary not found: {xray_bin}"
        return results

    for result in results:
        try:
            proc = subprocess.run(
                [exe, "tls", "ping", result.host],
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            result.xray_ok = proc.returncode == 0
            result.xray_output = ((proc.stdout or "") + (proc.stderr or "")).strip()[:1000]
        except Exception as exc:
            result.xray_ok = False
            result.xray_output = _short_error(exc)
    return results


def write_sni_report(results: Iterable[SNIResult], path: Path) -> None:
    path.write_text(
        json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def render_sni_report(results: Iterable[SNIResult]) -> str:
    rows = list(results)
    lines = [
        "SNI CHECK",
        "=" * 92,
        f"{'STATUS':<8} {'HOST':<30} {'IP':<20} {'TLS':<9} {'ALPN':<7} {'MS':>7}  DETAILS",
        "-" * 92,
    ]
    for r in rows:
        status = "PASS" if r.suitable else "FAIL"
        ms = "-" if r.latency_ms is None else f"{r.latency_ms:.1f}"
        detail = r.error or "certificate/SNI OK; TLS 1.3; h2"
        if r.xray_ok is True:
            detail += "; xray tls ping OK"
        elif r.xray_ok is False:
            detail += "; xray tls ping FAILED"
        lines.append(
            f"{status:<8} {r.host[:30]:<30} {r.ip[:20]:<20} "
            f"{r.tls_version[:9]:<9} {r.alpn[:7]:<7} {ms:>7}  {detail}"
        )
    passed = sum(1 for r in rows if r.suitable)
    lines.extend(["", f"Suitable: {passed}/{len(rows)}"])
    return "\n".join(lines) + "\n"
