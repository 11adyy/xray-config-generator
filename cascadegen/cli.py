from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .deploy import deploy_cascade, remote_sni_check, remove_cascade, test_panels
from .generator import render_routes, write_output
from .model import DEFAULT_SNI_POOL, Server, Topology, parse_port_pool, parse_routes
from .ui import run_ui
from .validate import validate_json_files, validate_with_xray
from .sni import check_sni_pool, render_sni_report, run_xray_tls_ping, write_sni_report


def load_topology(path: Path) -> Topology:
    return Topology.from_dict(json.loads(path.read_text(encoding="utf-8")))


def checked_topology(topo: Topology, timeout: float = 4.0, xray_bin: str | None = None):
    results = check_sni_pool(topo.sni_pool, timeout=timeout)
    if xray_bin:
        run_xray_tls_ping(results, xray_bin)
    good = [r.host for r in results if r.suitable]
    if not good:
        raise SystemExit("SNI check failed: no suitable TLS 1.3 + h2 targets")
    data = topo.to_dict()
    data["sni_pool"] = good
    return Topology.from_dict(data), results


def save_sni_reports(results, output_dir: Path) -> None:
    write_sni_report(results, output_dir / "SNI_CHECKS.json")
    (output_dir / "SNI_CHECKS.txt").write_text(render_sni_report(results), encoding="utf-8")


def cmd_generate(args: argparse.Namespace) -> int:
    topo = load_topology(Path(args.topology))
    if args.profile:
        topo.profile = args.profile
    if args.transport:
        topo.transport = args.transport
    results = None
    if args.check_sni:
        topo, results = checked_topology(topo, args.sni_timeout, args.xray_tls_ping)
    out = Path(args.output)
    manifest = write_output(topo, out)
    if results is not None:
        save_sni_reports(results, out)
        print(render_sni_report(results))
    print(render_routes(manifest))
    return 0


def cmd_quick(args: argparse.Namespace) -> int:
    servers: list[Server] = []
    for item in args.server:
        if "=" not in item:
            raise SystemExit(f"--server must be NAME=IP, got: {item}")
        name, ip = item.split("=", 1)
        servers.append(Server(name.strip(), ip.strip()))
    topo = Topology(
        servers=servers,
        routes=parse_routes(args.routes),
        port_pool=parse_port_pool(args.ports),
        sni_pool=[x.strip() for x in args.sni.split(",") if x.strip()] if args.sni else DEFAULT_SNI_POOL.copy(),
        profile=args.profile,
        transport=args.transport,
        dual_entry=not args.single_entry,
        fingerprint=args.fingerprint,
        cascade_id=args.cascade_id,
        block_private=not args.allow_private,
        block_bittorrent=not args.allow_bittorrent,
    )
    topo.validate()
    results = None
    if args.check_sni:
        topo, results = checked_topology(topo, args.sni_timeout, args.xray_tls_ping)
    out = Path(args.output)
    manifest = write_output(topo, out)
    if results is not None:
        save_sni_reports(results, out)
        print(render_sni_report(results))
    print(render_routes(manifest))
    return 0


def cmd_check_sni(args: argparse.Namespace) -> int:
    if args.sni:
        hosts = [x.strip() for x in args.sni.split(",") if x.strip()]
    elif args.topology:
        hosts = load_topology(Path(args.topology)).sni_pool
    else:
        hosts = DEFAULT_SNI_POOL.copy()
    results = check_sni_pool(hosts, timeout=args.timeout, workers=args.workers)
    if args.xray:
        run_xray_tls_ping(results, args.xray)
    text = render_sni_report(results)
    print(text, end="")
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        write_sni_report(results, out)
    return 0 if any(r.suitable for r in results) else 1


def cmd_example(args: argparse.Namespace) -> int:
    topo = Topology(
        servers=[
            Server("entry", "203.0.113.10", panel_url="https://203.0.113.10:2053/SECRET", auth_mode="token", api_token="PUT_TOKEN_HERE"),
            Server("middle", "198.51.100.20", panel_url="https://198.51.100.20:2053/OLDPATH", auth_mode="legacy", username="admin", password="PUT_PASSWORD_HERE"),
            Server("exit", "192.0.2.30", panel_url="https://192.0.2.30:2053/SECRET", auth_mode="token", api_token="PUT_TOKEN_HERE"),
        ],
        routes=[["entry", "middle", "exit"]],
        port_pool=[443, 8443, 2053, 2083],
        transport="xhttp",
    )
    print(json.dumps(topo.to_dict(), indent=2, ensure_ascii=False))
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    root = Path(args.output)
    configs = sorted((root / "servers").glob("*.json")) + sorted((root / "clients").glob("*.json"))
    if not configs:
        print("No generated JSON configs found", file=sys.stderr)
        return 2
    errors = validate_json_files(configs)
    if args.xray:
        errors.extend(validate_with_xray(configs, args.xray))
    if errors:
        for err in errors:
            print("ERROR:", err, file=sys.stderr)
        return 1
    print(f"OK: {len(configs)} JSON configs")
    return 0


def cmd_panel_test(args: argparse.Namespace) -> int:
    topo = load_topology(Path(args.topology))
    statuses = test_panels(topo, timeout=args.timeout)
    ok = 0
    for r in statuses:
        if r.ok:
            ok += 1
            print(f"PASS {r.server}: auth={r.auth}, api={r.api_style}, xray={r.xray_state or '?'} {r.xray_version} {r.message}")
        else:
            print(f"FAIL {r.server}: {r.message}")
    return 0 if ok == len(statuses) else 1


def cmd_panel_sni(args: argparse.Namespace) -> int:
    topo = load_topology(Path(args.topology))
    selected, report = remote_sni_check(topo, timeout=args.timeout)
    print("REMOTE REALITY SNI CHECK")
    print("=" * 72)
    for server in topo.servers:
        row = report.get("servers", {}).get(server.name, {})
        supported = bool(row.get("scanner_supported"))
        print(f"{server.name}: scanner={'yes' if supported else 'no (legacy/fallback)'}")
        if supported:
            for host in topo.sni_pool:
                detail = row.get("targets", {}).get(host, {})
                if not detail.get("available"):
                    print(f"  ? {host}: unavailable")
                    continue
                ok = detail.get("feasible") is True
                tls = detail.get("tlsVersion") or ('TLS1.3' if detail.get('tls13') else '-')
                alpn = detail.get("alpn") or ('h2' if detail.get('h2') else '-')
                reason = detail.get("reason") or ""
                print(f"  {'PASS' if ok else 'FAIL'} {host}: tls={tls}, alpn={alpn}, {reason}".rstrip(', '))
    print("Selected pool:", ", ".join(selected) if selected else "<none>")
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return 0 if selected else 1


def cmd_deploy(args: argparse.Namespace) -> int:
    topo = load_topology(Path(args.topology))
    results = None
    if not args.skip_sni_check:
        topo, results = checked_topology(topo, args.sni_timeout, args.xray_tls_ping)
    out = Path(args.output)
    result = deploy_cascade(topo, out, timeout=args.timeout)
    if results is not None:
        save_sni_reports(results, out)
        print(render_sni_report(results))
    print(render_routes(result.manifest))
    for r in result.servers:
        verify = "runtime-verified" if r.runtime_verified else "API-verified"
        print(f"DEPLOY {r.server}: auth={r.auth}, api={r.api_style}, inbounds={r.created_inbounds}, {verify}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    topo = load_topology(Path(args.topology))
    for line in remove_cascade(topo, timeout=args.timeout):
        print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="config-generator", description="Generate and deploy Xray VLESS+REALITY cascades")
    sub = p.add_subparsers(dest="command")

    sub.add_parser("ui", help="ncurses interface")

    g = sub.add_parser("generate", help="generate from topology.json")
    g.add_argument("topology")
    g.add_argument("-o", "--output", default="cascade-output")
    g.add_argument("--profile", choices=["modern", "legacy"])
    g.add_argument("--transport", choices=["xhttp", "tcp"])
    g.add_argument("--check-sni", action="store_true", help="use only locally verified TLS 1.3+h2 SNI targets")
    g.add_argument("--sni-timeout", type=float, default=4.0)
    g.add_argument("--xray-tls-ping", metavar="PATH", help="also run xray tls ping during SNI verification")

    q = sub.add_parser("quick", help="generate without writing topology by hand")
    q.add_argument("--server", action="append", required=True, metavar="NAME=IP")
    q.add_argument("--routes", required=True, help='e.g. "entry>middle>exit;backup>exit"')
    q.add_argument("--ports", required=True, help='per-server pool, e.g. "443,8443,20000-20010"; same port may be reused on different servers')
    q.add_argument("--sni", default="", help="comma-separated SNI pool; built-in pool if omitted")
    q.add_argument("--fingerprint", default="chrome")
    q.add_argument("--profile", choices=["modern", "legacy"], default="legacy")
    q.add_argument("--transport", choices=["xhttp", "tcp"], default="xhttp", help="inter-server transport")
    q.add_argument("--single-entry", action="store_true", help="disable default dual XHTTP+TCP client entry")
    q.add_argument("--cascade-id", default="c1")
    q.add_argument("--allow-private", action="store_true")
    q.add_argument("--allow-bittorrent", action="store_true")
    q.add_argument("--check-sni", action="store_true", help="use only locally verified TLS 1.3+h2 SNI targets")
    q.add_argument("--sni-timeout", type=float, default=4.0)
    q.add_argument("--xray-tls-ping", metavar="PATH", help="also run xray tls ping during SNI verification")
    q.add_argument("-o", "--output", default="cascade-output")

    c = sub.add_parser("check-sni", help="check REALITY SNI/target candidates")
    c.add_argument("--sni", default="", help="comma-separated hostnames; built-in pool if omitted")
    c.add_argument("--topology", help="read SNI pool from topology JSON")
    c.add_argument("--timeout", type=float, default=4.0, help="per-host TCP/TLS timeout")
    c.add_argument("--workers", type=int, default=8, help="parallel checks")
    c.add_argument("--xray", metavar="PATH", help="also run 'xray tls ping HOST'")
    c.add_argument("-o", "--output", help="write JSON report")

    pt = sub.add_parser("panel-test", help="test new-token and legacy-login 3x-ui access")
    pt.add_argument("topology")
    pt.add_argument("--timeout", type=float, default=8.0)

    ps = sub.add_parser("panel-sni", help="probe REALITY targets from each 3x-ui server when supported")
    ps.add_argument("topology")
    ps.add_argument("--timeout", type=float, default=8.0)
    ps.add_argument("-o", "--output", help="write remote scan JSON report")

    d = sub.add_parser("deploy", help="deploy cascade through each 3x-ui panel API")
    d.add_argument("topology")
    d.add_argument("-o", "--output", default="cascade-output")
    d.add_argument("--timeout", type=float, default=8.0)
    d.add_argument("--skip-sni-check", action="store_true")
    d.add_argument("--sni-timeout", type=float, default=4.0)
    d.add_argument("--xray-tls-ping", metavar="PATH")

    rm = sub.add_parser("remove", help="remove only objects belonging to cascade_id")
    rm.add_argument("topology")
    rm.add_argument("--timeout", type=float, default=8.0)

    sub.add_parser("example", help="print example topology JSON")

    v = sub.add_parser("validate", help="validate generated JSON and optionally ask Xray to test it")
    v.add_argument("output", nargs="?", default="cascade-output")
    v.add_argument("--xray", metavar="PATH", help="run 'xray run -test -config' for each config")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.command in (None, "ui"):
        run_ui()
        return 0
    handlers = {
        "generate": cmd_generate,
        "quick": cmd_quick,
        "check-sni": cmd_check_sni,
        "panel-test": cmd_panel_test,
        "panel-sni": cmd_panel_sni,
        "deploy": cmd_deploy,
        "remove": cmd_remove,
        "example": cmd_example,
        "validate": cmd_validate,
    }
    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
