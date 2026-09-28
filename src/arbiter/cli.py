"""Command-line entry points for ARBITER."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import webbrowser
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


def _scan_targets(args: argparse.Namespace) -> list[str]:
    targets = list(args.targets)
    if args.hosts_file:
        try:
            targets.extend(
                line.strip()
                for line in Path(args.hosts_file).read_text().splitlines()
                if line.strip() and not line.startswith("#")
            )
        except OSError as exc:
            raise ValueError(f"could not read {args.hosts_file!r}: {exc}") from exc
    if not targets:
        raise ValueError("provide at least one target or --hosts-file")
    return targets


def _pki_scan(args: argparse.Namespace) -> int:
    from arbiter.pki_risk_scoring.scan import ScanError, parse_target, scan_tls

    try:
        targets = _scan_targets(args)
    except ValueError as exc:
        print(f"arbiter pki scan: {exc}", file=sys.stderr)
        return 2
    reports = []
    for target in targets:
        try:
            host, port = parse_target(target, args.port)
            reports.append(scan_tls(host, port, timeout=args.timeout).to_dict())
        except ScanError as exc:
            print(f"{target}: {exc}", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(reports, indent=2))
        return 0
    print("host\tTLS\tcipher\tcertificates\tworst key risk")
    for report in reports:
        levels = [certificate["public_key"]["level"] for certificate in report["certificates"]]
        worst = max(levels, key=("low", "medium", "high", "critical").index, default="unknown")
        print(f"{report['host']}:{report['port']}\t{report['tls_version']}\t{report['cipher']}\t{len(levels)}\t{worst}")
    return 0


@contextmanager
def _demo_environment(data_dir: Path) -> Iterator[None]:
    """Temporarily enable the narrowly scoped, local-only demo capabilities."""
    previous = {key: os.environ.get(key) for key in ("ARBITER_DATA_DIR", "ARBITER_DEMO_MODE")}
    os.environ["ARBITER_DATA_DIR"] = str(data_dir)
    os.environ["ARBITER_DEMO_MODE"] = "1"
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _demo_check(_: argparse.Namespace) -> int:
    """Run deterministic presets in-process; never open a listener or browser."""
    from arbiter.api.app import create_app
    from arbiter.demo import DemoCheckError, run_preflight

    with tempfile.TemporaryDirectory(prefix="arbiter-demo-check-") as directory:
        with _demo_environment(Path(directory)):
            try:
                results = run_preflight(create_app())
            except DemoCheckError as exc:
                print(f"Demo pre-flight failed: {exc}", file=sys.stderr)
                return 1
    for result in results:
        print(f"{result.status.upper():7} {result.scenario_id}: {result.detail}")
    return 0


def _demo(args: argparse.Namespace) -> int:
    if args.check:
        return _demo_check(args)

    from arbiter.api.app import create_app, dashboard_dist

    static_dir = dashboard_dist()
    if not (static_dir / "index.html").is_file():
        print(
            f"ARBITER's pre-built dashboard is missing at {static_dir}. "
            "Build it before packaging with `cd frontend && npm ci && npm run build`.",
            file=sys.stderr,
        )
        return 2

    data_dir = Path.cwd() / ".arbiter-demo" if args.keep_data else Path(tempfile.mkdtemp(prefix="arbiter-demo-"))
    if args.keep_data:
        data_dir.mkdir(parents=True, exist_ok=True)
    url = f"http://127.0.0.1:{args.port}/"
    print("\n" + "=" * 68)
    print(" ARBITER OFFLINE DEMO")
    print(f" Open: {url}")
    print(" Press Ctrl-C to stop. Demo data is throwaway and stays local.")
    print("=" * 68 + "\n")
    try:
        with _demo_environment(data_dir):
            app = create_app()
            webbrowser.open(url)
            import uvicorn

            uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    finally:
        if args.keep_data:
            print(f"Kept reusable demo data at {data_dir}")
        else:
            shutil.rmtree(data_dir, ignore_errors=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="arbiter", description="ARBITER quantum-risk tools")
    commands = parser.add_subparsers(dest="command", required=True)
    pki = commands.add_parser("pki", help="PKI quantum-risk tools")
    pki_commands = pki.add_subparsers(dest="pki_command", required=True)
    scan = pki_commands.add_parser("scan", help="scan public TLS endpoints")
    scan.add_argument("targets", nargs="*", help="host, host:port, or [ipv6]:port")
    scan.add_argument("--hosts-file", help="file containing one target per line")
    scan.add_argument("--port", type=int, default=443, help="default port for targets without a port (default: 443)")
    scan.add_argument("--timeout", type=float, default=5.0, help="per-target timeout in seconds (default: 5)")
    scan.add_argument("--json", action="store_true", help="emit JSON")
    scan.set_defaults(handler=_pki_scan)

    demo = commands.add_parser("demo", help="run the offline dashboard demo")
    demo.add_argument("--port", type=int, default=8000, help="local dashboard port (default: 8000)")
    demo.add_argument("--keep-data", action="store_true", help="keep the temporary demo ledger and SQLite data")
    demo.add_argument("--check", action="store_true", help="run seeded presets headlessly and exit")
    demo.set_defaults(handler=_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "port", 1) not in range(1, 65536):
        print("arbiter demo: --port must be between 1 and 65535", file=sys.stderr)
        return 2
    return args.handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
