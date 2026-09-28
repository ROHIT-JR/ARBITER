"""Command-line entry points for ARBITER."""

from __future__ import annotations

import argparse
import json
import sys
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
