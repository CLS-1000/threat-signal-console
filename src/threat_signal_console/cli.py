"""Command line: ingest, serve, verify, rebuild, status, thresholds, calibrate."""

from __future__ import annotations

import argparse
import json
import sys

from threat_signal_console import __version__, calibration, config, pipeline
from threat_signal_console.models import Source
from threat_signal_console.store import Store, StoreError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="threat-signal-console",
        description="Triage cyber threat signals through four transparent gates.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--data-dir", help="Where the audit log and index live (default: ./data, or $TSC_DATA_DIR)")
    commands = parser.add_subparsers(dest="command", required=True)

    ingest = commands.add_parser("ingest", help="Fetch sources and run new items through the gates")
    ingest.add_argument("--sources", help="Sources file (default: config/sources.toml, or $TSC_SOURCES)")
    ingest.add_argument("--source", action="append", help="Only this source id (repeatable); also runs disabled sources")
    ingest.add_argument("--file", help="Ingest one local file or URL instead of the sources file")
    ingest.add_argument("--kind", choices=["kev", "stix"], help="With --file: feed format")
    ingest.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="With --file: source tier")
    ingest.add_argument("--name", help="With --file: source name shown to analysts")
    ingest.add_argument("--id", help="With --file: source id (default: derived from the name)")

    serve = commands.add_parser("serve", help="Run the console and its API")
    serve.add_argument("--host", default="127.0.0.1", help="Default 127.0.0.1. The API has no login; do not expose it.")
    serve.add_argument("--port", type=int, default=8000)

    commands.add_parser("status", help="Counts, sources and the audit log head")
    commands.add_parser("verify", help="Check the audit log's hash chain and compare it with the index")
    commands.add_parser("rebuild", help="Rebuild the index from the audit log")
    commands.add_parser("calibrate", help="Measure triage against analyst verdicts")

    thresholds = commands.add_parser("thresholds", help="Show or change thresholds")
    for name in ("velocity", "credibility", "volume-floor", "provenance-floor", "similarity-ceiling"):
        thresholds.add_argument(f"--{name}", type=float)
    thresholds.add_argument("--set-by", default="cli", help="Who is making the change (recorded in the audit log)")

    args = parser.parse_args(argv)
    try:
        return _run(args, parser)
    except (StoreError, config.ConfigError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    data_dir = config.data_dir(args.data_dir)

    if args.command == "serve":
        import uvicorn

        from threat_signal_console.web.app import create_app

        uvicorn.run(create_app(data_dir), host=args.host, port=args.port)
        return 0

    store = Store(data_dir)

    if args.command == "ingest":
        if args.file:
            if not (args.kind and args.tier and args.name):
                parser.error("--file needs --kind, --tier and --name")
            source_id = args.id or "".join(ch if ch.isalnum() else "-" for ch in args.name.lower()).strip("-")
            sources = [Source(id=source_id, name=args.name, kind=args.kind, tier=args.tier, location=args.file)]
        else:
            sources = config.load_sources(args.sources)
            if args.source:
                unknown = set(args.source) - {source.id for source in sources}
                if unknown:
                    parser.error(f"unknown source id(s): {', '.join(sorted(unknown))}")
                sources = [source for source in sources if source.id in args.source]
            else:
                sources = [source for source in sources if source.enabled]
        if not sources:
            print("No enabled sources. Edit the sources file or pass --source.", file=sys.stderr)
            return 1
        failed = False
        for source in sources:
            run = pipeline.ingest_source(store, source)
            if run.get("error"):
                failed = True
                print(f"{source.id}: FAILED: {run['error']}")
                continue
            print(
                f"{source.id}: {run['new']} new, {run['revised']} revised, {run['unchanged']} unchanged, "
                f"{run['rejected']} rejected, {run['skipped_old']} older than the cutoff; "
                f"{run['signals_evaluated']} signal(s) evaluated"
            )
            for reason in run.get("rejected_examples", []):
                print(f"    rejected: {reason}")
        by_state = store.status()["by_state"]
        print("Signals now: " + (", ".join(f"{count} {state.lower()}" for state, count in sorted(by_state.items())) or "none"))
        return 1 if failed else 0

    if args.command == "status":
        print(json.dumps(store.status(), indent=2))
        return 0

    if args.command == "verify":
        result = store.verify()
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] and not result["apply_errors"] else 2

    if args.command == "rebuild":
        print(f"Rebuilt the index from {store.rebuild()} audit log event(s).")
        return 0

    if args.command == "calibrate":
        print(json.dumps(calibration.report(store), indent=2))
        return 0

    if args.command == "thresholds":
        changes = {
            name: value
            for name, value in {
                "velocity": args.velocity,
                "credibility": args.credibility,
                "volume_floor": args.volume_floor,
                "provenance_floor": args.provenance_floor,
                "similarity_ceiling": args.similarity_ceiling,
            }.items()
            if value is not None
        }
        if changes:
            try:
                result = pipeline.set_thresholds(store, changes, args.set_by)
            except ValueError as error:
                print(f"error: {error}", file=sys.stderr)
                return 1
            print(f"Saved. {result['signals_changed']} signal(s) changed state." if result["changed"] else "No change.")
        print(json.dumps(store.current_thresholds().to_dict(), indent=2))
        return 0

    return 1
