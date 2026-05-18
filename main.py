"""CLI entrypoint: parse arguments, run fuzzer, export reports."""

from __future__ import annotations

import asyncio
import sys
import warnings

from cli.options import parse_bf_length, parse_cookies
from cli.parser import parse_arguments
from cli.runner import run_scan
from cli.surfaces import resolve_surfaces


async def main() -> None:
    args = parse_arguments()
    if args.level is not None:
        args.sqli_evasion_level = args.level
        args.osci_evasion_level = args.level
        args.lfi_evasion_level = args.level
        args.ssrf_evasion_level = min(args.level, 2)
    try:
        args.bf_min_length, args.bf_max_length = parse_bf_length(
            args.bf_length,
            args.bf_max_length,
        )
    except ValueError as exc:
        print(str(exc))
        return

    cookies = parse_cookies(args.cookie) if args.cookie else {}
    base_url = args.url.rstrip("/")
    surfaces = await resolve_surfaces(args, base_url, cookies)
    if not surfaces:
        return

    await run_scan(args, base_url=base_url, surfaces=surfaces)


if __name__ == "__main__":
    if sys.platform == "win32":
        # Suppress asyncio Windows loop policy deprecation noise on Python 3.13+.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
