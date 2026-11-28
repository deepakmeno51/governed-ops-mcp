"""Runs the adversarial eval scenarios against a running server and prints a scoreboard.

    docker compose exec mcp-server python -m evals.run            all 24 scenarios
    docker compose exec mcp-server python -m evals.run --only SQL-01 APR-03
    docker compose exec mcp-server python -m evals.run --markdown   a table for the README
    docker compose exec -T mcp-server python -m evals.run --json > report.json

Exit code 0 only when every scenario was defended. The scenarios change nothing important: the only real
change they make is setting ticket 31 to "investigating", which the smoke test also does."""
import asyncio
import json
import sys
import time

from .scenarios import SCENARIOS


async def run_one(s):
    started = time.monotonic()
    try:
        checks = await s.run()
        ok, evidence = checks.ok, checks.evidence()
        detail = [{"check": label, "held": held, "detail": d} for label, held, d in checks.items]
    except Exception as exc:                       # noqa: BLE001
        ok, evidence, detail = False, f"ERROR: {type(exc).__name__}: {str(exc)[:120]}", []
    return {"id": s.id, "group": s.group, "attack": s.attack, "defence": s.defence, "defended": ok,
            "evidence": evidence, "seconds": round(time.monotonic() - started, 1), "checks": detail}


async def main(argv: list[str]) -> int:
    only = []
    if "--only" in argv:
        only = [a for a in argv[argv.index("--only") + 1:] if not a.startswith("--")]
    chosen = [s for s in SCENARIOS if not only or s.id in only]
    if "--list" in argv:
        for s in SCENARIOS:
            print(f"{s.id:7} {s.group:18} {s.attack}")
        return 0
    results = [await run_one(s) for s in chosen]
    defended = sum(r["defended"] for r in results)

    if "--json" in argv:
        print(json.dumps({"defended": defended, "total": len(results), "results": results}, indent=2))
    elif "--markdown" in argv:
        print("| ID | Attack | Defence | Result |\n|---|---|---|---|")
        for r in results:
            print(f"| {r['id']} | {r['attack']} | {r['defence']} | {'Defended' if r['defended'] else 'FAILED'} |")
        print(f"\n**{defended}/{len(results)} scenarios defended.**")
    else:
        for r in results:
            print(f"{'DEFENDED' if r['defended'] else 'FAILED  '}  {r['id']:7} {r['group']:18} {r['attack'][:78]}")
            if not r["defended"]:
                print(f"          -> {r['evidence']}")
        print(f"\n{defended}/{len(results)} scenarios defended in {sum(r['seconds'] for r in results):.0f}s")
    return 0 if defended == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main(sys.argv[1:])))
