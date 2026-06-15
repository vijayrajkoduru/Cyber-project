"""Standalone CLI — `python -m red_team_ops <command>`.

Commands:
  init      create an engagement + RoE  (use --accept-roe to assert authorization)
  ack       acknowledge the RoE for an engagement
  list      list engagements
  scenario  list emulation scenarios
  run       run a scenario against an authorized in-scope target
  report    render the latest run as a Markdown red-team report
"""
from __future__ import annotations

import argparse
import sys

from . import attack_catalog as cat
from . import engine
from . import report as report_mod
from . import scope as scopemod
from .safety import ALLOWED_IMPACTS, contract_text


def _cmd_init(a):
    eng = scopemod.create_engagement(
        client=a.client, authorized_by=a.authorized_by,
        in_scope=[s for s in (a.scope or "").split(",") if s.strip()],
        out_of_scope=[s for s in (a.out_of_scope or "").split(",") if s.strip()],
        impact_level=a.impact, window_days=a.days, auth_ref=a.auth_ref or "",
    )
    if a.accept_roe:
        eng = scopemod.acknowledge_roe(eng["id"])
    print(f"engagement created: {eng['id']}")
    print(f"  client      : {eng['client']}")
    print(f"  in-scope    : {eng['in_scope']}")
    print(f"  out-of-scope: {eng['out_of_scope']}")
    print(f"  impact      : {eng['impact_level']}")
    print(f"  expires     : {eng['expires_at']}")
    print(f"  RoE ack     : {eng['roe_acknowledged']}")
    print(f"  contract    : {contract_text()}")
    if not eng["roe_acknowledged"]:
        print(f"\nNext: python -m red_team_ops ack --engagement {eng['id']}")


def _cmd_ack(a):
    eng = scopemod.acknowledge_roe(a.engagement)
    print(f"RoE acknowledged for {eng['id']} at {eng.get('roe_acknowledged_at')}")


def _cmd_list(a):
    ids = scopemod.list_engagements()
    print("\n".join(ids) if ids else "(no engagements)")


def _cmd_scenario(a):
    print("Scenarios:")
    for name in cat.all_scenarios():
        ids = [t["id"] for t in cat.scenario(name)]
        print(f"  {name}: {' -> '.join(ids)}")


def _cmd_run(a):
    try:
        run = engine.run_scenario(a.engagement, a.scenario, a.target)
    except (scopemod.ScopeError, ValueError) as e:
        print(f"REFUSED: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"run complete: {run['emulated']} emulated, {run['blocked']} blocked "
          f"across {len(run['tactics_covered'])} tactic(s)")
    print(f"saved: {run.get('_saved')}")
    print(f"report: python -m red_team_ops report --engagement {a.engagement}")


def _cmd_report(a):
    runs = engine.latest_runs(a.engagement)
    if not runs:
        print("no runs for that engagement", file=sys.stderr)
        sys.exit(2)
    run = engine.load_run(runs[-1])
    md = report_mod.render_markdown(run)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(md)
        print(f"wrote {a.out}")
    else:
        print(md)


def main(argv=None):
    try:                                  # Windows consoles default to cp1252
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    p = argparse.ArgumentParser(prog="red_team_ops",
                                description="Internal authorized red-team adversary-emulation engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("init", help="create an engagement + RoE")
    pi.add_argument("--client", required=True)
    pi.add_argument("--authorized-by", required=True)
    pi.add_argument("--scope", required=True, help="comma-separated in-scope targets")
    pi.add_argument("--out-of-scope", default="")
    pi.add_argument("--impact", default="emulation", choices=ALLOWED_IMPACTS)
    pi.add_argument("--days", type=int, default=14)
    pi.add_argument("--auth-ref", default="")
    pi.add_argument("--accept-roe", action="store_true",
                    help="assert you have written authorization (acknowledges RoE)")
    pi.set_defaults(fn=_cmd_init)

    pa = sub.add_parser("ack", help="acknowledge the RoE")
    pa.add_argument("--engagement", required=True)
    pa.set_defaults(fn=_cmd_ack)

    sub.add_parser("list", help="list engagements").set_defaults(fn=_cmd_list)
    sub.add_parser("scenario", help="list emulation scenarios").set_defaults(fn=_cmd_scenario)

    pr = sub.add_parser("run", help="run a scenario against an in-scope target")
    pr.add_argument("--engagement", required=True)
    pr.add_argument("--scenario", required=True)
    pr.add_argument("--target", required=True)
    pr.set_defaults(fn=_cmd_run)

    prep = sub.add_parser("report", help="render the latest run")
    prep.add_argument("--engagement", required=True)
    prep.add_argument("--out", default="")
    prep.set_defaults(fn=_cmd_report)

    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
