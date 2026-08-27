"""CLI: classify responses from a file, stdin, or an argument.

  smtpsift "550 5.1.1 User unknown"
  cat maillog | smtpsift --summary
  smtpsift -f bounces.txt --json
"""
import argparse
import json
import sys
from collections import Counter

from .classify import classify


def _lines(args):
    if args.response:
        return [args.response]
    fh = open(args.file) if args.file else sys.stdin
    return [l.strip() for l in fh if l.strip()]


def main(argv=None):
    p = argparse.ArgumentParser(prog="smtpsift",
                                description="Classify SMTP rejections and deferrals.")
    p.add_argument("response", nargs="?", help="a single response to classify")
    p.add_argument("-f", "--file", help="file of responses, one per line")
    p.add_argument("--provider", help="gmail, microsoft, yahoo, ... if you already know it")
    p.add_argument("--json", action="store_true", help="JSON Lines output")
    p.add_argument("--summary", action="store_true", help="counts by category instead of per-line")
    a = p.parse_args(argv)

    if not a.response and not a.file and sys.stdin.isatty():
        p.print_help()
        return 2

    counts, actions = Counter(), Counter()
    for line in _lines(a):
        r = classify(line, a.provider)
        counts[r.category] += 1
        actions[r.action] += 1
        if a.summary:
            continue
        if a.json:
            print(json.dumps(r.as_dict()))
        else:
            perm = "permanent" if r.permanent else "temporary"
            prov = f" [{r.provider}]" if r.provider else ""
            print(f"{r.category:18} {r.action:11} {perm:9}{prov}")
            print(f"  {r.response[:110]}")
            if r.matched:
                print(f"  -> {r.matched}")

    if a.summary:
        total = sum(counts.values())
        print(f"{total} responses\n")
        for cat, n in counts.most_common():
            print(f"  {cat:20} {n:6}  {100*n/total:5.1f}%")
        print("\nactions:")
        for act, n in actions.most_common():
            print(f"  {act:20} {n:6}  {100*n/total:5.1f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
