#!/usr/bin/env python3
"""
build-fw-feed.py — assemble the SignupSentry firewall rule feed (NDJSON).

Firewall rules are hand-authored (not derived from an external source like the
CVE feed), so this builder's job is to collect your rule source, validate its
structure, de-duplicate by id, and emit one clean NDJSON feed with a metadata
header line. The GitHub Action (build-fw-feed.workflow.yml) runs this, then a
PHP step (validate-fw.php) checks every pattern compiles under PCRE — the same
engine the plugin uses — before publishing to the `fw-latest` release.

Source: one or more .ndjson files under rules/ (default), or --in <file>.
Each source line is one rule:
  {"id":"SGS-FW-SQLI-1","category":"sqli","severity":"high",
   "target":["query","body"],"pattern":"(?i)\\bunion\\b...","action":"block",
   "message":"...", "cve":null,"applies_type":null,"applies_slug":null}

Usage:
  python3 build-fw-feed.py --src rules --out firewall-rules.ndjson
  python3 build-fw-feed.py --in rules/firewall-rules.ndjson --out out.ndjson
"""

import argparse
import datetime
import glob
import json
import os
import re
import sys

CATEGORIES = {
    "sqli", "xss", "traversal", "lfi_rfi", "cmdi",
    "object_injection", "probe", "virtual-patch", "generic",
}
SEVERITIES = {"critical", "high", "med", "low"}
ACTIONS = {"block", "log"}
TARGETS = {"query", "body", "uri", "path", "cookie", "ua", "referer"}


def load_lines(paths):
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                line = line.strip()
                if line:
                    yield p, n, line


def main():
    ap = argparse.ArgumentParser(description="Build the SignupSentry firewall rule feed.")
    ap.add_argument("--src", default="rules", help="directory of *.ndjson rule sources")
    ap.add_argument("--in", dest="infile", help="single source file (overrides --src)")
    ap.add_argument("--out", default="firewall-rules.ndjson", help="output NDJSON path")
    ap.add_argument("--strict", action="store_true", help="fail on unknown category/target/severity instead of warning")
    args = ap.parse_args()

    if args.infile:
        paths = [args.infile]
    else:
        paths = sorted(glob.glob(os.path.join(args.src, "*.ndjson")))
    if not paths:
        sys.exit(f"ERROR: no rule source files found (looked in {args.infile or args.src!r}).")

    rules, seen, errors, warnings = [], {}, [], []

    for path, n, line in load_lines(paths):
        where = f"{path}:{n}"
        try:
            o = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"{where}: invalid JSON ({e})")
            continue
        if not isinstance(o, dict):
            continue
        # Skip a metadata header line if present in a source file.
        if "pattern" not in o and ("format" in o or "built_at" in o or "count" in o):
            continue

        rid = str(o.get("id", "")).strip()
        pat = o.get("pattern", "")
        if not rid or not pat:
            errors.append(f"{where}: rule needs both 'id' and 'pattern'")
            continue
        if rid in seen:
            warnings.append(f"{where}: duplicate id {rid} (first seen {seen[rid]}) — skipped")
            continue
        seen[rid] = where

        cat = str(o.get("category", "generic"))
        sev = str(o.get("severity", "med")).lower()
        if sev == "medium":
            sev = "med"
        act = str(o.get("action", "block")).lower()
        tgt = o.get("target") or ["query", "body"]
        if not isinstance(tgt, list) or not tgt:
            errors.append(f"{where}: 'target' must be a non-empty list")
            continue

        # Best-effort regex sanity (PHP PCRE is the authoritative check, done in CI).
        try:
            re.compile(pat)
        except re.error as e:
            errors.append(f"{where}: regex does not compile in Python ({e}) — verify PCRE")

        for label, val, allowed in (("category", cat, CATEGORIES), ("severity", sev, SEVERITIES),
                                     ("action", act, ACTIONS)):
            if val not in allowed:
                msg = f"{where}: {label} {val!r} not in {sorted(allowed)}"
                (errors if args.strict else warnings).append(msg)
        for t in tgt:
            if t not in TARGETS:
                msg = f"{where}: target {t!r} not in {sorted(TARGETS)}"
                (errors if args.strict else warnings).append(msg)

        rules.append({
            "id": rid,
            "category": cat,
            "severity": sev if sev in SEVERITIES else "med",
            "target": [str(t) for t in tgt],
            "pattern": pat,
            "action": act if act in ACTIONS else "block",
            "message": str(o.get("message", ""))[:191],
            "cve": o.get("cve"),
            "applies_type": o.get("applies_type"),
            "applies_slug": o.get("applies_slug"),
        })

    for w in warnings:
        print("WARN:", w, file=sys.stderr)
    if errors:
        for e in errors:
            print("ERROR:", e, file=sys.stderr)
        sys.exit(f"\n{len(errors)} error(s); feed not written.")
    if not rules:
        sys.exit("ERROR: no valid rules assembled.")

    rules.sort(key=lambda r: r["id"])  # stable diffs
    meta = {
        "format": "sgs-fw-1",
        "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(rules),
        "source": "authored",
    }
    with open(args.out, "w", encoding="utf-8") as out:
        out.write(json.dumps(meta, separators=(",", ":")) + "\n")
        for r in rules:
            out.write(json.dumps(r, separators=(",", ":")) + "\n")

    print(f"Wrote {len(rules)} rules to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
