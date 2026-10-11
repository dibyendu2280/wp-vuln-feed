#!/usr/bin/env python3
"""
build-feed.py — assemble the SignupSentry vulnerability feed (NDJSON).

It reads a public, machine-readable WordPress vulnerability source and emits
one `sgs-vuln-1` record per line, which SignupSentry imports locally and
matches on-box against installed versions. Run it in CI (see
wp-vuln-feed.workflow.yml) and attach the output to a GitHub release — exactly
the same delivery model as the VPN DB. No site data is involved anywhere in
this pipeline; it only transforms a public feed.

Default source: the Wordfence Intelligence free "production" vulnerability
feed, which is openly downloadable without an API key and maps
plugin/theme slug -> affected version ranges -> CVE + patched version.
    https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production
Other sources (NVD CVE JSON, OSV.dev exports, Patchstack) can be adapted by
writing another `parse_*` function that yields the same record dict.

Usage:
    python3 build-feed.py --out wp-vulnerabilities.ndjson
    python3 build-feed.py --in wordfence.json --out feed.ndjson   # offline

Output record (one JSON object per line):
    {"id","type","slug","cve","title","severity","cvss",
     "affected":[{"introduced","fixed"}],"fixed_in","reference","published"}
The first line is feed metadata: {"format","built_at","count","source"}.
"""

import argparse
import datetime
import json
import sys
import urllib.request

WORDFENCE_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"


def _num(x):
    """Best-effort float, else None (CVSS score may be number, string, or absent)."""
    if x in (None, ""):
        return None
    try:
        return float(x)
    except (TypeError, ValueError):
        return None


def vkey(v):
    """Sort key for dotted versions so 1.10 > 1.9."""
    out = []
    for part in str(v).replace("-", ".").split("."):
        out.append((0, int(part)) if part.isdigit() else (1, part))
    return out


def vgt(a, b):
    return vkey(a) > vkey(b)


def severity_from_cvss(score, rating):
    if rating:
        r = str(rating).lower()
        if r in ("critical", "high", "medium", "low"):
            return "med" if r == "medium" else r
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "med"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "med"
    return "low"


def range_fixed(rng, patched_versions):
    """
    Map a Wordfence affected range to our half-open [introduced, fixed)
    semantics (vulnerable iff introduced <= v < fixed).
      - exclusive upper bound  -> fixed = to_version as-is
      - inclusive upper bound  -> fixed = the authoritative patched version
                                   above it, else a sentinel that includes
                                   `to` but excludes its successor
      - no upper bound / unpatched -> fixed = None (genuinely open-ended)
    """
    to = rng.get("to_version")
    if to in (None, "", "*"):
        return None
    if rng.get("to_inclusive"):
        for p in sorted(patched_versions, key=vkey):
            if vgt(p, to):
                return p
        return str(to) + ".999999"
    return to


def parse_wordfence(data):
    """Yield feed records from the Wordfence Intelligence production feed.

    Tolerant of shape: the feed may be an object keyed by UUID, a bare list,
    or wrapped under a "data"/"vulnerabilities" key. Per-record it accepts the
    documented v2/v3 fields and skips (never crashes on) anything odd.
    """
    if isinstance(data, dict) and "slug" not in data:
        for wrap in ("data", "vulnerabilities", "results"):
            if isinstance(data.get(wrap), (dict, list)):
                data = data[wrap]
                break
    items = data.values() if isinstance(data, dict) else data
    for v in items:
        if not isinstance(v, dict):
            continue
        cve = None
        cve_field = v.get("cve")
        if isinstance(cve_field, str):
            cve = cve_field or None
        elif isinstance(cve_field, list):
            for c in cve_field:
                if isinstance(c, str) and c:
                    cve = c
                    break
                if isinstance(c, dict) and c.get("id"):
                    cve = c["id"]
                    break

        cvss_obj = v.get("cvss")
        if isinstance(cvss_obj, dict):
            score = cvss_obj.get("score")
            rating = cvss_obj.get("rating")
        elif isinstance(cvss_obj, (int, float, str)):
            score, rating = cvss_obj, None
        else:
            score, rating = None, None
        sev = severity_from_cvss(score, rating)

        ref = ""
        for item in (v.get("references") or []):
            if isinstance(item, str) and item:
                ref = item
                break
            if isinstance(item, dict):
                ref = item.get("url") or item.get("link") or ""
                if ref:
                    break
        if not ref:
            ref = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else ""
        published = (v.get("published") or "")[:10]
        title = v.get("title") or ""

        for sw in (v.get("software") or []):
            sw_type = sw.get("type")
            if sw_type not in ("plugin", "theme"):
                continue
            slug = sw.get("slug")
            if not slug:
                continue
            pv = sw.get("patched_versions")
            patched = list(pv.values()) if isinstance(pv, dict) else (pv or [])
            patched = [str(p) for p in patched if p]
            av = sw.get("affected_versions") or {}
            av_items = av.values() if isinstance(av, dict) else (av if isinstance(av, list) else [])
            affected = []
            for rng in av_items:
                if not isinstance(rng, dict):
                    continue
                frm = rng.get("from_version")
                introduced = "0" if frm in (None, "", "*") else frm
                affected.append({"introduced": introduced, "fixed": range_fixed(rng, patched)})
            if not affected:
                affected = [{"introduced": "0", "fixed": (sorted(patched, key=vkey)[0] if patched else None)}]
            fixed_in = None
            fixes = [r["fixed"] for r in affected if r["fixed"]]
            if fixes:
                fixed_in = sorted(fixes, key=vkey)[0]
            elif patched:
                fixed_in = sorted(patched, key=vkey)[0]

            yield {
                "id": (cve or v.get("id") or "VULN"),
                "type": sw_type,
                "slug": slug,
                "cve": cve,
                "title": title[:255],
                "severity": sev,
                "cvss": _num(score),
                "affected": affected,
                "fixed_in": fixed_in,
                "reference": ref[:255],
                "published": published,
            }


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "signupsentry-feed-builder"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser(description="Build the SignupSentry NDJSON vulnerability feed.")
    ap.add_argument("--in", dest="infile", help="local JSON source (skip download)")
    ap.add_argument("--url", default=WORDFENCE_URL, help="source feed URL")
    ap.add_argument("--out", default="wp-vulnerabilities.ndjson", help="output NDJSON path")
    ap.add_argument("--source", default="wordfence", help="label stored in feed meta")
    args = ap.parse_args()

    if args.infile:
        with open(args.infile, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    else:
        data = fetch(args.url)

    records = list(parse_wordfence(data))
    if not records:
        sys.exit(
            "ERROR: parsed 0 vulnerability records. The source responded but its\n"
            "shape wasn't recognised (the feed format may have changed). Save the\n"
            "raw response and inspect it:\n"
            f"    curl -s '{args.url}' | head -c 2000\n"
            "then share the first record's field names so the parser can be updated."
        )
    # Stable, de-duplicated by (type, slug, id).
    seen, uniq = set(), []
    for rec in records:
        k = (rec["type"], rec["slug"], rec["id"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(rec)

    meta = {
        "format": "sgs-vuln-1",
        "built_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": len(uniq),
        "source": args.source,
    }
    with open(args.out, "w", encoding="utf-8") as out:
        out.write(json.dumps(meta, separators=(",", ":")) + "\n")
        for rec in uniq:
            out.write(json.dumps(rec, separators=(",", ":")) + "\n")

    print(f"Wrote {len(uniq)} records to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
