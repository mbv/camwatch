#!/usr/bin/env python3
"""Extract Xiaomi API session from an HTTP Toolkit HAR into data/session.json."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
CAMWATCH = HERE.parent
REPO = CAMWATCH.parent
DEFAULT_HAR = REPO / "x" / "HTTPToolkit_2026-07-30_12-03.har"
DEFAULT_OUT = CAMWATCH / "data" / "session.json"


def extract(har_path: Path) -> dict:
    har = json.loads(har_path.read_text())
    best = None
    for e in har["log"]["entries"]:
        url = e["request"]["url"]
        qs = parse_qs(urlparse(url).query)
        if "ssecurity" not in qs:
            continue
        cookie = ""
        for h in e["request"].get("headers", []):
            if h["name"].lower() == "cookie":
                cookie = h["value"]
                break
        parts = {}
        for part in cookie.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                parts[k] = v
        st = parts.get("serviceToken") or parts.get("yetAnotherServiceToken")
        if not st or "cUserId" not in parts:
            continue
        keep = [
            "userId",
            "cUserId",
            "serviceToken",
            "yetAnotherServiceToken",
            "PassportDeviceId",
            "locale",
            "countryCode",
        ]
        cookie_slim = "; ".join(f"{k}={parts[k]}" for k in keep if k in parts)
        cand = {
            "userId": parts.get("userId", ""),
            "cUserId": parts["cUserId"],
            "serviceToken": st,
            "ssecurity": qs["ssecurity"][0],
            "cookies": cookie_slim,
            "source": har_path.name,
        }
        if "eventlist" in url:
            return cand
        if best is None:
            best = cand
    if best is None:
        raise SystemExit(f"no usable session in {har_path}")
    return best


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("har", nargs="?", default=str(DEFAULT_HAR))
    ap.add_argument("-o", "--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()
    har = Path(args.har)
    if not har.is_file():
        raise SystemExit(f"HAR not found: {har}")
    sess = extract(har)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sess, indent=2) + "\n")
    print(f"wrote {out}")
    print(f"  source={sess.get('source')}")
    print(f"  cUserId={sess['cUserId']}")
    print(f"  ssecurity={sess['ssecurity']}")
    print(f"  serviceToken_len={len(sess['serviceToken'])}")
    if not sess.get("userId"):
        print("  note: HAR had no userId cookie; cUserId+serviceToken+ssecurity is enough")


if __name__ == "__main__":
    main()
