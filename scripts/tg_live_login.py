#!/usr/bin/env python3
"""One-shot helper: create a Pyrogram string session for telegram.live.session_file.

  pip install -U -r scripts/requirements-live.txt
  python3 scripts/tg_live_login.py

Writes ./data/tg_user.session (JSON with session string) by default.
Uses kurigram (pyrogram-compatible fork required by py-tgcalls).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys


async def main() -> None:
    try:
        from pyrogram import Client
    except ImportError:
        print("pip install -U -r scripts/requirements-live.txt", file=sys.stderr)
        raise SystemExit(1)

    api_id = int(os.environ.get("TG_API_ID") or input("api_id: ").strip())
    api_hash = os.environ.get("TG_API_HASH") or input("api_hash: ").strip()
    out = os.environ.get("TG_SESSION_FILE", "./data/tg_user.session")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)

    async with Client("camwatch_login", api_id=api_id, api_hash=api_hash, in_memory=True) as app:
        session = await app.export_session_string()
        with open(out, "w", encoding="utf-8") as f:
            json.dump({"session": session}, f)
        me = await app.get_me()
        print(f"Wrote {out} for @{me.username or me.id}")


if __name__ == "__main__":
    asyncio.run(main())
