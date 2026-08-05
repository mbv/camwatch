#!/usr/bin/env python3
"""Telegram group voice-chat publisher sidecar (PyTgCalls / ntgcalls).

Speaks a simple line-oriented JSON protocol on stdin + CW_PROTO_FD (fd 3):

  → stdin:  {"cmd":"start","chat_id":-100…,"source":"https://…|file|/path"}
  → stdin:  {"cmd":"stop"}
  → stdin:  {"cmd":"ping"}
  ← fd3:    {"ok":true,…} / {"ok":false,"error":"…"}

Requires: pip install -U -r scripts/requirements-live.txt
(kurigram = maintained pyrogram fork; or telethon — set SESSION_BACKEND=telethon)

Env:
  TG_API_ID, TG_API_HASH, TG_SESSION_FILE  (session string or path to file containing it)
  CW_PROTO_FD  (default 3) — write-end for protocol replies
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import traceback


TEST_MP4 = "https://docs.evostream.com/sample_content/assets/sintel1m720p.mp4"

# Protocol replies go to CW_PROTO_FD so MTProto libs can't pollute stdout.
_PROTO_FD = int(os.environ.get("CW_PROTO_FD", "3"))
try:
    _PROTO = os.fdopen(_PROTO_FD, "w", buffering=1)
except Exception:
    _PROTO = sys.stdout


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def reply(obj: dict) -> None:
    _PROTO.write(json.dumps(obj, separators=(",", ":")) + "\n")
    _PROTO.flush()


def load_session(path: str) -> str:
    if not path:
        raise SystemExit("TG_SESSION_FILE required")
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read().strip()
        # Allow JSON {"session":"..."} or bare string.
        if raw.startswith("{"):
            data = json.loads(raw)
            return data.get("session") or data.get("string_session") or raw
        return raw
    # Treat as inline session string stored in the config field.
    return path


async def main() -> None:
    api_id = int(os.environ["TG_API_ID"])
    api_hash = os.environ["TG_API_HASH"]
    session = load_session(os.environ.get("TG_SESSION_FILE", ""))

    backend = os.environ.get("SESSION_BACKEND", "pyrogram").lower()
    if backend == "telethon":
        from telethon import TelegramClient
        from telethon.sessions import StringSession

        client = TelegramClient(StringSession(session), api_id, api_hash)
        await client.start()
    else:
        from pyrogram import Client

        try:
            client = Client(
                name="camwatch_live",
                api_id=api_id,
                api_hash=api_hash,
                session_string=session,
                in_memory=True,
            )
        except Exception:
            client = Client(
                "camwatch_live",
                api_id=api_id,
                api_hash=api_hash,
                session_string=session,
                in_memory=True,
            )
        await client.start()

    from pytgcalls import PyTgCalls

    calls = PyTgCalls(client)
    await calls.start()

    playing_chat: int | None = None

    async def do_start(chat_id: int, source: str) -> None:
        nonlocal playing_chat
        if playing_chat is not None:
            try:
                await calls.leave_call(playing_chat)
            except Exception:
                pass
            playing_chat = None
        if not source:
            source = TEST_MP4
        log(f"sidecar: play chat={chat_id} source={source[:80]}")

        # Live HTTP MPEG-TS often has no width/height in a short ffprobe →
        # InvalidVideoProportion. Skip MediaStream.check_stream and feed raw
        # yuv420p via an ffmpeg SHELL description with known geometry.
        w, h, fps = 1280, 720, 25
        try:
            from urllib.parse import urlparse, parse_qs

            q = parse_qs(urlparse(source).query)
            if q.get("w"):
                w = int(q["w"][0])
            if q.get("h"):
                h = int(q["h"][0])
            if q.get("fps"):
                fps = int(q["fps"][0])
        except Exception:
            pass

        import shlex

        from ntgcalls import MediaSource
        from pytgcalls.types.raw import Stream, VideoParameters, VideoStream

        vp = VideoParameters(width=w, height=h, frame_rate=fps, adjust_by_height=False)
        # Go serves framed raw yuv420p (not H.264). Copy into ntgcalls without
        # a second decode — H.264 mid-stream errors were painting the frame green.
        ff = (
            "ffmpeg -hide_banner -loglevel error "
            f"-f rawvideo -pix_fmt yuv420p -video_size {w}x{h} -framerate {fps} "
            f"-i {shlex.quote(source)} "
            f"-f rawvideo -pix_fmt yuv420p -video_size {w}x{h} -framerate {fps} pipe:1"
        )
        stream = Stream(camera=VideoStream(MediaSource.SHELL, ff, vp))
        await calls.play(chat_id, stream)
        playing_chat = chat_id

    async def do_stop() -> None:
        nonlocal playing_chat
        if playing_chat is None:
            return
        chat = playing_chat
        playing_chat = None
        try:
            await calls.leave_call(chat)
        except Exception as e:
            log(f"sidecar: leave_call: {e}")

    # Attach stdin BEFORE ready so Go's immediate "start" is not lost.
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    log("sidecar: PyTgCalls ready")
    reply({"ok": True, "event": "ready"})

    while True:
        line = await reader.readline()
        if not line:
            break
        line = line.decode("utf-8", errors="replace").strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as e:
            reply({"ok": False, "error": f"bad json: {e}"})
            continue
        cmd = msg.get("cmd")
        try:
            if cmd == "ping":
                reply({"ok": True, "event": "pong", "playing": playing_chat})
            elif cmd == "start":
                chat_id = int(msg["chat_id"])
                source = msg.get("source") or TEST_MP4
                if source == "test":
                    source = TEST_MP4
                await do_start(chat_id, source)
                reply({"ok": True, "event": "started", "chat_id": chat_id})
            elif cmd == "stop":
                await do_stop()
                reply({"ok": True, "event": "stopped"})
            else:
                reply({"ok": False, "error": f"unknown cmd {cmd}"})
        except Exception as e:
            log(traceback.format_exc())
            err = str(e).strip() or type(e).__name__
            reply({"ok": False, "error": err})

    await do_stop()
    try:
        await client.stop()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
