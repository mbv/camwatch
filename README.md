# Camwatch

Xiaomi camera event watcher: poll cloud `eventlist` → MTP P2P clip download → Telegram.

## Protocol support

Implements Xiaomi **MISS vendor 6 (MTP)** only — the native Mi Home path
(`miss_get_vendor` with `support_vendors=MTP`, `obsolete_tutk=0`). Older TUTK /
CS2 vendors are not spoken; if the cloud returns a non-6 vendor the session fails.

Wire stack matches current Mi Home cameras (e.g. `xiaomi.camera.c302n`): UDP CNT
login → KCP → MTP, media on ChaCha `CNT~`/`CHK~`, SD index via RDT type-6, playback
with miss cmds `0x10d` / `0x10e` / `0x10f`. Cloud signalling `ssVer` (MSIP `0x000d`)
is taken from `vendor_params` at dial time (observed values around ~453).

Past-event video is **SD playback** (`0x10d`), not a cloud file download. Segment
`sessionid` values are real SD `TimeItem` starts (not minute-floored `createTime`).
Camwatch syncs the SD index via MTP RDT type-6 (same as Mi Home), then seeks with the
covering segment’s `sessionid` + `offset`. Live leftovers are drained; `filenotfound`
fails the capture instead of sending junk.

P2P sessions are **warmed per DID** for a few minutes after a download (Mi Home–style
sticky media path): consecutive timeline taps reuse the same MTP bind and briefly
cached RDT index instead of redialing `ssAddrs` each time. `/live` evicts the warm
session first so live and SD do not share a connection.

Optional **live → Telegram group voice chat** uses a PyTgCalls/ntgcalls Python sidecar
plus a user MTProto session (Bot API cannot join VCs). See `telegram.live` in the
example config, `scripts/tg_live_login.py`, and `/live` / `/live_test` / `/live_stop`.

Wire debug: set `mtp_verbose: true` for CHK/KCP/CNT prints (off by default).

## Quick start

```bash
cd camwatch
cp configs/camwatch.example.yaml configs/camwatch.yaml
# Session from HAR:
python3 scripts/extract-session-from-har.py ../x/HTTPToolkit.har
# Fill telegram bot_token / chat_id in configs/camwatch.yaml

go mod tidy
go run ./cmd/camwatch -config configs/camwatch.yaml
```

## Docker

```bash
cd camwatch
python3 scripts/extract-session-from-har.py   # → data/session.json
# Edit configs/camwatch.docker.yaml telegram bot_token + chat_id
docker compose up --build -d
docker compose logs -f
```

- Image includes `ffmpeg` + CGO sqlite.
- Compose uses `network_mode: host` (best for MTP on Linux). On Docker Desktop, host networking is limited — remove that line if needed.
- Persist `./data` → `/app/data` (session, sqlite, clips).

## Telegram bot (timeline)

With `telegram.bot_enabled: true`, commands are accepted only from configured `chat_id`:

| Command | Action |
|---------|--------|
| `/start` | Help |
| `/devices` | List configured DIDs |
| `/timeline` | Today's events (UTC) |
| `/timeline yesterday` | Yesterday (UTC) |
| `/timeline 2026-07-28` | That UTC calendar day |
| `/timeline 2026-07-28 <did>` | Day for a specific camera |
| `/live [did]` | Publish camera live into group voice chat (`telegram.live`) |
| `/live_test` | Spike: sample MP4 into VC (no camera) |
| `/live_stop` | Stop live publish |

Tap an inline event button to download via MTP and receive the clip.

## Live voice chat (ntgcalls)

1. Create `api_id` / `api_hash` at https://my.telegram.org
2. `pip install -r scripts/requirements-live.txt` (kurigram + py-tgcalls; Docker image includes a venv)
3. `python3 scripts/tg_live_login.py` → `data/tg_user.session`
4. Enable `telegram.live` in config (user must be in the target group and allowed to speak)
5. Spike without camera: `go run ./cmd/live-spike -config configs/camwatch.yaml`
6. Or `/live_test` / `/live` from the bot

## Layout

- `internal/ports` — interfaces (`ClipRequester`, `PickStore`, …)
- `internal/xiaomi/{auth,api,miss,crypto}` — Xiaomi cloud + miss_get_vendor
- `internal/mtp` — MTP P2P
- `internal/recorder` — playback → annex-B → ffmpeg mp4
- `internal/notify/telegram` — outbound notify + interactive bot
- `internal/orchestrator` — poll / dedupe / single-flight download

## Config knobs

- `poll_interval` (default 45s)
- `log_only: true` — eventlist + dedupe only
- `telegram.bot_enabled` — interactive `/timeline`
- `clip.duration_sec` — MTP playback window
