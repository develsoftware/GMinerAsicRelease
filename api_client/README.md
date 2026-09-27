# Miner API Client (Python)

A standalone Python client for the miner HTTP API — the same protocol the web
control panel uses. Suitable for monitoring, automation and scripting against
any device running this firmware.

Single file: [`miner_api.py`](miner_api.py). No dependencies beyond the
Python 3.6+ standard library (`pycryptodome` is needed only for the
`change-password` command).

## Quick start

```bash
# Public endpoints — no password required
python3 miner_api.py 192.168.0.100 stats
python3 miner_api.py 192.168.0.100 hashboards
python3 miner_api.py 192.168.0.100 log --count 50
python3 miner_api.py 192.168.0.100 log-pack -o diagnostics.tar.gz

# Authorized endpoints — default panel password is "root"
python3 miner_api.py 192.168.0.100 config --password root
python3 miner_api.py 192.168.0.100 set-config --file pools.json
python3 miner_api.py 192.168.0.100 backup -o backup.cfg
python3 miner_api.py 192.168.0.100 reboot
```

`--password` may be placed before or after the subcommand. The default port
is 80; override with `--port` (simulator builds listen on 8081).

## Commands

### Public (no authentication)

| Command | Description |
|---|---|
| `stats` | Live status: hashrate, boards, pools, fans, errors |
| `metrics [--since TS]` | Hashrate/temperature history arrays |
| `hashboards` | Per-board, per-chip frequency/hashrate/temperatures |
| `presets` | Hardware description and available tuning presets |
| `log [--index N] [--count N]` | Event log entries |
| `log-pack -o FILE` | Full diagnostic archive (`.tar.gz`) |

### Authorized (require `--password`)

| Command | Description |
|---|---|
| `config` | Current configuration (JSON) |
| `set-config --file F` | Apply a configuration subset (same JSON shape as `config` output; sections must be complete — e.g. the whole `cooling` object, not just one field) |
| `reset-config` | Reset configuration to factory defaults |
| `backup -o F` / `restore F` | Config backup / restore (`.cfg`) |
| `find-miner on\|off` | Blink the identification LED |
| `reboot` | Reboot the device (takes effect ~3 s later) |
| `update FILE` | Flash a firmware image; device reboots on success |
| `uninstall` | Restore the stock firmware and reboot |
| `change-password NEW` | Change the panel password (invalidates the session) |
| `logout` | Invalidate the server-side session key |

## Using as a library

```python
from miner_api import MinerApi

api = MinerApi("192.168.0.100")

# Read-only monitoring needs no login:
stats = api.statistics()
print(stats["hashrate"], stats["status"])

# Control operations require authorization first:
api.authorize("root")                       # default password
cfg = api.config()
cfg["stratum"]["servers"][0]["url"] = "stratum.example.com:3333"
api.set_config({"stratum": cfg["stratum"]})
api.reboot()
```

Every API error raises `ApiError` with the server-provided `code`:

| Code | Meaning |
|---|---|
| 1 | Unknown |
| 2 | Internal |
| 3 | NotAuthorized |
| 4 | InvalidParameters |
| 5 | IncorrectPassword |

## Protocol overview

All calls are HTTP POST to `http://<host>/api/<script>.cgi` with a JSON body
and header `Content-type: application/json; charset=UTF-8`. Firmware upload
and config restore send raw bytes as `application/octet-stream` instead.

Every JSON response uses the envelope:

```json
{"session_id": "...", "result": true, "data": {...}, "error": "...", "error_code": 0}
```

### Authentication (SCRAM-SHA-256 variant)

1. `POST /api/authorize1.cgi` with `{"data": {"message": "n,,n=user,r=<clientNonce>"}}`
   — the server replies with `r=<nonce>,s=<base64 salt>,i=<iterations>` and a
   `client_id`.
2. Derive keys: `saltedPassword = PBKDF2-HMAC-SHA256(password, salt, i, 32)`.
3. `POST /api/authorize2.cgi` with header `X-Client-Id` and the client proof.
   The server replies with `v=<server signature>` which the client verifies
   (mutual authentication).
4. On success the SCRAM `ClientSignature` becomes the session access key
   (TTL: 1 hour). Every subsequent request carries:

   ```
   X-Client-Id: <base64 client_id>
   X-Request-HMAC: base64(HMAC-SHA256(accessKey,
       "POST:/api/<script>.cgi:" + lowercase_hex(SHA256(raw request body))))
   ```

**Non-standard quirk:** the SCRAM-internal HMACs swap the key/message roles
compared to RFC 5802, because the panel uses `CryptoJS.HmacSHA256(message,
key)` and the server mirrors it:

```
clientKey       = HMAC(key="Client Key",  msg=saltedPassword)
clientSignature = HMAC(key=authMessage,   msg=storedKey)
serverSignature = HMAC(key=authMessage,   msg=serverKey)
```

The per-request `X-Request-HMAC` uses the normal orientation
(`key=accessKey`, `msg=signing string`). See `miner_api.py` for a reference
implementation and comments pointing at the firmware sources.

### Antminer-compatible API

The device also exposes Bitmain-style endpoints at `/cgi-bin/<method>.cgi`
with standard HTTP Digest authentication (MD5, username `root`, panel
password), e.g. `get_system_info`, `stats`, `summary`, `pools`, `reboot`.
This works out of the box with `requests.auth.HTTPDigestAuth("root", password)`
and is a simpler alternative for basic monitoring. Control methods
(`set_miner_conf`, `blink`, `reboot`) require `antminer_api_control` to be
enabled in the miner configuration.
