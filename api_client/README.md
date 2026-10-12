# Miner API Client (Python)

A standalone Python client for the miner HTTP API — the same protocol the web
control panel uses. Suitable for monitoring, automation and scripting against
devices using authorization protocol v2. Older GMiner authorization is refused.

Single file: [`miner_api.py`](miner_api.py). No dependencies beyond the
Python 3.6+ standard library (`pycryptodome` is needed only for the
`change-password` command).

## Quick start

```bash
# Public endpoints — no password required
python3 miner_api.py 192.168.0.100 stats
python3 miner_api.py 192.168.0.100 hashboards
python3 miner_api.py 192.168.0.100 log --count 50
python3 miner_api.py 192.168.0.100 log-pack -o diagnostics.zip

# Authorized endpoints — default panel password is "root"
python3 miner_api.py 192.168.0.100 config --password root
python3 miner_api.py 192.168.0.100 set-config --file pools.json
python3 miner_api.py 192.168.0.100 backup -o backup.cfg
python3 miner_api.py 192.168.0.100 reboot
```

`--password` may be placed before or after the subcommand. The default port
is 80; override with `--port` (simulator builds listen on 8081).
Each authorized CLI command opens its own session and attempts logout when it
finishes, so repeated script invocations do not accumulate live root sessions.

## Commands

### Public (no authentication)

| Command | Description |
|---|---|
| `stats` | Live status: hashrate, boards, pools, fans, errors |
| `metrics [--since TS]` | Hashrate/temperature history arrays |
| `hashboards` | Per-board, per-chip frequency/hashrate/temperatures |
| `presets` | Hardware description and available tuning presets |
| `log [--index N] [--count N]` | Event log entries |
| `log-pack -o FILE` | Download diagnostic files and build a local ZIP (default: `log_pack.zip`) |

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
api.logout()
```

`api.download_log_pack("diagnostics.zip")` gets the ordered manifest from
`log_pack_list`, then downloads each file through `log_pack_file` with its `id`.
The server supplies archive names: TXT logs start at zero, with padding based
on the last log number. Logs arrive as `text/plain` with HTTP gzip when accepted,
or as `application/gzip` without Content-Encoding otherwise. The client decodes
either representation before ZIP DEFLATE, after checking the original wire
`Content-Length`.
`core.gz` and `core.bz2` have no HTTP Content-Encoding and are added with ZIP
STORE, preserving their original bytes. Core files do not affect log numbering.

Downloads allow at most three attempts per request for transient failures. If a
file was removed, the incomplete ZIP is discarded and a fresh list is downloaded,
with at most one full restart. Only a complete ZIP replaces the output path;
failures leave an existing output untouched and clean up the temporary file.
The old server-side `log_pack` endpoint is no longer used.

Every API error raises `ApiError` with the server-provided `code`:

| Code | Meaning |
|---|---|
| 1 | Unknown |
| 2 | Internal |
| 3 | NotAuthorized |
| 4 | InvalidParameters |
| 5 | IncorrectPassword |
| 6 | FileNotFound (`File Not Found`, HTTP 404) |
| 7 | DownloadBusy (`Download Busy`, HTTP 503) |
| 8 | NotAcceptable (`Not Acceptable`, HTTP 406) |

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
   canonical Base64 `client_id`. The client requires `authorization_version: 2`.
   The server inserts `!v2!` before its random nonce; the marker is covered by
   the SCRAM proof.
2. Derive keys: `saltedPassword = PBKDF2-HMAC-SHA256(password, salt, i, 32)`.
3. `POST /api/authorize2.cgi` with header `X-Client-Id` and the client proof.
   The server replies with `v=<server signature>` which the client verifies
   (mutual authentication), and must again advertise `authorization_version: 2`.
   These two handshake requests are unsigned. The challenge expires after
   60 seconds and is consumed before the first proof check; a failed login
   requires a new `authorize1` challenge and fresh nonce.
4. On success the SCRAM `ClientSignature` becomes the session access key
   (TTL: 1 hour). A fresh login belongs exclusively to this `MinerApi` instance;
   credentials are never cached, exported or shared between instances. Every
   subsequent request carries:

   ```
   X-Client-Id: <canonical padded Base64 of 32-byte client ID>
   X-Request-Sequence: <canonical decimal uint64, starting at 1>
   X-Request-HMAC-V2: base64(HMAC-SHA256(accessKey,
       "v2:POST:/api/<script>.cgi:<client ID>:<sequence>:" +
       lowercase_hex(SHA256(raw request body))))
   ```

The URI, identity, sequence and exact JSON or binary body bytes are bound by
the signature. Sequence numbers increase for each attempt, including network
failures; they are never reused with the same key. At `18446744073709551615`,
another login is required. The server verifies the MAC before atomically
claiming a sequence in a 64-entry replay window. Duplicate sequences and
sequences outside that window are rejected.

Calls on one instance are serialized with a lock, including transport, login
and password encryption. Concurrent Python threads therefore use one ordered
counter, and a slow upload cannot be overtaken by later polling requests.
`logout()` forgets the local credentials even when its network request fails;
a successful password change also clears them. Log in again before further
control operations. The client does not retry control commands or fall back to an
older MAC format. It sends neither `X-Request-HMAC` nor `X-Content-HMAC`.

**Non-standard quirk:** the SCRAM-internal HMACs swap the key/message roles
compared to RFC 5802, because the panel uses `CryptoJS.HmacSHA256(message,
key)` and the server mirrors it:

```
clientKey       = HMAC(key="Client Key",  msg=saltedPassword)
clientSignature = HMAC(key=authMessage,   msg=storedKey)
serverSignature = HMAC(key=authMessage,   msg=serverKey)
```

The per-request `X-Request-HMAC-V2` uses the normal orientation
(`key=accessKey`, `msg=signing string`). See `miner_api.py` for a reference
implementation and comments pointing at the firmware sources.

### Offline tests

Run from the repository root:

```bash
python3 -m unittest discover -s utils/api_client -p 'test_*.py' -v
```

The standard-library transport fixture checks SCRAM proofs, mandatory v2
advertisements, one-use challenges, exact JSON/binary MACs, URI binding,
counter exhaustion, failed requests and serialized concurrent calls. No
device or network connection is used.

### Antminer-compatible API

The device also exposes Bitmain-style endpoints at `/cgi-bin/<method>.cgi`
with standard HTTP Digest authentication (MD5, username `root`, panel
password), e.g. `get_system_info`, `stats`, `summary`, `pools`, `reboot`.
This works out of the box with `requests.auth.HTTPDigestAuth("root", password)`
and is a simpler alternative for basic monitoring. Control methods
(`set_miner_conf`, `blink`, `reboot`) require `antminer_api_control` to be
enabled in the miner configuration.
