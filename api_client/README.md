# GMiner API Client — Firmware 1.32

A standalone Python client for the HTTP API used by the GMiner web interface.
Use it for monitoring, configuration, diagnostics and firmware updates on
devices running **GMiner 1.32**.

Requires **Python 3.7+** and the standard library. Only password changes require
the optional [`pycryptodome`](https://pypi.org/project/pycryptodome/) package:

```bash
python3 -m pip install pycryptodome
```

## Quick start

Run these commands from the directory containing `miner_api.py`. Replace
`miner.local` with the device's IP address or hostname.

```bash
# Monitoring and diagnostics do not require a password
python3 miner_api.py miner.local stats
python3 miner_api.py miner.local metrics
python3 miner_api.py miner.local hashboards
python3 miner_api.py miner.local log --count 50
python3 miner_api.py miner.local log-pack -o diagnostics.zip

# Read configuration and save a backup
python3 miner_api.py miner.local config --password 'your-panel-password'
python3 miner_api.py miner.local backup -o backup.cfg --password 'your-panel-password'
```

The default panel password is `root`; omit `--password` when it is unchanged.
`--password` is accepted before the subcommand, or after an authenticated
subcommand. Public subcommands do not accept it after the subcommand.
The default HTTP port is 80; put `--port PORT` before the subcommand.
Use `python3 miner_api.py --help` or `<command> --help` for CLI options.

Each authenticated CLI command opens a fresh session and attempts logout when
it finishes. Access keys are not saved between invocations.

## Commands

### Public commands

| Command | Description |
|---|---|
| `stats` | Live hashrate, boards, pools, fans and errors |
| `metrics [--since TS]` | Available 1-hour and 24-hour history arrays |
| `hashboards` | Per-board and per-chip frequency, hashrate and temperatures |
| `presets` | Hardware description and available tuning presets |
| `log [--index N] [--count N]` | Event log entries |
| `log-pack [-o FILE]` | Download diagnostics as a local ZIP; default `log_pack.zip` |

Firmware 1.32 ignores `--since` and the library's `metrics(since=...)` parameter:
both return the available 1-hour and 24-hour histories without filtering.
Filter samples in your application if needed.

PSU telemetry is optional. On supported hardware, `stats` includes
`psu_temp: {"min": ..., "max": ...}` in °C, and `metrics` can include
`psu_temp_1h` and `psu_temp_24h`. Handle missing fields when sensors or readings
are unavailable.

### Authenticated commands

All commands below use the panel password. Configuration changes, restore,
reboot, firmware update and uninstall affect the running device.

| Command | Description |
|---|---|
| `config` | Current configuration as JSON |
| `set-config --file FILE` | Apply configuration sections from a JSON file |
| `reset-config` | Reset configuration to factory defaults |
| `backup [-o FILE]` | Download a `.cfg` backup; default `backup.cfg` |
| `restore FILE` | Restore a previously downloaded `.cfg` backup |
| `find-miner on\|off` | Toggle the identification LED |
| `reboot` | Reboot the device after about 3 seconds |
| `update FILE` | Upload firmware; device reboots on success |
| `uninstall` | Restore stock firmware and reboot |
| `change-password NEW` | Change the panel password; requires `pycryptodome` |
| `logout` | Invalidate the session opened by this invocation |

For `set-config`, use the same JSON structure as `config`. Supply complete
sections, for example the entire `cooling` object rather than one of its fields.

```bash
python3 miner_api.py miner.local set-config --file settings.json --password 'your-panel-password'
python3 miner_api.py miner.local restore backup.cfg --password 'your-panel-password'
python3 miner_api.py miner.local update firmware-1.32.tar --password 'your-panel-password'
```

## Python library

Public monitoring needs no login:

```python
from miner_api import MinerApi

api = MinerApi("miner.local")
stats = api.statistics()
print(stats.get("hashrate"), stats.get("psu_temp"))
history = api.metrics()
```

Authorize before reading or changing configuration and other control operations:

```python
from getpass import getpass
from miner_api import MinerApi

api = MinerApi("miner.local", port=80)
api.authorize(getpass("Panel password: "))
try:
    config = api.config()
    backup = api.backup_config()  # bytes; raises ApiError on an API error
    with open("backup.cfg", "wb") as output:
        output.write(backup)
finally:
    api.logout()
```

`api.set_config(config_subset)` applies configuration sections,
`api.restore_config(backup_bytes)` restores a backup, and
`api.update_firmware(firmware_bytes)` uploads firmware.
`api.download_log_pack("diagnostics.zip")` downloads diagnostic files and builds
the ZIP locally. It retries transient downloads up to three times and can
restart once if a file disappears. Only a complete ZIP replaces the output;
an unsuccessful download leaves an existing ZIP untouched.

Server errors raise `ApiError`, exposing `code` and optional `http_status`.
Error codes are: 1 Unknown, 2 Internal, 3 NotAuthorized, 4 InvalidParameters,
5 IncorrectPassword, 6 FileNotFound, 7 DownloadBusy and 8 NotAcceptable.
Client and transport errors use code -1.

Calls on one client instance are serialized. `logout()` clears local credentials
even if its request fails; successful password changes also clear them.
Authorize again before subsequent control operations. Control commands are not
automatically retried.

## Protocol

Calls use HTTP POST to `http://<host>/api/<script>.cgi`. JSON requests use
`Content-Type: application/json; charset=UTF-8`; firmware uploads and config
restore use raw bytes with `application/octet-stream`. JSON responses have this
envelope; the library returns `data` on success:

```json
{"session_id": "...", "result": true, "data": {}, "error": "", "error_code": 0}
```

Authentication uses the panel's SCRAM-SHA-256 variant through `authorize1` and
`authorize2`, including verification of the server proof. The client then signs
the exact JSON or binary request body:

```text
X-Client-Id: <canonical padded Base64 of the 32-byte client ID>
X-Request-HMAC: Base64(HMAC-SHA256(accessKey,
    "POST:/api/<script>.cgi:" + lowercase_hex(SHA256(raw body))))
```

The access key is the SCRAM `ClientSignature`. Requests have no sequence
counter. The SCRAM-internal HMACs use GMiner's key/message order:

```text
clientKey       = HMAC(key="Client Key", msg=saltedPassword)
clientSignature = HMAC(key=authMessage, msg=storedKey)
serverSignature = HMAC(key=authMessage, msg=serverKey)
```

Per-request HMAC uses the normal order: `key=accessKey`, `msg=signing string`.
See [`miner_api.py`](miner_api.py) for the reference implementation.

## Offline tests

Run from this directory:

```bash
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Tests use a standard-library transport fixture to check authentication,
request signatures, session cleanup, errors, diagnostic downloads and concurrent
calls. They do not contact a miner.
