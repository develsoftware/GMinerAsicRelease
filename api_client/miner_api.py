#!/usr/bin/env python3
"""
Standalone Python client for the miner HTTP API.

This script replicates exactly what the web control panel does when it talks
to the device (see web/control_panel/src/api/ApiManager.ts and
miner/src/ApiServer/ApiServer.cpp):

  * All API calls are HTTP POST requests to http://<host>/api/<script>.cgi
  * Public (read-only) endpoints need no authentication:
    statistics, metrics, hashboards, presets, log, log_pack_list, log_pack_file
  * Control endpoints (config, set_config, reboot_system, update, ...)
    require a SCRAM-SHA-256 login followed by per-request HMAC-SHA-256
    v2 signatures (X-Client-Id, X-Request-Sequence and X-Request-HMAC-V2).

Every JSON response uses the envelope:
  {"session_id": "...", "result": true|false, "data": ..., "error": "...",
   "error_code": 0}
error_code values: 1 Unknown, 2 Internal, 3 NotAuthorized,
                   4 InvalidParameters, 5 IncorrectPassword,
                   6 FileNotFound, 7 DownloadBusy, 8 NotAcceptable

Authentication: the default panel password is "root" (it can be changed
in the web panel; if changed, pass it via --password).

Dependencies: Python 3.6+ standard library only.
Optional: `pycryptodome` is required ONLY for the `change-password` command
(the new password is sent AES-256-CBC encrypted with the session access key).

Usage examples:
  python3 miner_api.py 192.168.0.100 stats
  python3 miner_api.py 192.168.0.100 config
  python3 miner_api.py 192.168.0.100 reboot --password mysecret
  python3 miner_api.py 192.168.0.100 set-config --file pools.json
  python3 miner_api.py 192.168.0.100 backup -o backup.cfg
  python3 miner_api.py 192.168.0.100 update firmware.tar
"""

import argparse
import base64
import gzip
import hashlib
import hmac
import http.client
import json
import os
import re
import secrets
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import zipfile
import zlib

DEFAULT_PASSWORD = "root"          # factory default panel password
DEFAULT_TIMEOUT = 5                # seconds, same as the web panel
LONG_TIMEOUT = 180                 # seconds, used for updates/backups/log files
API_PREFIX = "/api/"               # signed URI must include prefix + ".cgi"
MAX_SEQUENCE = (1 << 64) - 1


class ApiError(Exception):
    """Raised when the API answers with result=false or an HTTP error."""

    ERROR_NAMES = {
        1: "Unknown", 2: "Internal", 3: "NotAuthorized",
        4: "InvalidParameters", 5: "IncorrectPassword",
        6: "FileNotFound", 7: "DownloadBusy", 8: "NotAcceptable",
    }

    def __init__(self, code, message, http_status=None):
        self.code = code
        self.http_status = http_status
        name = self.ERROR_NAMES.get(code, "Unknown")
        super().__init__("API error %d (%s): %s" % (code, name, message))


class MinerApi:
    """Client for one miner. Create, optionally authorize(), then call."""

    def __init__(self, host, port=80):
        self.base_url = "http://%s:%d%s" % (host, port, API_PREFIX)
        self.client_id = None        # base64 string from authorize1.cgi
        self.access_key = None       # raw bytes: SCRAM ClientSignature
        self._sequence = 0
        # Serialize the synchronous transport too: a slow upload must not fall
        # behind 64 later requests in the server's replay window.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Low-level transport
    # ------------------------------------------------------------------

    def _post(self, script, body, content_type, signed, timeout, client_id=None):
        """Send one POST request and return raw response bytes.

        The HMAC (when `signed` is True) is computed over the EXACT raw body
        bytes we put on the wire:
          base64(HMAC-SHA256(access_key,
                  "v2:POST:/api/<script>.cgi:<client ID>:<sequence>:" +
                  hex_lower(SHA256(body))))
        """
        with self._lock:
            return self._post_locked(script, body, content_type, signed,
                                     timeout, client_id)

    def _post_locked(self, script, body, content_type, signed, timeout, client_id):
        uri = "%s%s.cgi" % (API_PREFIX, script)
        headers = {"Content-type": content_type}
        if client_id is not None:
            headers["X-Client-Id"] = client_id
        if signed:
            if self.access_key is None or self.client_id is None:
                raise ApiError(3, "authorize() is required")
            if self._sequence == MAX_SEQUENCE:
                raise ApiError(3, "request sequence exhausted; authorize again")
            self._sequence += 1
            sequence = str(self._sequence)
            body_hash = hashlib.sha256(body).hexdigest()
            data = ("v2:POST:%s:%s:%s:%s" %
                    (uri, self.client_id, sequence, body_hash)).encode("utf-8")
            headers["X-Client-Id"] = self.client_id
            headers["X-Request-Sequence"] = sequence
            headers["X-Request-HMAC-V2"] = base64.b64encode(
                hmac.new(self.access_key, data, hashlib.sha256).digest()
            ).decode("ascii")

        request = urllib.request.Request(
            self.base_url + script + ".cgi", data=body,
            headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                raw = resp.read()
                if script == "log_pack_file":
                    # urllib does not decode HTTP gzip. Decode both log formats;
                    # octet-stream core dumps retain their compressed bytes.
                    response_headers = getattr(resp, "headers", {})
                    length = response_headers.get("Content-Length")
                    if length is not None and len(raw) != int(length):
                        raise ApiError(-1, "incomplete diagnostic file response")
                    content_type = response_headers.get("Content-Type", "")
                    content_type = content_type.split(";", 1)[0].strip().lower()
                    if content_type == "application/json":
                        self._response_data(raw)
                        raise ApiError(2, "unexpected JSON diagnostic file response")
                    encoding = response_headers.get("Content-Encoding", "").lower()
                    if encoding and encoding not in ("gzip", "identity"):
                        raise ApiError(2, "unsupported diagnostic file encoding: %s" %
                                       encoding)
                    if encoding == "gzip" or content_type == "application/gzip":
                        try:
                            raw = gzip.decompress(raw)
                        except (OSError, EOFError, zlib.error) as e:
                            raise ApiError(-1, "invalid gzip diagnostic file: %s" % e)
                return raw
        except urllib.error.HTTPError as e:
            try:
                envelope = json.loads(e.read().decode("utf-8"))
            except (ValueError, OSError):
                envelope = {}
            raise ApiError(envelope.get("error_code", -1),
                           envelope.get("error", "HTTP %d %s" % (e.code, e.reason)),
                           http_status=e.code)
        except urllib.error.URLError as e:
            raise ApiError(-1, "connection failed: %s" % e.reason)
        except (OSError, http.client.HTTPException) as e:
            raise ApiError(-1, "connection failed: %s" % e)

    def _request(self, script, params=None, binary=False, timeout=DEFAULT_TIMEOUT):
        """POST JSON (or raw bytes) and return the `data` field / raw bytes."""
        with self._lock:
            if isinstance(params, (bytes, bytearray)):
                raw = self._post(script, bytes(params), "application/octet-stream",
                                 signed=True, timeout=timeout)
            else:
                payload = json.dumps(params if params is not None else {}).encode("utf-8")
                signed = self.access_key is not None
                raw = self._post(script, payload, "application/json; charset=UTF-8",
                                 signed=signed, timeout=timeout)
            if binary:
                return raw                       # e.g. log_pack_file / backup_config
            return self._response_data(raw)

    @staticmethod
    def _response_data(raw):
        envelope = json.loads(raw.decode("utf-8"))
        if not envelope.get("result"):
            raise ApiError(envelope.get("error_code", -1),
                           envelope.get("error", "Unknown Error"))
        return envelope.get("data")

    # ------------------------------------------------------------------
    # Authentication (SCRAM-SHA-256, same variant as the web panel)
    # ------------------------------------------------------------------

    def authorize(self, password):
        """Full login handshake. Stores client_id + access_key on success."""
        with self._lock:
            self._clear_authorization()
            self._authorize_locked(password)

    def _clear_authorization(self):
        self.client_id = None
        self.access_key = None
        self._sequence = 0

    @staticmethod
    def _require_v2(data):
        if not isinstance(data, dict) or data.get("authorization_version") != 2:
            raise ApiError(-1, "authorization protocol v2 required")

    @staticmethod
    def _canonical_client_id(value):
        try:
            if not isinstance(value, str) or len(value) != 44:
                raise ValueError()
            decoded = base64.b64decode(value, validate=True)
            if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
                raise ValueError()
        except (ValueError, TypeError):
            raise ApiError(-1, "invalid client identity")
        return value

    def _authorize_locked(self, password):
        client_nonce = "".join(chr(secrets.randbelow(0x7e - 0x2d + 1) + 0x2d)
                               for _ in range(16))
        client_first = "n,,n=user,r=" + client_nonce

        # Step 1: ask for salt / iteration count / client id.
        data = self._request("authorize1", {"data": {"message": client_first}})
        self._require_v2(data)
        client_id = self._canonical_client_id(data.get("client_id"))
        server_first = data.get("message")

        # Parse "r=<client+server nonce>,s=<base64 salt>,i=<iterations>".
        parts = re.fullmatch(r"r=([^,]+),s=([^,]*),i=([1-9][0-9]*)",
                             server_first) if isinstance(server_first, str) else None
        if parts is None:
            raise ApiError(-1, "invalid SCRAM challenge")
        nonce, salt_b64, iterations = parts.group(1), parts.group(2), int(parts.group(3))
        if not nonce.startswith(client_nonce) or len(nonce) <= len(client_nonce):
            raise ApiError(-1, "server nonce mismatch")

        # Step 2: derive keys exactly as the web panel does.
        # WARNING, non-standard SCRAM: the panel calls CryptoJS
        # HmacSHA256(message, key), and the server mirrors that
        # (CryptUtils::hmacSha256(key=authMessage/"Client Key", ...)),
        # so the HMAC key/message roles are SWAPPED vs RFC 5802:
        #   clientKey       = HMAC(key="Client Key", msg=saltedPassword)
        #   clientSignature = HMAC(key=authMessage,  msg=storedKey)
        #   serverSignature = HMAC(key=authMessage,  msg=serverKey)
        salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                     base64.b64decode(salt_b64),
                                     iterations, dklen=32)
        client_key = hmac.new(b"Client Key", salted, hashlib.sha256).digest()
        stored_key = hashlib.sha256(client_key).digest()
        final_without_proof = "c=biws,r=" + nonce
        auth_message = ",".join([client_first, server_first,
                                 final_without_proof]).encode("utf-8")
        client_signature = hmac.new(auth_message, stored_key,
                                    hashlib.sha256).digest()
        proof = bytes(a ^ b for a, b in zip(client_key, client_signature))

        # Step 3: send proof; server replies with "v=<server signature>".
        # NOTE: authorize2 carries X-Client-Id but intentionally no HMAC.
        msg = final_without_proof + ",p=" + base64.b64encode(proof).decode()
        payload = json.dumps({"data": {"message": msg}}).encode("utf-8")
        raw = self._post("authorize2", payload, "application/json; charset=UTF-8",
                         signed=False, timeout=DEFAULT_TIMEOUT, client_id=client_id)
        data = self._response_data(raw)
        self._require_v2(data)

        # Verify the server knows the password too (mutual authentication).
        server_key = hmac.new(b"Server Key", salted, hashlib.sha256).digest()
        expected = hmac.new(auth_message, server_key, hashlib.sha256).digest()
        server_sig = data.get("message")
        expected_sig = "v=" + base64.b64encode(expected).decode("ascii")
        if (not isinstance(server_sig, str) or
                re.fullmatch(r"v=[A-Za-z0-9+/]{43}=", server_sig) is None or
                not hmac.compare_digest(server_sig, expected_sig)):
            raise ApiError(-1, "server signature mismatch")

        # ClientSignature doubles as the session access key (TTL: 1 hour).
        self.client_id = client_id
        self.access_key = client_signature
        self._sequence = 0

    # ------------------------------------------------------------------
    # Public endpoints (no authorization needed)
    # ------------------------------------------------------------------

    def statistics(self):
        """Live miner status: hashrate, boards, pools, fans, errors."""
        return self._request("statistics")

    def metrics(self, since=0):
        """Hashrate/temperature history arrays since unix time `since`."""
        return self._request("metrics", {"t": int(since)})

    def hashboards(self):
        """Per-board, per-chip frequency/hashrate/temperature array."""
        return self._request("hashboards")

    def presets(self):
        """Available tuning presets and hardware description."""
        return self._request("presets")

    def log(self, index=0, count=100):
        """Event log: `count` entries starting at `index`."""
        return self._request("log", {"index": int(index), "count": int(count)})

    def log_pack_list(self):
        """Flush current logs and return diagnostic files in archive order."""
        return self._request("log_pack_list", timeout=LONG_TIMEOUT)

    def log_pack_file(self, file_id):
        """Return one TXT log or the original compressed core dump bytes."""
        return self._request("log_pack_file", {"id": file_id},
                             binary=True, timeout=LONG_TIMEOUT)

    @staticmethod
    def _diagnostic_files(manifest):
        if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
            raise ApiError(2, "invalid diagnostic file list")
        files = manifest["files"]
        ids, names = set(), set()
        for entry in files:
            if not isinstance(entry, dict):
                raise ApiError(2, "invalid diagnostic file entry")
            file_id, name = entry.get("id"), entry.get("name")
            kind, method = entry.get("kind"), entry.get("zip_method")
            if (not isinstance(file_id, str) or not file_id or file_id in ids or
                    not isinstance(name, str) or not name or name in (".", "..") or
                    "/" in name or "\\" in name or "\x00" in name or name in names or
                    (kind, method) not in (("log", "deflate"), ("coredump", "store"))):
                raise ApiError(2, "invalid diagnostic file entry")
            ids.add(file_id)
            names.add(name)
        return files

    @staticmethod
    def _diagnostic_retryable(error):
        return (error.code == 7 or
                error.http_status in (408, 429, 500, 502, 503, 504) or
                (error.code == -1 and error.http_status is None))

    def _diagnostic_request(self, request, attempts):
        for attempt in range(attempts):
            try:
                return request()
            except ApiError as error:
                if attempt + 1 == attempts or not self._diagnostic_retryable(error):
                    raise
                time.sleep(0.2 * (attempt + 1))

    def download_log_pack(self, output_path, attempts=3, restarts=1):
        """Build a ZIP locally, publishing the output only after all files arrive.

        Each transient request has at most `attempts` tries. A removed file
        discards the incomplete archive and fetches a fresh manifest, at most
        `restarts` times. Only one input file is held in memory at a time.
        """
        if attempts < 1 or restarts < 0:
            raise ValueError("attempts must be positive and restarts non-negative")
        output_path = os.path.abspath(output_path)
        for restart in range(restarts + 1):
            manifest = self._diagnostic_request(self.log_pack_list, attempts)
            files = self._diagnostic_files(manifest)
            fd, temporary_path = tempfile.mkstemp(
                prefix=".log-pack-", suffix=".zip.tmp",
                dir=os.path.dirname(output_path))
            os.close(fd)
            try:
                with zipfile.ZipFile(temporary_path, "w", allowZip64=True) as archive:
                    for entry in files:
                        data = self._diagnostic_request(
                            lambda: self.log_pack_file(entry["id"]), attempts)
                        method = (zipfile.ZIP_STORED if entry["zip_method"] == "store"
                                  else zipfile.ZIP_DEFLATED)
                        archive.writestr(entry["name"], data, compress_type=method)
                        del data
                os.replace(temporary_path, output_path)
                return
            except ApiError as error:
                if error.code != 6 or restart == restarts:
                    raise
            finally:
                if os.path.exists(temporary_path):
                    os.unlink(temporary_path)

    # ------------------------------------------------------------------
    # Authorized endpoints (call authorize() first)
    # ------------------------------------------------------------------

    def config(self):
        """Current configuration: stratum/cooling/performance/miner/network."""
        return self._request("config")

    def set_config(self, cfg):
        """Apply a configuration subset (same JSON shape as config())."""
        return self._request("set_config", cfg)

    def reset_config(self):
        """Reset configuration to factory defaults."""
        return self._request("reset_config")

    def backup_config(self):
        """Download a config backup (raw .cfg bytes)."""
        return self._request("backup_config", binary=True, timeout=LONG_TIMEOUT)

    def restore_config(self, blob):
        """Upload a backup previously obtained via backup_config()."""
        return self._request("restore_config", blob, timeout=LONG_TIMEOUT)

    def find_miner(self, value):
        """Toggle the identification LED (True = blinking)."""
        return self._request("find_miner", {"value": bool(value)})

    def reboot(self):
        """Reboot the device (takes effect ~3 seconds later)."""
        return self._request("reboot_system")

    def update_firmware(self, blob):
        """Flash a firmware image (raw bytes). Device reboots on success."""
        return self._request("update", blob, timeout=LONG_TIMEOUT)

    def uninstall(self):
        """Restore the stock firmware and reboot."""
        return self._request("uninstall")

    def logout(self):
        """Invalidate the server-side session group and forget the local key."""
        with self._lock:
            try:
                return self._request("logout")
            finally:
                self._clear_authorization()

    def change_password(self, new_password):
        """Change the panel password. The session dies afterwards.

        The new password is AES-256-CBC encrypted with the session access
        key and a fixed IV (see ApiManager.ts changePassword).
        """
        with self._lock:
            return self._change_password_locked(new_password)

    def _change_password_locked(self, new_password):
        if self.access_key is None:
            raise ApiError(3, "authorize() is required")
        try:
            from Crypto.Cipher import AES           # pycryptodome
            from Crypto.Util.Padding import pad
        except ImportError:
            raise ApiError(-1, "change_password requires `pip install "
                               "pycryptodome`")
        iv = bytes.fromhex("5b4fb7715e7166f618eff3539669d87f")
        cipher = AES.new(self.access_key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(new_password.encode("utf-8"), 16))
        result = self._request("change_password",
                               {"password": base64.b64encode(encrypted).decode()})
        self._clear_authorization()
        return result


# ----------------------------------------------------------------------
# Command line interface
# ----------------------------------------------------------------------

def _print_json(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main():
    parser = argparse.ArgumentParser(
        description="Client for the miner HTTP API (same protocol as the "
                    "web control panel).")
    parser.add_argument("host", help="miner IP address or hostname")
    parser.add_argument("--port", type=int, default=80,
                        help="API port (default: 80)")
    parser.add_argument("--password", default=DEFAULT_PASSWORD,
                        help="panel password (default: %(default)s)")

    # Also accept --password AFTER the subcommand (argparse only parses
    # top-level options before it). SUPPRESS keeps the global default
    # when the option is not repeated on the subcommand.
    pw = argparse.ArgumentParser(add_help=False)
    pw.add_argument("--password", default=argparse.SUPPRESS)

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("stats", help="live statistics (no auth)")
    m = sub.add_parser("metrics", help="hashrate/temp history (no auth)")
    m.add_argument("--since", type=int, default=0, help="unix timestamp")
    sub.add_parser("hashboards", help="chip-level board data (no auth)")
    sub.add_parser("presets", help="available presets (no auth)")
    lg = sub.add_parser("log", help="event log (no auth)")
    lg.add_argument("--index", type=int, default=0)
    lg.add_argument("--count", type=int, default=100)
    lp = sub.add_parser("log-pack",
                        help="download diagnostics and build a ZIP (no auth)")
    lp.add_argument("-o", "--output", default="log_pack.zip")

    sub.add_parser("config", parents=[pw], help="current configuration")
    sc = sub.add_parser("set-config", parents=[pw],
                        help="apply configuration subset")
    sc.add_argument("--file", required=True,
                    help="JSON file with config subset (see `config` output)")
    sub.add_parser("reset-config", parents=[pw],
                   help="factory-reset the configuration")
    bc = sub.add_parser("backup", parents=[pw],
                        help="download config backup (.cfg)")
    bc.add_argument("-o", "--output", default="backup.cfg")
    rc = sub.add_parser("restore", parents=[pw],
                        help="restore config from backup file")
    rc.add_argument("file")
    fm = sub.add_parser("find-miner", parents=[pw],
                        help="blink the identification LED")
    fm.add_argument("state", choices=["on", "off"])
    sub.add_parser("reboot", parents=[pw], help="reboot the device")
    up = sub.add_parser("update", parents=[pw], help="flash firmware image file")
    up.add_argument("file")
    sub.add_parser("uninstall", parents=[pw], help="restore stock firmware")
    cp = sub.add_parser("change-password", parents=[pw],
                        help="change panel password")
    cp.add_argument("new_password")
    sub.add_parser("logout", parents=[pw], help="invalidate the session")

    args = parser.parse_args()
    api = MinerApi(args.host, args.port)

    # Commands that only touch public endpoints never need to log in.
    public = {"stats", "metrics", "hashboards", "presets", "log", "log-pack"}
    try:
        if args.command not in public:
            api.authorize(args.password)
        _run_command(api, args)
    finally:
        # Each CLI process owns its fresh root. Do not fill the server's
        # bounded session table with one hour of completed script invocations.
        if api.access_key is not None:
            try:
                api.logout()
            except (ApiError, OSError, ValueError):
                pass


def _run_command(api, args):
    if args.command == "stats":
        _print_json(api.statistics())
    elif args.command == "metrics":
        _print_json(api.metrics(args.since))
    elif args.command == "hashboards":
        _print_json(api.hashboards())
    elif args.command == "presets":
        _print_json(api.presets())
    elif args.command == "log":
        _print_json(api.log(args.index, args.count))
    elif args.command == "log-pack":
        api.download_log_pack(args.output)
        print("saved to", args.output)
    elif args.command == "config":
        _print_json(api.config())
    elif args.command == "set-config":
        with open(args.file, "r", encoding="utf-8") as f:
            _print_json(api.set_config(json.load(f)) or {"result": True})
    elif args.command == "reset-config":
        api.reset_config()
        print("configuration reset")
    elif args.command == "backup":
        with open(args.output, "wb") as f:
            f.write(api.backup_config())
        print("saved to", args.output)
    elif args.command == "restore":
        with open(args.file, "rb") as f:
            api.restore_config(f.read())
        print("configuration restored")
    elif args.command == "find-miner":
        api.find_miner(args.state == "on")
        print("find_miner:", args.state)
    elif args.command == "reboot":
        api.reboot()
        print("rebooting")
    elif args.command == "update":
        with open(args.file, "rb") as f:
            api.update_firmware(f.read())
        print("firmware uploaded, device will reboot")
    elif args.command == "uninstall":
        api.uninstall()
        print("restoring stock firmware, device will reboot")
    elif args.command == "change-password":
        api.change_password(args.new_password)
        print("password changed (session invalidated)")
    elif args.command == "logout":
        api.logout()
        print("logged out")


if __name__ == "__main__":
    try:
        main()
    except ApiError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
