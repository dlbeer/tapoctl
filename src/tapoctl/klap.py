"""KLAP local protocol used by current Tapo plug firmware (P100/P110/P110M...).

Handshake:
  1. POST /app/handshake1 <local_seed>        -> <remote_seed><server_hash>
  2. POST /app/handshake2 <client_hash>        (with TP_SESSIONID cookie)
Then each request is AES-128-CBC encrypted with keys derived from the seeds
and a hash of the account credentials, and POSTed to /app/request?seq=N.
"""

import hashlib
import http.client
import json
import os
import time
import uuid

from . import aes


class TapoError(Exception):
    pass


class AuthError(TapoError):
    pass


def _sha256(b):
    return hashlib.sha256(b).digest()


def _sha1(b):
    return hashlib.sha1(b).digest()


def _md5(b):
    return hashlib.md5(b).digest()


class _Session:
    def __init__(self, local_seed, remote_seed, auth_hash):
        h = local_seed + remote_seed + auth_hash
        self.key = _sha256(b"lsk" + h)[:16]
        full_iv = _sha256(b"iv" + h)
        self.iv = full_iv[:12]
        self.seq = int.from_bytes(full_iv[-4:], "big", signed=True)
        self.sig = _sha256(b"ldk" + h)[:28]

    def _seq_bytes(self):
        return self.seq.to_bytes(4, "big", signed=True)

    def encrypt(self, msg):
        self.seq += 1
        if self.seq > 0x7FFFFFFF:
            self.seq = -0x80000000
        ct = aes.cbc_encrypt(self.key, self.iv + self._seq_bytes(), msg)
        return _sha256(self.sig + self._seq_bytes() + ct) + ct

    def decrypt(self, msg):
        return aes.cbc_decrypt(self.key, self.iv + self._seq_bytes(), msg[32:])


class Device:
    """A connection to a single Tapo device over KLAP."""

    def __init__(self, host, username, password, timeout=5.0, port=80):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.username = username.encode()
        self.password = password.encode()
        self.cookie = None
        self.session = None
        self.terminal_uuid = str(uuid.uuid4())

    def _post(self, path, body):
        conn = http.client.HTTPConnection(self.host, self.port,
                                          timeout=self.timeout)
        try:
            headers = {"Content-Type": "application/octet-stream"}
            if self.cookie:
                headers["Cookie"] = self.cookie
            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            data = resp.read()
            for k, v in resp.getheaders():
                if k.lower() == "set-cookie" and v.startswith("TP_SESSIONID="):
                    self.cookie = v.split(";", 1)[0]
            return resp.status, data
        finally:
            conn.close()

    def handshake(self):
        local_seed = os.urandom(16)
        status, data = self._post("/app/handshake1", local_seed)
        if status != 200 or len(data) < 48:
            raise TapoError("%s: handshake1 failed (HTTP %d); device may not "
                            "support the KLAP protocol" % (self.host, status))
        remote_seed, server_hash = data[:16], data[16:48]

        # KLAP v2 (current firmware), then v1 (older firmware).
        v2 = _sha256(_sha1(self.username) + _sha1(self.password))
        v1 = _md5(_md5(self.username) + _md5(self.password))
        if _sha256(local_seed + remote_seed + v2) == server_hash:
            auth_hash = v2
            client_hash = _sha256(remote_seed + local_seed + v2)
        elif _sha256(local_seed + v1) == server_hash:
            auth_hash = v1
            client_hash = _sha256(remote_seed + v1)
        else:
            raise AuthError("%s: credentials rejected by device" % self.host)

        status, _ = self._post("/app/handshake2", client_hash)
        if status != 200:
            raise TapoError("%s: handshake2 failed (HTTP %d)" %
                            (self.host, status))
        self.session = _Session(local_seed, remote_seed, auth_hash)

    def request(self, method, params=None):
        if self.session is None:
            self.handshake()
        msg = {
            "method": method,
            "request_time_milli": int(time.time() * 1000),
            "terminal_uuid": self.terminal_uuid,
        }
        if params is not None:
            msg["params"] = params
        payload = self.session.encrypt(json.dumps(msg).encode())
        status, data = self._post("/app/request?seq=%d" % self.session.seq,
                                  payload)
        if status != 200:
            self.session = None
            raise TapoError("%s: request failed (HTTP %d)" % (self.host, status))
        try:
            resp = json.loads(self.session.decrypt(data))
        except ValueError as e:
            raise TapoError("%s: bad response: %s" % (self.host, e))
        code = resp.get("error_code", -1)
        if code != 0:
            raise TapoError("%s: %s returned error %d" %
                            (self.host, method, code))
        return resp.get("result")

    def get_info(self):
        return self.request("get_device_info")

    def set_power(self, on):
        self.request("set_device_info", {"device_on": bool(on)})
