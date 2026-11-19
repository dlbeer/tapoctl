import hashlib
import http.server
import json
import os
import threading
import unittest
from urllib.parse import parse_qs, urlparse

from src.tapoctl import aes, klap


def sha256(b):
    return hashlib.sha256(b).digest()


USER, PASS = "user@example.com", "secret"
AUTH = sha256(hashlib.sha1(USER.encode()).digest() +
              hashlib.sha1(PASS.encode()).digest())


class FakeDevice(http.server.BaseHTTPRequestHandler):
    """Device side of KLAP v2, written independently of the client."""
    state = {}

    def log_message(self, *a):
        pass

    def reply(self, body, cookie=False):
        self.send_response(200)
        if cookie:
            self.send_header("Set-Cookie", "TP_SESSIONID=abc;TIMEOUT=86400")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        url = urlparse(self.path)
        st = FakeDevice.state
        if url.path == "/app/handshake1":
            st["local"], st["remote"] = body, os.urandom(16)
            self.reply(st["remote"] + sha256(body + st["remote"] + AUTH),
                       cookie=True)
        elif url.path == "/app/handshake2":
            assert self.headers["Cookie"] == "TP_SESSIONID=abc"
            assert body == sha256(st["remote"] + st["local"] + AUTH)
            self.reply(b"")
        elif url.path == "/app/request":
            seed = st["local"] + st["remote"] + AUTH
            key = sha256(b"lsk" + seed)[:16]
            iv = sha256(b"iv" + seed)[:12]
            seq = int(parse_qs(url.query)["seq"][0])
            sb = seq.to_bytes(4, "big", signed=True)
            assert body[:32] == sha256(sha256(b"ldk" + seed)[:28] + sb +
                                       body[32:])
            req = json.loads(aes.cbc_decrypt(key, iv + sb, body[32:]))
            if req["method"] == "set_device_info":
                st["on"] = req["params"]["device_on"]
                result = {}
            else:
                result = {"device_on": st.get("on", False),
                          "nickname": "TGFtcA==", "model": "P110M"}
            resp = json.dumps({"error_code": 0, "result": result}).encode()
            self.reply(os.urandom(32) + aes.cbc_encrypt(key, iv + sb, resp))


class KlapTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), FakeDevice)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_power_cycle(self):
        d = klap.Device("127.0.0.1", USER, PASS, port=self.port)
        d.set_power(True)
        info = d.get_info()
        self.assertTrue(info["device_on"])
        self.assertEqual(info["nickname"], "TGFtcA==")
        d.set_power(False)
        self.assertFalse(d.get_info()["device_on"])

    def test_bad_credentials(self):
        d = klap.Device("127.0.0.1", USER, "wrong", port=self.port)
        with self.assertRaises(klap.AuthError):
            d.get_info()


class AesTest(unittest.TestCase):
    def test_fips197_vector(self):
        # FIPS-197 Appendix C.1, as single-block CBC with zero IV.
        key = bytes(range(16))
        pt = bytes.fromhex("00112233445566778899aabbccddeeff")
        ct = aes.cbc_encrypt(key, bytes(16), pt)
        self.assertEqual(ct[:16].hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes.cbc_decrypt(key, bytes(16), ct), pt)


if __name__ == "__main__":
    unittest.main()
