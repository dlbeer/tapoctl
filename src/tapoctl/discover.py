"""Local network discovery of Tapo devices (TP-Link "TDP" on UDP port 20002).

The probe carries an RSA public key, which the device may use to encrypt
parts of its reply. We only need the plaintext fields (IP, MAC, model), so
the key is generated just to make a well-formed probe and then discarded.
"""

import base64
import json
import os
import random
import socket
import struct
import sys
import time
import zlib

PORT = 20002


def _is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        x = pow(random.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits, e):
    while True:
        n = int.from_bytes(os.urandom(bits // 8), "big")
        n |= (3 << (bits - 2)) | 1
        if (n - 1) % e and _is_probable_prime(n):
            return n


def _der(tag, body):
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + length + body


def _der_int(v):
    return _der(0x02, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def _public_key_pem(bits=1024):
    e = 65537
    n = _random_prime(bits // 2, e) * _random_prime(bits // 2, e)
    rsa_key = _der(0x30, _der_int(n) + _der_int(e))
    alg = _der(0x30, bytes.fromhex("06092a864886f70d010101") + b"\x05\x00")
    spki = _der(0x30, alg + _der(0x03, b"\x00" + rsa_key))
    b64 = base64.b64encode(spki).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) +
            "\n-----END PUBLIC KEY-----\n")


def _probe():
    payload = json.dumps({"params": {"rsa_key": _public_key_pem()}},
                         separators=(",", ":")).encode()
    header = struct.pack(">BBHHBBII", 2, 0, 1, len(payload), 17, 0,
                         random.getrandbits(32), 0x5A6B7C8D)
    pkt = bytearray(header + payload)
    pkt[12:16] = struct.pack(">I", zlib.crc32(pkt) & 0xFFFFFFFF)
    return bytes(pkt)


def _broadcast_addrs():
    addrs = {"255.255.255.255"}
    if sys.platform.startswith("linux"):
        try:
            import fcntl
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                for _, name in socket.if_nameindex():
                    try:
                        r = fcntl.ioctl(s.fileno(), 0x8919,  # SIOCGIFBRDADDR
                                        struct.pack("256s", name.encode()))
                        a = socket.inet_ntoa(r[20:24])
                        if a != "0.0.0.0":
                            addrs.add(a)
                    except OSError:
                        pass
            finally:
                s.close()
        except (ImportError, OSError):
            pass
    return sorted(addrs)


def discover(targets=None, timeout=3.0):
    """Probe the network and return {ip: info_dict} for responding devices.

    targets: extra addresses (unicast or broadcast) to probe in addition to
    the local broadcast addresses.
    """
    pkt = _probe()
    dests = _broadcast_addrs() + list(targets or [])
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    found = {}
    try:
        sock.bind(("", 0))
        for attempt in range(3):
            for d in dests:
                try:
                    sock.sendto(pkt, (d, PORT))
                except OSError:
                    pass
            end = time.monotonic() + timeout / 3
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    break
                sock.settimeout(left)
                try:
                    data, (ip, _) = sock.recvfrom(4096)
                except socket.timeout:
                    break
                try:
                    info = json.loads(data[16:]).get("result") or {}
                except ValueError:
                    continue
                info.setdefault("ip", ip)
                found[ip] = info
    finally:
        sock.close()
    return found
