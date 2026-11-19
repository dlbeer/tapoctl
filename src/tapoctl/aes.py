"""Minimal pure-Python AES-128-CBC with PKCS#7 padding.

The Python standard library has no block cipher, and we want tapoctl to run
with nothing but the system interpreter. Messages exchanged with Tapo devices
are tiny, so speed is not a concern.
"""


def _xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def _gmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _xtime(a)
        b >>= 1
    return r


def _make_sbox():
    sbox = [0] * 256
    for x in range(256):
        # Multiplicative inverse in GF(2^8) (0 maps to 0).
        inv = 0
        if x:
            for y in range(1, 256):
                if _gmul(x, y) == 1:
                    inv = y
                    break
        s = inv
        for i in range(1, 5):
            s ^= ((inv << i) | (inv >> (8 - i))) & 0xFF
        sbox[x] = s ^ 0x63
    return sbox


_SBOX = _make_sbox()
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

_MUL = {n: [_gmul(x, n) for x in range(256)] for n in (2, 3, 9, 11, 13, 14)}


def _expand_key(key):
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    w = list(key)
    rcon = 1
    for i in range(4, 44):
        t = w[(i - 1) * 4:i * 4]
        if i % 4 == 0:
            t = [_SBOX[t[1]] ^ rcon, _SBOX[t[2]], _SBOX[t[3]], _SBOX[t[0]]]
            rcon = _xtime(rcon)
        w.extend(w[(i - 4) * 4 + j] ^ t[j] for j in range(4))
    return [w[r * 16:(r + 1) * 16] for r in range(11)]


def _add(s, k):
    return [a ^ b for a, b in zip(s, k)]


def _shift_rows(s):
    return [s[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]


def _inv_shift_rows(s):
    return [s[(r + 4 * ((c - r) % 4))] for c in range(4) for r in range(4)]


def _mix_columns(s, m):
    m2, m3 = _MUL[m[0]], _MUL[m[1]]
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out += [
            m2[a[0]] ^ m3[a[1]] ^ a[2] ^ a[3],
            a[0] ^ m2[a[1]] ^ m3[a[2]] ^ a[3],
            a[0] ^ a[1] ^ m2[a[2]] ^ m3[a[3]],
            m3[a[0]] ^ a[1] ^ a[2] ^ m2[a[3]],
        ]
    return out


def _inv_mix_columns(s):
    e, b, d, n = _MUL[14], _MUL[11], _MUL[13], _MUL[9]
    out = []
    for c in range(4):
        a = s[4 * c:4 * c + 4]
        out += [
            e[a[0]] ^ b[a[1]] ^ d[a[2]] ^ n[a[3]],
            n[a[0]] ^ e[a[1]] ^ b[a[2]] ^ d[a[3]],
            d[a[0]] ^ n[a[1]] ^ e[a[2]] ^ b[a[3]],
            b[a[0]] ^ d[a[1]] ^ n[a[2]] ^ e[a[3]],
        ]
    return out


def _encrypt_block(rk, block):
    s = _add(block, rk[0])
    for r in range(1, 10):
        s = _mix_columns(_shift_rows([_SBOX[x] for x in s]), (2, 3))
        s = _add(s, rk[r])
    s = _shift_rows([_SBOX[x] for x in s])
    return _add(s, rk[10])


def _decrypt_block(rk, block):
    s = _add(block, rk[10])
    for r in range(9, 0, -1):
        s = [_INV_SBOX[x] for x in _inv_shift_rows(s)]
        s = _inv_mix_columns(_add(s, rk[r]))
    s = [_INV_SBOX[x] for x in _inv_shift_rows(s)]
    return _add(s, rk[0])


def cbc_encrypt(key, iv, data):
    """Encrypt with AES-128-CBC, applying PKCS#7 padding."""
    rk = _expand_key(key)
    pad = 16 - len(data) % 16
    data = bytes(data) + bytes([pad]) * pad
    prev = list(iv)
    out = bytearray()
    for i in range(0, len(data), 16):
        prev = _encrypt_block(rk, _add(data[i:i + 16], prev))
        out += bytes(prev)
    return bytes(out)


def cbc_decrypt(key, iv, data):
    """Decrypt AES-128-CBC and strip PKCS#7 padding."""
    if len(data) % 16 or not data:
        raise ValueError("ciphertext length is not a multiple of 16")
    rk = _expand_key(key)
    prev = list(iv)
    out = bytearray()
    for i in range(0, len(data), 16):
        block = list(data[i:i + 16])
        out += bytes(_add(_decrypt_block(rk, block), prev))
        prev = block
    pad = out[-1]
    if not 1 <= pad <= 16 or out[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding")
    return bytes(out[:-pad])
