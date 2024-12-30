"""
MIT License

Copyright (c) 2024 Enrico Pozzobon <enrico@epozzobon.it>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import struct
from typing import Callable
from sfs.aes import r_con as RCON, s_box as SBOX, AES


def rot_word(w: int) -> int:
    return ((w >> 8) & 0xffffff) | ((w << 24) & 0xff000000)


def sub_bytes(w: int) -> int:
    w, = struct.unpack('<I', bytes([SBOX[b] for b in struct.pack('<I', w)]))
    return w


def expand_key_32B(key: bytes) -> bytes:
    # Wrong AES 256-bit key expansion used in SFS files
    assert len(key) == 32
    key32 = list(struct.unpack('<8I', key))
    for j in range(7):
        key32[0] ^= sub_bytes(rot_word(key32[7])) ^ RCON[j+1]
        for i in range(7):
            key32[i+1] ^= key32[i]
        key32[4] ^= sub_bytes(key32[3])
        for i in range(4, 7):
            key32[i+1] ^= key32[i]
        key += struct.pack('<8I', *key32)
    return key[:240]


class WrongAES(AES):
    def _expand_key(self, master_key: bytes) -> list[list[list[int]]]:
        if self.n_rounds != 14:
            return AES._expand_key(self, master_key)
        round_keys = expand_key_32B(master_key)
        return [
            [list(struct.pack('<I', i))
             for i in struct.unpack('<IIII', round_keys[16*j:16*j+16])]
            for j in range(15)
        ]


def crc16(src: bytes, start: int = 0) -> int:
    lut = [
        0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
        0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
        0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
        0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
        0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
        0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
        0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
        0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
        0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
        0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
        0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
        0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
        0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
        0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
        0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
        0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
        0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
        0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
        0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
        0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
        0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
        0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
        0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
        0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
        0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
        0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
        0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
        0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
        0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
        0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
        0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
        0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040
    ]
    for p in src:
        start = start >> 8 ^ lut[(p ^ start) & 0xff]
    return start


def explode_key(password: bytes) -> bytes:
    pb = bytes.fromhex('''
        01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10
        10 32 54 76 98 BA DC FE EF CD AB 89 67 45 23 01
        67 45 23 01 0F 1E 2D 3C
    ''')
    h = pb[:32]
    p = [(u) for u in struct.unpack('<8I', h)]
    ripemd256_round(p, spiceup(password))
    return struct.pack('<8I', *[int(u) for u in p[:8]])[:32]


def ripemd256_round(p: list[int], m: bytes) -> None:
    q = [(u) for u in struct.unpack('<16I', m)]
    f: list[Callable[[int, int, int], int]] = [
        (lambda X, Y, Z: X ^ Y ^ Z),
        (lambda X, Y, Z: X & Y | ~X & Z),
        (lambda X, Y, Z: (X | ~Y) ^ Z),
        (lambda X, Y, Z: X & Z | Y & ~Z),
    ]
    K = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC]
    Kp = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x00000000]
    J = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
         7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
         11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
         11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12]
    R = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
         7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
         3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
         1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2]
    JP = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8]
    RP = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14]

    def rol(i: int, j: int) -> int:
        i &= 0xffffffff
        i = (i << j) | (i >> (32 - j))
        return i & 0xffffffff

    A, B, C, D, Ap, Bp, Cp, Dp = p
    for i in range(0, 64):
        A = rol(A + q[R[i]] + K[i//16]
                + f[i//16](B, C, D), J[i])
        Ap = rol(Ap + q[RP[i]] + Kp[i//16]
                 + f[(63-i)//16](Bp, Cp, Dp), JP[i])
        A, D, C, B, Ap, Dp, Cp, Bp = D, C, B, A, Dp, Cp, Bp, Ap
        if i == 15:
            A, Ap = Ap, A
        elif i == 31:
            B, Bp = Bp, B
        elif i == 47:
            C, Cp = Cp, C
        elif i == 63:
            D, Dp = Dp, D
    p[:] = [0xffffffff & (n + m)
            for n, m
            in zip(p, [A, B, C, D, Ap, Bp, Cp, Dp])]


def spiceup(rawkey: bytes) -> bytes:
    result = (rawkey + b'\x00' * 64)[:64]
    whoops = bytearray(result)
    whoops[len(rawkey)] = 0x80
    whoops[0x38:0x3a] = struct.pack('<H', len(rawkey) * 8)
    return bytes(whoops)


def xorpad(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b)
    return bytes(i ^ j for i, j in zip(a, b))
