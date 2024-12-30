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

from dataclasses import dataclass
import struct

from sfs.wrongaes import WrongAES, explode_key, xorpad


@dataclass
class DirectoryTree:
    nnco: int
    b: int
    c: int
    d: int
    e: int
    f: int
    g: int
    h: int
    files: list['FileHeader']

    def __init__(self, data: bytes, rem_entries: int) -> None:
        t = struct.unpack('<i7I', data[:32])
        self.nnco, self.b, self.c, self.d, self.e, self.f, self.g, self.h = t
        self.files = []

        leftover = data[32:]

        for _ in range(rem_entries):
            if len(leftover) < 512:
                assert all(b == 0 for b in leftover)
                break

            fileheader = leftover[:512]
            leftover = leftover[512:]
            rem_entries -= 1

            fh = FileHeader(fileheader)
            self.files.append(fh)

        assert all(b == 0 for b in leftover)

    def __repr__(self) -> str:
        return 'DirectoryTree(' + ', '.join([
            repr(self.nnco),
            hex(self.b),
            repr(self.c),
            repr(self.d),
            repr(self.e),
            repr(self.f),
            repr(self.g),
            repr(self.h)
        ]) + ')'


@dataclass
class FileHeader:
    filename: str
    fo: int
    size: int
    times: tuple[int, int, int]
    ftype: int
    parent: int
    other: bytes
    etype: int
    poop: int
    key: bytes

    def __init__(self, data: bytes) -> None:
        assert len(data) == 512
        t = struct.unpack('<i4QIiI32s140sI288s', data)
        (self.fo, self.size, timea, timeb, timec, self.ftype,
         self.parent, self.poop, self.key, self.other, self.etype,
         fname) = t
        self.times = timea/1e9, timeb/1e9, timec/1e9
        self.filename = fname.decode('ascii').strip('\x00')

    def __repr__(self) -> str:
        return 'FileHeader(' + ', '.join([
            repr(self.filename),
            repr(self.fo),
            repr(self.size),
            repr(self.times),
            repr(self.ftype),
            repr(self.parent),
            repr(self.poop),
            repr(self.etype),
            # repr(self.key.hex()),
            # repr(self.other.hex()),
        ]) + ')'

    def decrypt_key(self, password: bytes) -> bytes:
        cipher = WrongAES(explode_key(password))
        iv = cipher.encrypt_block(b'\xff' * 16)
        blocks = [self.key[:16], self.key[16:32]]
        for i in range(len(blocks)):
            block = blocks[i]
            next_iv = xorpad(block, iv)
            block = cipher.decrypt_block(block)
            block = xorpad(block, iv)
            iv = next_iv
            blocks[i] = block
        decrypted_key = b''.join(blocks)
        return explode_key(decrypted_key + b'\x00')


@dataclass
class FileChunk:
    nfo: int
    i: int
    j: int
    k: int
    l: int
    m: int
    n: int
    o: int
    dchunks: list[int]

    def __init__(self, data: bytes) -> None:
        assert len(data) >= 36
        assert len(data) % 4 == 0
        t = struct.unpack('<iIIIIIII', data[:32])
        self.dchunks = []
        self.nfo, self.i, self.j, self.k, self.l, self.m, self.n, self.o = t
        data = data[32:]
        for i in range(0, len(data), 4):
            fdco, = struct.unpack('<i', data[i:i+4])
            if fdco > 0:
                self.dchunks.append(fdco)

    def __repr__(self) -> str:
        return 'FileChunk(' + ', '.join([
            repr(self.nfo),
            repr(self.i),
            repr(self.j),
            repr(self.k),
            repr(self.l),
            repr(self.m),
            repr(self.n),
            repr(self.o),
            repr(self.dchunks)
        ]) + ')'


@dataclass
class FileDataChunk:
    xor: int
    r: int
    flags: int
    data: bytes
    pad: bytes

    def __init__(self, data: bytes) -> None:
        assert len(data) > 32
        self.data = data[32:]
        self.q, self.xor, self.flags, self.pad = struct.unpack(
            '<iII20s', data[:32])
        assert FileDataChunk.checkxor(self.data) == self.xor

    @staticmethod
    def checkxor(data: bytes) -> int:
        x = 0
        for b in struct.unpack(f'{len(data)//4}I', data):
            x ^= b
        return x

    def __repr__(self) -> str:
        return 'FileDataChunk(' + ', '.join([
            repr(self.q),
            hex(self.xor),
            hex(self.flags)
        ]) + f', {len(self.data)}B)'

    def decrypt(self, key: bytes) -> bytes:
        if not self.flags & 0x100:
            return self.data

        data = bytearray(self.data)
        cipher = WrongAES(key)
        iv = cipher.encrypt_block(b'\xff' * 16)
        for i in range(len(data) // 16):
            block = bytes(data[i*16:i*16+16])
            next_iv = xorpad(block, iv)
            block = cipher.decrypt_block(block)
            block = xorpad(block, iv)
            iv = next_iv
            data[i*16:i*16+16] = block
        return bytes(data)


@dataclass
class Header:
    pad: bytes
    csc: int
    oof: int
    chunk_size: int
    a: int
    b: int
    c: int
    d: int
    e: int
    dto: int
    n_entr: int
    key: bytes

    def __init__(self, data: bytes) -> None:
        assert len(data) == 364

        t = struct.unpack('<8s272s8sIIIIIIIIIII32s', data)
        (magic, self.pad, magic2, self.csc, self.oof, self.chunk_size,
         self.a, self.b, self.c, self.d, self.e,
         self.dto, self.n_entr, self.n_chunks, self.key) = t

        assert magic == b'AAMVHFSS'
        assert magic2 == b'AASFSSGN'
