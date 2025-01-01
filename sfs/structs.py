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
from typing import Any

from sfs.wrongaes import explode_key, sfs_decrypt, checkxor


@dataclass(slots=True, init=False)
class DirectoryTree:
    next_chunk: int
    xor: int
    c: int
    d: int
    e: int
    f: int
    g: int
    h: int
    files: list['FileHeader']

    def __init__(self, data: bytes, rem_entries: int) -> None:
        (self.next_chunk, self.xor, self.c, self.d, self.e, self.f, self.g,
         self.h) = struct.unpack('<i7I', data[:32])
        self.files = []

        leftover = data[32:]
        assert checkxor(leftover) == self.xor

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

    def serialize(self, chunk_size: int) -> bytes:
        data = b''
        for file in self.files:
            data += file.serialize()

        self.xor = checkxor(data)
        hdr = struct.pack('<i7I', self.next_chunk, self.xor, self.c, self.d,
                          self.e, self.f, self.g, self.h)

        data = hdr + data
        assert len(data) <= chunk_size
        data += b'\x00' * (chunk_size - len(data))
        assert len(data) == chunk_size
        return data

    def __repr__(self) -> str:
        return 'DirectoryTree(' + ', '.join([
            repr(self.next_chunk),
            hex(self.xor),
            repr(self.c),
            repr(self.d),
            repr(self.e),
            repr(self.f),
            repr(self.g),
            repr(self.h)
        ]) + ')'


@dataclass(slots=True, init=False)
class FileHeader:
    offset: int
    size: int
    times: tuple[int, int, int]
    ftype: int
    parent: int
    zero: int
    key: bytes
    unknown: bytes
    etype: int
    filename: str

    def __init__(self, data: bytes) -> None:
        assert len(data) == 512
        t = struct.unpack('<i4QIiI32s140sI288s', data)
        (self.offset, self.size, timea, timeb, timec, self.ftype,
         self.parent, self.zero, self.key, self.unknown, self.etype,
         fname) = t
        self.times = timea/1e9, timeb/1e9, timec/1e9
        self.filename = fname.decode('ascii').strip('\x00')
        assert self.zero == 0

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, FileHeader):
            return False
        return (
            self.filename == other.filename and
            self.offset == other.offset and
            self.size == other.size and
            self.times == other.times and
            self.ftype == other.ftype and
            self.parent == other.parent and
            self.unknown == other.unknown and
            self.etype == other.etype and
            self.zero == other.zero and
            self.key == other.key
        )

    def __repr__(self) -> str:
        return 'FileHeader(' + ', '.join([
            repr(self.filename),
            repr(self.offset),
            repr(self.size),
            repr(self.times),
            repr(self.ftype),
            repr(self.parent),
            repr(self.zero),
            repr(self.etype),
            # repr(self.key.hex()),
            # repr(self.unknown.hex()),
        ]) + ')'

    def serialize(self) -> bytes:
        fname = self.filename.encode('ascii')
        fname += b'\x00' * (288 - len(fname))
        timea, timeb, timec = [round(1e9 * i) for i in self.times]
        t = (self.offset, self.size, timea, timeb, timec, self.ftype,
             self.parent, self.zero, self.key, self.unknown, self.etype,
             fname)
        data = struct.pack('<i4QIiI32s140sI288s', *t)
        assert len(data) == 512
        return data

    def decrypt_key(self, password: bytes) -> bytes:
        data = bytearray(self.key)
        sfs_decrypt(data, explode_key(password))
        decrypted_key = bytes(data)
        return explode_key(decrypted_key + b'\x00')


@dataclass(slots=True, init=False)
class FileChunk:
    next_chunk: int
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
        self.dchunks = []
        (self.next_chunk, self.i, self.j, self.k, self.l, self.m, self.n,
         self.o) = struct.unpack('<iIIIIIII', data[:32])
        if self.next_chunk != -1:
            raise NotImplementedError()
        data = data[32:]
        for i in range(0, len(data), 4):
            fdco, = struct.unpack('<i', data[i:i+4])
            if fdco > 0:
                self.dchunks.append(fdco)

    def __repr__(self) -> str:
        return 'FileChunk(' + ', '.join([
            repr(self.next_chunk),
            repr(self.i),
            repr(self.j),
            repr(self.k),
            repr(self.l),
            repr(self.m),
            repr(self.n),
            repr(self.o),
            repr(self.dchunks)
        ]) + ')'


@dataclass(slots=True, init=False)
class FileDataChunk:
    q: int
    xor: int
    flags: int
    unknown: bytes
    data: bytes

    def __init__(self, data: bytes) -> None:
        assert len(data) > 32
        self.data = data[32:]
        self.q, self.xor, self.flags, self.unknown = struct.unpack(
            '<iII20s', data[:32])
        assert checkxor(self.data) == self.xor

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
        sfs_decrypt(data, key)
        return bytes(data)


@dataclass(slots=True, init=False)
class Header:
    unknown: bytes
    csc: int
    oof: int
    chunk_size: int
    a: int
    b: int
    c: int
    d: int
    e: int
    tree_offset: int
    n_entr: int
    n_chunks: int
    key: bytes

    def __init__(self, data: bytes) -> None:
        assert len(data) == 364

        t = struct.unpack('<8s272s8sIIIIIIIIIII32s', data)
        (magic, self.unknown, magic2, self.csc, self.oof, self.chunk_size,
         self.a, self.b, self.c, self.d, self.e, self.tree_offset,
         self.n_entr, self.n_chunks, self.key) = t

        assert magic == b'AAMVHFSS'
        assert magic2 == b'AASFSSGN'
