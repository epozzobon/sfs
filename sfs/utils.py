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
import zlib

from sfs.wrongaes import WrongAES, xorpad, crc16
from sfs.structs import FileDataChunk


def aacs_inflate(data: bytes) -> bytes:
    assert data[:4] == b'AACS'
    compression_level, = struct.unpack('<I', data[20:24])

    pieces = struct.unpack('<IIII', data[0x80:0x90])
    avail_in, inflated_size, crc, p3 = pieces
    if inflated_size == 0:
        return b''
    deflated = data[0x90:0x90 + avail_in]
    assert len(deflated) == avail_in
    assert avail_in == p3 - 16
    assert all(b == 0 for b in data[0x90 + avail_in:])

    if compression_level == 0:
        data = deflated
    if compression_level in [1, 2]:
        data = zlib.decompress(deflated)
    else:
        raise ValueError(f"Unknown compression level {compression_level}")

    assert len(data) == inflated_size
    assert crc == crc16(data)
    return data


def aacs_deflate(data: bytes, compression_level: int) -> bytes:
    hdr = struct.pack('<4sIIIII', b'AACS', 0x80000, 0, 1,
                      0x40000000, compression_level)
    hdr += b'\x00' * 0x68
    if compression_level == 1:
        deflated = zlib.compress(data, level=compression_level)
    else:
        # TODO: allow setting compression level
        raise NotImplementedError()

    avail_in = len(deflated)
    inflated_size = len(data)
    crc = crc16(data)
    sizes = struct.pack('<IIII', avail_in, inflated_size,
                        crc, avail_in + 16)
    data = hdr + sizes + deflated
    return data


def split_into_chunks(data: bytes, chunk_data_size: int) -> list[bytes]:
    chunks: list[bytes] = []
    for off in range(0, len(data), chunk_data_size):
        chunk_data = data[off:off+chunk_data_size]
        assert len(chunk_data) <= chunk_data_size
        if len(chunk_data) < chunk_data_size:
            chunk_data += b'\x00' * (chunk_data_size - len(chunk_data))
        assert len(chunk_data) == chunk_data_size
        chunks.append(chunk_data)
    return chunks


def make_chunks(data: bytes, chunk_size: int,
                key: None | bytes = None) -> list[bytes]:
    # split data into chunks, leaving 32 bytes for header
    chunk_data_size = chunk_size - 32
    chunks = split_into_chunks(data, chunk_data_size)

    # put header on each chunk
    for i, chunk_data in enumerate(chunks):
        if key is not None:
            datab = bytearray(chunk_data)
            cipher = WrongAES(key)
            iv = cipher.encrypt_block(b"\xff" * 16)
            for j in range(len(datab) // 16):
                pt = bytes(datab[j*16:j*16 + 16])
                ct = cipher.encrypt_block(xorpad(pt, iv))
                iv = xorpad(ct, iv)
                datab[j*16:j*16 + 16] = ct
            chunk_data = bytes(datab)

        xor = FileDataChunk.checkxor(chunk_data)
        flags = 6 if key is None else 0x106
        chunk_hdr = struct.pack("<iII20s", -1, xor, flags, b"\x00" * 20)
        chunks[i] = chunk_hdr + chunk_data
    return chunks
