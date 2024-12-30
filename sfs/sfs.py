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

from io import BufferedReader
import sys
from typing import Iterator
from sfs.structs import (Header, DirectoryTree, FileChunk, FileHeader,
                         FileDataChunk)
from sfs.utils import make_chunks, aacs_inflate, aacs_deflate


class SFSContainer:
    def __init__(self, fd: BufferedReader) -> None:
        self.fd = fd
        hdrbytes = fd.read(364)
        self._hdr = Header(hdrbytes)
        if self._hdr.chunk_size != 4096:
            raise NotImplementedError()

    def _get_chunk(self, c: int) -> bytes:
        if c <= 0:
            raise ValueError(f'Requested invalid chunk {c}')
        pos = c * self._hdr.chunk_size + 280
        self.fd.seek(pos)
        data = self.fd.read(self._hdr.chunk_size)
        if len(data) == 0:
            raise ValueError(f'Requested invalid chunk {c} (out of file)')
        assert len(data) == self._hdr.chunk_size
        return data

    def _put_chunk(self, c: int, buf: bytes) -> None:
        if c <= 0:
            raise ValueError(f'Requested invalid chunk {c}')
        if len(buf) != self._hdr.chunk_size:
            xp = self._hdr.chunk_size
            raise ValueError(f'Chunk has size {len(buf)}, expected {xp}')
        pos = c * self._hdr.chunk_size + 280
        self.fd.seek(pos)
        self.fd.write(buf)

    def get_tree(self) -> Iterator[DirectoryTree]:
        nco = self._hdr.dto
        rem_entries = self._hdr.n_entr
        while 1:
            chunk = self._get_chunk(nco)
            dt = DirectoryTree(chunk, rem_entries)
            rem_entries -= len(dt.files)
            assert rem_entries >= 0
            yield dt
            if rem_entries == 0 or nco == dt.nnco or dt.nnco <= 0:
                break
            nco = dt.nnco

    def write_file(self, file: FileHeader, data: bytes,
                   password: None | bytes = None,
                   compression_level: None | int = 1) -> None:

        key = None if password is None else file.decrypt_key(password)

        # deflate if needed
        if compression_level is not None:
            data = aacs_deflate(data, compression_level)

        chunks = make_chunks(data, self._hdr.chunk_size, key)

        file_chunk = FileChunk(self._get_chunk(file.fo))
        if len(chunks) > len(file_chunk.dchunks):
            # TODO: allocate new chunks
            raise NotImplementedError()

        if len(chunks) < len(file_chunk.dchunks):
            unused_chunks = file_chunk.dchunks[len(chunks):]
            file_chunk.dchunks = file_chunk.dchunks[:len(chunks)]
            # TODO: recycle unused chunks
            print(f'(SFS) WARNING: orphaned chunks: {unused_chunks}',
                  file=sys.stderr)

        for i, chunk in enumerate(chunks):
            idx = file_chunk.dchunks[i]
            self._put_chunk(idx, chunk)

    def read_file(self, file: FileHeader,
                  password: None | bytes = None) -> bytes:
        if file.fo == -1:
            return b''
        _, chunks = self.get_file(file)

        if password is not None:
            key = file.decrypt_key(password)
            data = b''.join(chunk.decrypt(key) for chunk in chunks)
        else:
            data = b''.join(chunk.data for chunk in chunks)

        if data[:4] == b'AACS':
            data = aacs_inflate(data)
        else:
            assert len(data) >= file.size
            assert all(b == 0 for b in data[file.size:]), 'Invalid padding'
            data = data[:file.size]

        return data

    def get_file(self, file: FileHeader
                 ) -> tuple[FileChunk, Iterator[FileDataChunk]]:
        assert file.fo != -1

        chunk = self._get_chunk(file.fo)
        fc = FileChunk(chunk)

        def iterator() -> Iterator[FileDataChunk]:
            for fdco in fc.dchunks:
                chunk = self._get_chunk(fdco)
                yield FileDataChunk(chunk)
        return fc, iterator()
