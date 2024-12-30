# This file was copied from https://github.com/boppreh/aes

"""
MIT License

Copyright (c) 2024 BoppreH

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

This is an exercise in secure symmetric-key encryption, implemented in pure
Python (no external libraries needed).

Original AES-128 implementation by Bo Zhu (http://about.bozhu.me) at
https://github.com/bozhu/AES-Python . PKCS#7 padding, CBC mode, PKBDF2, HMAC,
byte array and string support added by me at https://github.com/boppreh/aes.
Other block modes contributed by @righthandabacus.


Although this is an exercise, the `encrypt` and `decrypt` functions should
provide reasonable security to encrypted messages.
"""

from typing import Iterable


s_box = bytes.fromhex('''
    637C777BF26B6FC53001672BFED7AB76CA82C97DFA5947F0ADD4A2AF9CA472C0
    B7FD9326363FF7CC34A5E5F171D8311504C723C31896059A071280E2EB27B275
    09832C1A1B6E5AA0523BD6B329E32F8453D100ED20FCB15B6ACBBE394A4C58CF
    D0EFAAFB434D338545F9027F503C9FA851A3408F929D38F5BCB6DA2110FFF3D2
    CD0C13EC5F974417C4A77E3D645D197360814FDC222A908846EEB814DE5E0BDB
    E0323A0A4906245CC2D3AC629195E479E7C8376D8DD54EA96C56F4EA657AAE08
    BA78252E1CA6B4C6E8DD741F4BBD8B8A703EB5664803F60E613557B986C11D9E
    E1F8981169D98E949B1E87E9CE5528DF8CA1890DBFE6426841992D0FB054BB16
''')

inv_s_box = bytes.fromhex('''
    52096AD53036A538BF40A39E81F3D7FB7CE339829B2FFF87348E4344C4DEE9CB
    547B9432A6C2233DEE4C950B42FAC34E082EA16628D924B2765BA2496D8BD125
    72F8F66486689816D4A45CCC5D65B6926C704850FDEDB9DA5E154657A78D9D84
    90D8AB008CBCD30AF7E45805B8B34506D02C1E8FCA3F0F02C1AFBD0301138A6B
    3A9111414F67DCEA97F2CFCEF0B4E67396AC7422E7AD3585E2F937E81C75DF6E
    47F11A711D29C5896FB7620EAA18BE1BFC563E4BC6D279209ADBC0FE78CD5AF4
    1FDDA8338807C731B11210592780EC5F60517FA919B54A0D2DE57A9F93C99CEF
    A0E03B4DAE2AF5B0C8EBBB3C83539961172B047EBA77D626E169146355210C7D
''')


def sub_bytes(s: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            s[i][j] = s_box[s[i][j]]


def inv_sub_bytes(s: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            s[i][j] = inv_s_box[s[i][j]]


def shift_rows(s: list[list[int]]) -> None:
    s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]


def inv_shift_rows(s: list[list[int]]) -> None:
    s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
    s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
    s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]


def add_round_key(s: list[list[int]], k: list[list[int]]) -> None:
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]


# learned from https://web.archive.org/web/20100626212235/
# http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = bytes.fromhex('''
    00020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3e
    40424446484a4c4e50525456585a5c5e60626466686a6c6e70727476787a7c7e
    80828486888a8c8e90929496989a9c9ea0a2a4a6a8aaacaeb0b2b4b6b8babcbe
    c0c2c4c6c8caccced0d2d4d6d8dadcdee0e2e4e6e8eaeceef0f2f4f6f8fafcfe
    1b191f1d131117150b090f0d030107053b393f3d333137352b292f2d23212725
    5b595f5d535157554b494f4d434147457b797f7d737177756b696f6d63616765
    9b999f9d939197958b898f8d83818785bbb9bfbdb3b1b7b5aba9afada3a1a7a5
    dbd9dfddd3d1d7d5cbc9cfcdc3c1c7c5fbf9fffdf3f1f7f5ebe9efede3e1e7e5
''')


def mix_single_column(a: list[int]) -> None:
    # see Sec 4.1.2 in The Design of Rijndael
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime[a[0] ^ a[1]]
    a[1] ^= t ^ xtime[a[1] ^ a[2]]
    a[2] ^= t ^ xtime[a[2] ^ a[3]]
    a[3] ^= t ^ xtime[a[3] ^ u]


def mix_columns(s: list[list[int]]) -> None:
    for i in range(4):
        mix_single_column(s[i])


def inv_mix_columns(s: list[list[int]]) -> None:
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime[xtime[s[i][0] ^ s[i][2]]]
        v = xtime[xtime[s[i][1] ^ s[i][3]]]
        s[i][0] ^= u
        s[i][1] ^= v
        s[i][2] ^= u
        s[i][3] ^= v

    mix_columns(s)


r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def bytes2matrix(text: bytes) -> list[list[int]]:
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]


def matrix2bytes(matrix: list[list[int]]) -> bytes:
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes(sum(matrix, []))


def xor_bytes(a: Iterable[int], b: Iterable[int]) -> bytes:
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i ^ j for i, j in zip(a, b))


class AES:
    """
    Class for AES-128 encryption with CBC mode and PKCS#7.

    This is a raw implementation of AES, without key stretching or IV
    management. Unless you need that, please use `encrypt` and `decrypt`.
    """
    rounds_by_key_size = {16: 10, 24: 12, 32: 14}

    def __init__(self, master_key: bytes) -> None:
        """
        Initializes the object with a given key.
        """
        assert len(master_key) in AES.rounds_by_key_size
        self.n_rounds = AES.rounds_by_key_size[len(master_key)]
        self._key_matrices = self._expand_key(master_key)

    def _expand_key(self, master_key: bytes) -> list[list[list[int]]]:
        """
        Expands and returns a list of key matrices for the given master_key.
        """
        # Initialize round keys with raw key material.
        key_columns = bytes2matrix(master_key)
        iteration_size = len(master_key) // 4

        i = 1
        while len(key_columns) < (self.n_rounds + 1) * 4:
            # Copy previous word.
            word = list(key_columns[-1])

            # Perform schedule_core once every "row".
            if len(key_columns) % iteration_size == 0:
                # Circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [s_box[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of
                # R-CON are 0.
                word[0] ^= r_con[i]
                i += 1
            elif len(master_key) == 32 and len(
                    key_columns) % iteration_size == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [s_box[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = list(xor_bytes(word, key_columns[-iteration_size]))
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i:4*(i+1)]
                for i in range(len(key_columns) // 4)]

    def encrypt_block(self, plaintext: bytes) -> bytes:
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 16

        plain_state = bytes2matrix(plaintext)

        add_round_key(plain_state, self._key_matrices[0])

        for i in range(1, self.n_rounds):
            sub_bytes(plain_state)
            shift_rows(plain_state)
            mix_columns(plain_state)
            add_round_key(plain_state, self._key_matrices[i])

        sub_bytes(plain_state)
        shift_rows(plain_state)
        add_round_key(plain_state, self._key_matrices[-1])

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 16

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self._key_matrices[-1])
        inv_shift_rows(cipher_state)
        inv_sub_bytes(cipher_state)

        for i in range(self.n_rounds - 1, 0, -1):
            add_round_key(cipher_state, self._key_matrices[i])
            inv_mix_columns(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_bytes(cipher_state)

        add_round_key(cipher_state, self._key_matrices[0])

        return matrix2bytes(cipher_state)
