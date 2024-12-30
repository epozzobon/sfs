from sfs.wrongaes import WrongAES, expand_key_32B, explode_key, spiceup


def test_key_spicing() -> None:
    assert spiceup(b'45654hKL5-GFD1326lvmaQQ') == bytes.fromhex('''
        34 35 36 35 34 68 4B 4C 35 2D 47 46 44 31 33 32
        36 6C 76 6D 61 51 51 80 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 B8 00 00 00 00 00 00 00
    ''')

    assert spiceup(bytes.fromhex('''
        80 07 B2 7D 3D 05 AD C0 F7 3B F2 B6 D5 F9 4D 10
        AB 7B 51 BC E8 10 44 80 BE 2C 2F ED 28 C7 D0 0F
        00
    ''')) == bytes.fromhex('''
        80 07 B2 7D 3D 05 AD C0 F7 3B F2 B6 D5 F9 4D 10
        AB 7B 51 BC E8 10 44 80 BE 2C 2F ED 28 C7 D0 0F
        00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
        00 00 00 00 00 00 00 00 08 01 00 00 00 00 00 00
    ''')


def test_expand_key() -> None:
    assert expand_key_32B(bytes.fromhex('''
        55 D3 17 41 CD D7 D9 50 E8 B0 48 CE F4 C2 14 B9
        94 7C 4E 36 A4 F7 BC 87 A9 FB 30 15 7A 1F 64 C9
    ''')) == bytes.fromhex('''
        55 D3 17 41 CD D7 D9 50 E8 B0 48 CE F4 C2 14 B9
        94 7C 4E 36 A4 F7 BC 87 A9 FB 30 15 7A 1F 64 C9
        94 90 CA 9B 59 47 13 CB B1 F7 5B 05 45 35 4F BC
        BF DF 85 EF CA 61 38 E2 16 24 B5 FA B0 7E 5C 2B
        65 DA 3B 7C 3C 9D 28 B7 8D 6A 73 B2 C8 5F 3C 0E
        9F 4F 52 4A 22 AE D3 49 89 6B E7 B0 92 D0 8F 62
        11 A9 91 33 2D 34 B9 84 A0 5E CA 36 68 01 F6 38
        B2 32 E6 75 67 D2 91 4E 3B 59 01 C5 F5 02 1E 2C
        6E DB E0 D5 43 EF 59 51 E3 B1 93 67 8B B0 65 5F
        04 65 CE E5 5A 35 DC 81 3F 3C CF 20 AF 37 C2 AD
        E4 FE 75 AC A7 11 2C FD 44 A0 BF 9A CF 10 DA C5
        41 BF 43 86 D0 FF 8B 27 7E 83 8C A6 7F C8 49 8A
        2C C5 0B 7E 8B D4 27 83 CF 74 98 19 00 64 42 DC
        22 98 2D DC B3 BC A7 A1 5C 1B A1 7A CC 74 EE 2B
        FE ED FA 35 75 39 DD B6 BA 4D 45 AF BA 29 07 73
    ''')


def test_key_explosion() -> None:
    p = explode_key(b'45654hKL5-GFD1326lvmaQQ')
    assert bytes.fromhex('''
        55 D3 17 41 CD D7 D9 50 E8 B0 48 CE F4 C2 14 B9
        94 7C 4E 36 A4 F7 BC 87 A9 FB 30 15 7A 1F 64 C9
    ''') == p


def test_AES_decrypt() -> None:
    key = bytes.fromhex("""
        55 D3 17 41 CD D7 D9 50 E8 B0 48 CE F4 C2 14 B9
        94 7C 4E 36 A4 F7 BC 87 A9 FB 30 15 7A 1F 64 C9
    """)
    cipher = WrongAES(key)

    ct = bytes.fromhex('B3E379A245892144213F80A9E1223C02')
    pt = cipher.decrypt_block(ct)
    assert pt == bytes.fromhex('f7d9cca08ccaed6cc0ada92e9f4be040')


def test_AES_encrypt() -> None:
    key = bytes.fromhex("""
        55 D3 17 41 CD D7 D9 50 E8 B0 48 CE F4 C2 14 B9
        94 7C 4E 36 A4 F7 BC 87 A9 FB 30 15 7A 1F 64 C9
    """)
    cipher = WrongAES(key)

    pt = bytes.fromhex('ffffffffffffffffffffffffffffffff')
    ct = cipher.encrypt_block(pt)
    assert ct == bytes.fromhex('77de7eddb1cf40ac37965b984ab2ad50')


def test_AES_encrypt_decrypt() -> None:
    key = bytes.fromhex("""
        55 D3 17 41 CD D7 D9 50 E8 B0 48 CE F4 C2 14 B9
        94 7C 4E 36 A4 F7 BC 87 A9 FB 30 15 7A 1F 64 C9
    """)
    cipher = WrongAES(key)

    pt = bytes.fromhex('ffffffffffffffffffffffffffffffff')
    ct = cipher.encrypt_block(pt)
    assert ct == bytes.fromhex('77de7eddb1cf40ac37965b984ab2ad50')
    pt2 = cipher.decrypt_block(ct)
    assert pt2 == pt


if __name__ == '__main__':
    test_expand_key()
    test_AES_decrypt()
    test_AES_encrypt()
    test_key_spicing()
    test_key_explosion()
