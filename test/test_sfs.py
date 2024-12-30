from sfs import SFSContainer
import os.path
import hashlib


def test_sfs_with_encrypted_file() -> None:
    path = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'encrypted_example.sfs')
    HASHES = {
        'small.txt': '0b2b084a372b384bc1db6f537a382dbd',
        'photo.jpg': 'ecae485ada3b52e2bacf171e92877bbe',
        'photo.jpg.bak': 'd41d8cd98f00b204e9800998ecf8427e',
    }
    sfs = SFSContainer(open(path, 'rb'))
    for dt in sfs.get_tree():
        for f in dt.files:
            data = sfs.read_file(f, b'lol')
            d = hashlib.md5(data, usedforsecurity=False).digest()
            assert d.hex() == HASHES[f.filename], data


def test_sfs_with_compressed_file() -> None:
    path = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'compressed_example.sfs')
    HASHES = {
        'small.txt': '0b2b084a372b384bc1db6f537a382dbd',
        'sfsmanager.ini': '2be0a1cab5adcf94dbd4a202ac510986',
        'photo.jpg.bak': 'd41d8cd98f00b204e9800998ecf8427e',
        'photo.jpg': 'd41d8cd98f00b204e9800998ecf8427e',
        'another_file.txt': '9a531acf108c75f2c4085d2fe8a38f78',
        'file.txt': '9a531acf108c75f2c4085d2fe8a38f78',
    }
    sfs = SFSContainer(open(path, 'rb'))
    for dt in sfs.get_tree():
        for f in dt.files:
            data = sfs.read_file(f, b'lol')
            d = hashlib.md5(data, usedforsecurity=False).digest()
            assert d.hex() == HASHES[f.filename], data


def test_sfs_replace_file() -> None:
    pat0 = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'ugly_label.stc')
    pat1 = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'ugly_label_copy.stc')
    pat2 = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'LayoutDef.lyd')
    with open(pat0, 'rb') as src:
        with open(pat1, 'wb') as dst:
            dst.write(src.read())
    with open(pat2, 'rb') as src:
        layout = src.read()
    with open(pat1, 'rb+') as fd:
        sfs = SFSContainer(fd)
        for dt in sfs.get_tree():
            for f in dt.files:
                if f.filename == 'LayoutDef.lyd':
                    sfs.write_file(f, layout, b'45654hKL5-GFD1326lvmaQQ')
    with open(pat1, 'rb') as fd:
        d = hashlib.md5(fd.read(), usedforsecurity=False).digest()
    assert d.hex() == 'cd486e05a9a8a319ad67fd5dd63f15c7'
    os.unlink(pat1)


def test_sfs_from_label() -> None:
    path = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'ugly_label.stc')
    HASHES = {
        'Layout.ini': 'd41d8cd98f00b204e9800998ecf8427e',
        'LayoutDef.lyd': 'd2d878b756be022550e95439bb615a8d',
        'LayoutProps.def': '6658291332cd5ac4cdd4c6d4859d8641',
        'UserSettings.def': 'a9061dbdc676c0f425ee9e4f3bd86bb9',
        'Devices.def': '2ba452b8c0ef3def30fed915e93ec689',
        'History.xml': '0a4b51b1423ee3e6492a387b366eefab',
        'Infos.txt': 'd41d8cd98f00b204e9800998ecf8427e',
        'PreviewImage.png': 'abb57005f3787df42f3201f0fcade585'
    }
    sfs = SFSContainer(open(path, 'rb'))
    for dt in sfs.get_tree():
        for f in dt.files:
            data = sfs.read_file(f, b'45654hKL5-GFD1326lvmaQQ')
            d = hashlib.md5(data, usedforsecurity=False).digest()
            assert d.hex() == HASHES[f.filename]


def test_sfs_extract() -> None:
    path = os.path.join(*os.path.split(__file__)[:-1], 'assets',
                        'ugly_label.stc')
    sfs = SFSContainer(open(path, 'rb'))
    print(sfs._hdr)
    for dt in sfs.get_tree():
        print(f'    {dt}')
        for f in dt.files:
            print(f'        {f}')
            if f.fo != -1:
                fc, dcs = sfs.get_file(f)
                print(f'        {fc}')
                for dc in dcs:
                    print(f'            {dc}')
            data = sfs.read_file(f, b'45654hKL5-GFD1326lvmaQQ')
            with open('outputs/' + f.filename, 'wb') as fd:
                fd.write(data)
