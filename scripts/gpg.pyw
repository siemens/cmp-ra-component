import sys

open('dump.txt', 'a+').write('\n'+str(sys.argv))

if sys.argv[-1] == '--version':
    response = '''gpg (GnuPG) 2.4.0
                  libgcrypt 1.10.1
                  Copyright (C) 2021 g10 Code GmbH
                  License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
                  This is free software: you are free to change and redistribute it.
                  There is NO WARRANTY, to the extent permitted by law.

                  Home: C:\Users\z004mkfh\AppData\Roaming\gnupg
                  Supported algorithms:
                  Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
                  Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
                          CAMELLIA128, CAMELLIA192, CAMELLIA256
                  Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
                  Compression: Uncompressed, ZIP, ZLIB, BZIP2'''
    print(response)