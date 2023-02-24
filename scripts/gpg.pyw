import sys
import os
import subprocess

if sys.argv[-1] == '--version':
    response = '''gpg (GnuPG) 2.4.0
                  libgcrypt 1.10.1
                  Copyright (C) 2021 g10 Code GmbH
                  License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
                  This is free software: you are free to change and redistribute it.
                  There is NO WARRANTY, to the extent permitted by law.

                  Home: C:\\Users\\z004mkfh\\AppData\\Roaming\\gnupg
                  Supported algorithms:
                  Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
                  Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
                          CAMELLIA128, CAMELLIA192, CAMELLIA256
                  Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
                  Compression: Uncompressed, ZIP, ZLIB, BZIP2'''
    print(response)
    sys.exit(0)

if not os.environ['SignSettingsPath']:
    print("You must set the SignSettingsPath environment variable first")
    sys.exit(1)

path_accummulator = 'path_accummulator.tmp'
file_to_sign = sys.argv[-1]


# breakpoint()
# file = open(path_accummulator, 'a+')
try:
    paths = open(path_accummulator, 'r').readlines()
except FileNotFoundError:
    paths = [file_to_sign]
finally:
    file = open(path_accummulator, 'a+')
    file.write(f'{file_to_sign}\n')
    file.close()



if len(paths) == 3:
    paths.append(file_to_sign)
    paths = [item.strip() for item in paths]
    command = f"powershell.exe scripts\sign-gui-multi.ps1 -filesToSign {', '.join(paths)} -settingsFile {os.environ['SignSettingsPath']} -signaturePath target"

    print(f'Will run: {command}')
    subprocess.call(command)
    os.unlink(path_accummulator)
