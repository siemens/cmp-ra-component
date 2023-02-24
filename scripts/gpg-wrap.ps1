# This is a simple script that partially mimics the CLI of GPG, so it can be invoked by
# Maven's signing logic.
# 1. Place this script in a directory featured in the system's PATH, such that it can be
#    invoked at will.
# 2. To make it executable (akin to chmod +x on *nix environments), import the following
#    into your Windows Registry
#    ------------------ save this as a .reg file (remove the # comments) ---------------
# Windows Registry Editor Version 5.00
#
#
#
#[HKEY_CURRENT_USER\Software\Classes\Microsoft.PowerShellScript.1\Shell]
#
#@="0"


if ($args.Contains('--version')) {
    Write-Output "gpg (GnuPG) 2.4.0
libgcrypt 1.10.1
Copyright (C) 2021 g10 Code GmbH
License GNU GPL-3.0-or-later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Home: C:\\Users\\xxxxxx\\AppData\\Roaming\\gnupg
Supported algorithms:
Pubkey: RSA, ELG, DSA, ECDH, ECDSA, EDDSA
Cipher: IDEA, 3DES, CAST5, BLOWFISH, AES, AES192, AES256, TWOFISH,
      CAMELLIA128, CAMELLIA192, CAMELLIA256
Hash: SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224
Compression: Uncompressed, ZIP, ZLIB, BZIP2"
    return
}

#$raw = 'gpg-wrap --armor --detach-sign --output C:\\Users\\z004mkfh\\soft\\github-runner\\_work\\cmp-ra-component\\cmp-ra-component\\target\\CmpRaComponent-2.2.3-javadoc.jar.asc C:\\Users\\z004mkfh\\soft\\github-runner\\_work\\cmp-ra-component\\cmp-ra-component\\target\\CmpRaComponent-2.2.3-javadoc.jar'
$fileToSign = $args[-1]

if ($null -eq $env:SignClientInput) {
    $env:SignClientInput = $fileToSign
} else {
    $env:SignClientInput = "$env:SignClientInput;$fileToSign"
}

if (([regex]::Matches($env:SignClientInput, ";" )).count -eq 3) {
    Write-Output "Time to sign these 4 files: $env:SignClientInput"

    if (-not [Environment]::GetEnvironmentVariable('SignSettingsPath')) {throw "You must set the SignSettingsPath environment variable first"}

    $accumulatedPaths = $($env:SignClientInput).Split(';')
    Remove-Item Env:\SignClientInput

    Write-Output "Will run: .\scripts\sign-gui-multi.ps1 -filesToSign $accumulatedPaths -settingsFile $env:SignSettingsPath -signaturePath target"
    .\scripts\sign-gui-multi.ps1 -filesToSign $accumulatedPaths -settingsFile $env:SignSettingsPath -signaturePath target
}