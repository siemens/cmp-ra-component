# This is a simple script that partially mimics the CLI of GPG, so it can be invoked by
# Maven's signing logic. Note that on Windows Powershell scripts cannot be called directly by Maven,
# hence `gpg-wrap.cmd` is needed.

if ($args.Contains('--version')) {
    Write-Output "gpg (GnuPG) 2.4.0
libgcrypt 1.10.1"
    return
}

$fileToSign = $args[-1]

# Append the command line argument to the end of a file (adding a new line, if necessary); the argument will be the
# path to the file that Maven wants to sign
Add-Content path_accumulator_ps.tmp $fileToSign

# Load all the file paths accumulated so far
$accumulatedPaths = Get-Content path_accumulator_ps.tmp

# Check if we've accumulated 4 files (the jar, javadoc, source and pom). If yes, then it is time to sign them all,
# if not, we do nothing and wait for this program to be invoked again with new input data.
if ($accumulatedPaths.Count -eq 6) {
    Write-Output "Time to sign these 6 files: $accumulatedPaths"

    if (-not [Environment]::GetEnvironmentVariable('SignSettingsPath')) {throw "You must set the SignSettingsPath environment variable first"}

    # now that we have all the info we need, remove the temporary file such that the next time we run Maven's build,
    # we start from a clean slate
    Remove-Item path_accumulator_ps.tmp

    Write-Output "Will run: .\scripts\sign-gui.ps1 -filesToSign $accumulatedPaths -settingsFile $env:SignSettingsPath -signaturePath target"
    .\scripts\sign-gui.ps1 -filesToSign $accumulatedPaths -settingsFile $env:SignSettingsPath -signaturePath target
}
