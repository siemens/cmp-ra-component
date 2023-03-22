REM This is a thin wrapper around gpg-wrap.ps1, it is necessary because it seems that on Windows Maven cannot execute
REM a powershell script directly, as a standalone executable. What this file does is simply pass its arguments.
REM The Github Runner executes it from within the checked out project's top-level directory, so the relative path used
REM below is acceptable.

REM REQUIREMENT
REM - This file must be copied to a location that is accessible in the system's PATH environment variable, such that
REM   Maven can call it

powershell.exe scripts\gpg-wrap.ps1 %*