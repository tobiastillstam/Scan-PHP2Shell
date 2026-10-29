# Scan-PHP2Shell - project context for Claude Code

Single read-only PowerShell script that finds PHP installs on a Windows host
and reports whether they are affected by PHP2Shell (CVE-2026-109618,
CVE-2026-109619). Meant to run on many Windows servers (by hand, RMM or
scheduled task) and be collected via exit code and CSV.

Owner: Tobias Tillstam / Tillnet. License: MIT.

## Fixed releases

Upstream fix released 2026-10-21:

| Branch | Fixed in |
| --- | --- |
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | no upstream fix (end of life) |

The table lives in the script; keep README.md in sync when it changes.

## Coding conventions (house template)

Scripts follow the house PowerShell template (kept outside this repo).

- `#Requires -Version 5.1` and `#Requires -RunAsAdministrator`.
- NOTES holds Author, Webpage, GitHub, Company, License, Version (semver),
  Date Created, Last Modified, Change Log, Operational notes. Bump Version,
  Last Modified and the Change Log on every change, plus CHANGELOG.md and
  the README version badge.
- Every parameter: `[Parameter(Mandatory = $false)]` + one-line comment.
- Flat try/catch/finally, `Write-Verbose` bookends, section banners.
- Console output ASCII only (Write-Log folds accents, replaces the rest
  with '?'); no colours. CSV files UTF-8 with BOM.
- Keep PS 5.1 compatibility: no ternary, no `??`.
- `-and` / `-or` have equal precedence: always parenthesize.

## Design decisions

- **Read-only.** Nothing is gated by ShouldProcess because nothing on the
  host changes; transcript/CSV/LogRoot writes pass `-WhatIf:$false`.
  `-WhatIf` therefore runs a normal scan.
- **Never runs a found binary.** Versions come from the file's version
  resource only, never from `php.exe -v` / `php.exe -r`: the scan runs as
  admin, so a planted `php.exe` would execute with admin rights.
- **Exit codes** 0 unaffected / 1 needs patch / 2 inconclusive / 3 script
  error. 1 wins over 2. The catch block logs, writes the error record
  (`Write-Error -ErrorAction Continue`) and sets 3 instead of rethrowing:
  deliberate deviation from the template's bare `throw`, because a rethrow
  under `-File` gives exit code 1, which reads as NEEDS PATCH.
- **Files searched**: php.exe, php-cgi.exe, php-win.exe, php5/7/8(.dll),
  php5/7/8ts.dll. Enumeration uses the `php*` pattern, then an exact name
  set. Grouped per folder = one install; the lowest identified version
  decides (catches half-finished upgrades), and a note lists mixed versions.
- **PHP identification**: CompanyName `The PHP Group` or ProductName `PHP`
  (verified on the official 8.4.27 NTS x64 build: php.exe, php-cgi.exe,
  php-win.exe, php8.dll, phpdbg.exe all carry both). Anything else, e.g. a
  Chocolatey shim, is WARN with company/product/version in the note.
- **Classification**: branch in the fixed table -> UNAFFECTED / NEEDS
  PATCH; 8.6+ or 9+ -> WARN (not covered); everything else identified
  (8.1, 8.0, 7.x, 5.x) -> NEEDS PATCH with EndOfLife = True. Compare per
  branch, never against one "latest" version (that would flag patched
  8.2-8.4 as NEEDS PATCH).
- **Walk**: iterative stack over `\\?\` paths (long paths), reparse points
  not followed (junction loops), unreadable folders recorded with reason.
- **System excludes** per scanned drive root (`$SystemExcludes`): System
  Volume Information, $Recycle.Bin, Recovery, plus Windows / ProgramData /
  Program Files folders that stay denied to administrators. Without these
  every elevated run would be inconclusive (exit 2). Only generic Windows
  folders go in the list; host- or vendor-specific ones are for
  `-ExcludePath`.
- **Cloud placeholders** (Offline / RecallOnOpen / RecallOnDataAccess
  attributes) are not read; reading would hydrate them. WARN.
- **References (1.1.0)**, read before the walk unless `-SkipReferences`:
  IIS applicationHost.config (fullPath / scriptProcessor, comments
  stripped, redirection.config followed), Apache httpd.conf following
  Include in order with Define expansion (not "all *.conf", which would
  pick up files that are never loaded), services incl. NSSM, machine PATH,
  Uninstall entries (both registry views + loaded HKU). Credit for the idea
  is in README.md.
- **Reference rules**: referenced binaries are read even outside the walk
  (-Path, excludes, shares, junctions); references also apply with -Path.
  A missing reference is WARN: own row, or UNAFFECTED -> WARN when the
  folder holds PHP but the exact file is missing. PHP uninstall entry with
  no PHP below / no folder -> WARN; stack entry only when its folder is
  gone. PHPIniDir and PATH annotate only. Undefined Apache variable ->
  WARN. Unreadable config source -> -skipped.csv (exit 2).
- **32-bit host process** (RMM agents): IIS via Sysnative, registry via
  OpenBaseKey Registry64 + Registry32, httpd paths via Win32_Process.

## Test harness

`Tests\` is git-ignored and kept local; it is not part of the published
repo. Dependency-free (no Pester).

- `Tests\Invoke-ScannerTest.ps1 -Exe powershell.exe|pwsh.exe
  [-RealPhpDir <extracted official build>]` runs the script as a child
  process with `-File`. It compiles stub binaries with chosen version
  resources and strips `#Requires -RunAsAdministrator` from a copy (the
  original keeps it). 79 assertions (80 with `-RealPhpDir`): every status
  branch, shim / no-version / garbage file, php-cgi-only, DLL-only,
  upper-case name, mixed versions, deep and > 260-char paths, junction
  loop, denied folder (exit 2 + skipped CSV), `-ExcludePath` (exit 0),
  missing path (exit 3), `-WhatIf`, `-PassThru`, ASCII console, a live
  reference run, `-SkipReferences`.
- `Tests\Invoke-ReferenceTest.ps1`: 31 unit checks for IIS parsing (comments,
  env vars, handler arguments), Apache Include order / Define /
  ServerRoot-relative / unused file / undefined variable, and the merge
  rules on stub installs.
- Existing scenarios pass `-SkipReferences` so the test machine's own
  config cannot change them.
- Run under PS 5.1, PS 7 and 32-bit PS 5.1 (SysWOW64), non-elevated and
  once elevated. The deny-ACE scenario also holds when elevated.

## Backlog

- Report php.ini mitigations per install.
- Site web.config handler mappings, IIS Express, per-user PATH, Apache
  services with -f / -d (ConfigArgs in the service registry key).
- Load the fixed-release table from a file so a new advisory does not need
  a script release.
