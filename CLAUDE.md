# Scan-PHP2Shell - project context for Claude Code

Single read-only PowerShell script that finds PHP installs on a Windows host
and reports whether they are affected by PHP2Shell (CVE-2026-109618,
CVE-2026-109619), fixed upstream 2026-10-21 in 8.5.12, 8.4.27, 8.3.36 and
8.2.35. Meant to run on many Windows servers (by hand, RMM or scheduled
task) and be collected via exit code and CSV.

Owner: Tobias Tillstam / Tillnet. License: MIT.

Origin: rewrite of a quick unreleased scanner (Downloads\Scan-PHP2Shell.ps1)
that only looked for php.exe, misread shims as old PHP, always exited 0 and
had display-only output.

## Coding conventions (house template)

Template: `C:\Users\Tobias\.claude\script_templates\script_template.ps1`
(see the global CLAUDE.md).

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
  (8.1, 8.0, 7.x, 5.x) -> NEEDS PATCH with EndOfLife = True.
- **Walk**: iterative stack over `\\?\` paths (long paths), reparse points
  not followed (junction loops), unreadable folders recorded with reason.
- **System excludes** per scanned drive root (`$SystemExcludes`): System
  Volume Information, $Recycle.Bin, Recovery, plus Windows / ProgramData /
  Defender for Endpoint folders seen denied in the elevated run below.
  Without these every elevated run would be inconclusive (exit 2). Only
  generic Windows folders go in the list; host-specific ones (e.g.
  Windows\Installer\Razer) are for `-ExcludePath`.
- **Cloud placeholders** (Offline / RecallOnOpen / RecallOnDataAccess
  attributes) are not read; reading would hydrate them. WARN.
- **References (1.1.0)**, read before the walk unless `-SkipReferences`:
  IIS applicationHost.config (fullPath / scriptProcessor, comments
  stripped, redirection.config followed), Apache httpd.conf following
  Include in order with Define expansion (not "all *.conf", which would
  pick up files that are never loaded), services incl. NSSM, machine PATH,
  Uninstall entries (both registry views + loaded HKU). Idea taken from
  fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619 (Code Ape, MIT),
  reviewed 2026-10-22. That tool runs `php.exe -r` to get the version (a
  planted binary would run as admin) and compares against one latest
  version (false NEEDS PATCH on patched 8.2-8.4); deliberately not copied.
- **Reference rules** (decided with Tobias 2026-10-22): referenced binaries
  are read even outside the walk (-Path, excludes, shares, junctions);
  references also apply with -Path. A missing reference is WARN: own row,
  or UNAFFECTED -> WARN when the folder holds PHP but the exact file is
  missing. PHP uninstall entry with no PHP below / no folder -> WARN; stack
  entry only when its folder is gone. PHPIniDir and PATH annotate only.
  Undefined Apache variable -> WARN. Unreadable config source ->
  -skipped.csv (exit 2).
- **32-bit host process** (RMM agents): IIS via Sysnative, registry via
  OpenBaseKey Registry64 + Registry32, httpd paths via Win32_Process.

## Validated (2026-10-21, Windows 11 ARM64, non-elevated copy)

Harness: `Tests\Invoke-ScannerTest.ps1 -Exe powershell.exe|pwsh.exe
[-RealPhpDir <extracted official build>]` (git-ignored, local only). It
compiles stub binaries with chosen version resources, strips
`#Requires -RunAsAdministrator` from a copy, and checks 44 assertions:
every status branch, shim / no-version / garbage file, php-cgi-only,
DLL-only, upper-case name, mixed versions, deep and > 260-char paths,
junction loop, denied folder (exit 2 + skipped CSV), `-ExcludePath`
(exit 0), missing path (exit 3), `-WhatIf`, `-PassThru`, ASCII console.
Passed on PS 5.1 and PS 7, including the real PHP 8.4.27 build
(UNAFFECTED). Full C:\ scan non-elevated: 125,789 folders in 38 s, 190
folders denied (mostly ProgramData\Microsoft, Windows\System32), no false
hits outside the fixtures.

## Validated elevated (2026-10-22, same Windows 11 ARM64 host, v1.0.1)

Harness passed all 44 assertions elevated on PS 5.1 and PS 7 (real PHP
build not re-run; it was no longer on disk). The deny ACE in the locked
scenario still applies when elevated. Full scan with the real script:
130,875 folders in 38 s, no hits outside test fixtures, 18 folders
denied before the exclude update: Defender for Endpoint (11), WebThreatDefSvc,
config\BFS, LocalService Ngc, ProgramData SystemData /
CapabilityAccessManager, Windows\Installer\Razer (host-specific, not
excluded) and one leftover test fixture.

## Validated 1.1.0 (2026-10-22, same host, non-elevated)

Harness now 79 assertions (80 with -RealPhpDir): the 43 above, 4 for a live reference run on this host
(no IIS / Apache / PHP programs here, so "References to PHP: none"),
-SkipReferences, and `Tests\Invoke-ReferenceTest.ps1` (31 unit checks:
IIS parsing incl. comments / env vars / handler arguments, Apache Include
order / Define / ServerRoot-relative / unused file / undefined variable,
and the merge rules on stub installs). Existing scenarios pass
-SkipReferences so the host's own config cannot change them. Passed on
PS 5.1, PS 7 and 32-bit PS 5.1 (SysWOW64; Sysnative path exercised, no IIS
present).

## Open (needs a real elevated session on a server)

1. Run elevated on a server and read the `-skipped.csv`. Server roles may
   lock further folders (e.g. NetworkService Ngc); add generic ones to
   `$SystemExcludes`.
2. A server with a real PHP install (IIS FastCGI, XAMPP / Laragon if any).
   For 1.1.0 also check: ReferencedBy filled from the real
   applicationHost.config / httpd.conf, no false WARN from stale Uninstall
   entries or Apache conditionals, run time of the reference pass.
3. Run through the RMM tool and check the exit code arrives (and, if the
   agent is 32-bit, that IIS references still show up).

## Backlog

- Report php.ini mitigations per install.
- Site web.config handler mappings, IIS Express, per-user PATH, Apache
  services with -f / -d (ConfigArgs in the service registry key).
- Load the fixed-release table from a file so a new advisory does not need
  a script release.
