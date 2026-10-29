# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-22

### Added
- **Reference check** - IIS `applicationHost.config` (FastCGI and handler
  mappings, shared configuration followed), Apache `httpd.conf` with its
  includes and `Define` variables, services (direct and NSSM), the machine
  PATH and installed-programs entries for PHP or a PHP stack. Referenced
  binaries are classified even outside the walk (`-Path`, `-ExcludePath`,
  shares, junctions). Idea from
  [Check-PhpVersion](https://github.com/fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619)
  by Code Ape (MIT); no found binary is run.
- **CSV column `ReferencedBy`** (before `Note`).
- **`-SkipReferences`** - disk walk only.

### Changed
- A reference that leads to no PHP is `WARN`: a missing referenced file or
  folder, a PHP uninstall entry with no PHP under it, or an Apache path with
  an undefined variable. A host with such a reference now exits `2` instead
  of `0`.
- A 32-bit PowerShell reads IIS through `Sysnative` and the registry
  through both views.
- `-skipped.csv` can also list config sources that could not be read.

### Tested
- Test harness (79 assertions, plus 31 reference parser and merge checks)
  passed on PowerShell 5.1, PowerShell 7 and 32-bit PowerShell 5.1.

## [1.0.1] - 2026-10-22

### Changed
- **System excludes** extended after an elevated full-drive run: Defender
  for Endpoint folders (`ProgramData` and `Program Files`),
  `Windows\System32\WebThreatDefSvc`, `Windows\System32\config\BFS`,
  LocalService `Ngc`, `ProgramData\Microsoft\Windows\SystemData` and
  `CapabilityAccessManager`. These stay denied to administrators and would
  otherwise make every run inconclusive (exit 2).

### Tested
- Test harness (44 assertions) passed elevated on PowerShell 5.1 and 7.
- Elevated full system-drive scan: no false hits.

## [1.0.0] - 2026-10-21

First release. Scans a Windows host for PHP installs affected by PHP2Shell
(CVE-2026-109618, CVE-2026-109619), against the fixed releases 8.5.12,
8.4.27, 8.3.36 and 8.2.35.

### Added
- **Install detection** - `php.exe`, `php-cgi.exe`, `php-win.exe` and the
  engine DLLs (`php5/7/8[ts].dll`), grouped per folder; the lowest version
  in a folder decides.
- **PHP identification** - only files stamped The PHP Group / PHP count;
  shims and launchers are `WARN`, not misread as old PHP.
- **Exit codes** - 0 unaffected, 1 needs patch, 2 inconclusive, 3 script
  error.
- **CSV output** - one row per install (with ComputerName), plus a CSV of
  unreadable folders. Transcript of every run.
- **`-Path`, `-ExcludePath`, `-LogRoot`, `-PassThru`.**
- Built-in exclusion of system folders that are unreadable even when
  elevated.
- Long path support (`\\?\`), junction loop protection, cloud placeholders
  left unread.

### Tested
- Test harness (44 assertions) passed on PowerShell 5.1 and 7, including
  the official PHP 8.4.27 NTS x64 build (`UNAFFECTED`).
- Non-elevated full system-drive scan: no false hits.

[1.1.0]: https://github.com/tobiastillstam/Scan-PHP2Shell/releases/tag/v1.1.0
[1.0.1]: https://github.com/tobiastillstam/Scan-PHP2Shell/releases/tag/v1.0.1
