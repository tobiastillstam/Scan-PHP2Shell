# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-10-22

### Changed
- **System excludes** extended after an elevated full-drive run: Defender
  for Endpoint folders (`ProgramData` and `Program Files`),
  `Windows\System32\WebThreatDefSvc`, `Windows\System32\config\BFS`,
  LocalService `Ngc`, `ProgramData\Microsoft\Windows\SystemData` and
  `CapabilityAccessManager`. These stay denied to administrators and would
  otherwise make every run inconclusive (exit 2).

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

[1.0.1]: https://github.com/tobiastillstam/Scan-PHP2Shell/releases/tag/v1.0.1
[1.0.0]: https://github.com/tobiastillstam/Scan-PHP2Shell/releases/tag/v1.0.0
