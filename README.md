# Scan-PHP2Shell

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE)
![Platform](https://img.shields.io/badge/Windows%20Server-2016%2B-0078D6)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.1-blue)

Finds PHP installs on a Windows host and reports whether they are affected by
**PHP2Shell** (CVE-2026-109618, CVE-2026-109619): unauthenticated remote code
execution, fixed upstream on 2026-10-21.

Read-only. PHP is never executed; versions come from the files' version
resources. One exit code per host, so it fits RMM tools and scheduled tasks.

---

## What it does

- Walks all local fixed drives (or the folders given with `-Path`) and finds
  `php.exe`, `php-cgi.exe`, `php-win.exe` and the engine DLLs
  (`php5/7/8[ts].dll`). IIS FastCGI and Apache module setups are covered,
  not only installs that ship `php.exe`.
- Groups the files per folder into one install. The **lowest** PHP version
  in the folder decides, so a half-finished upgrade is caught.
- Only files stamped *The PHP Group* / *PHP* count as PHP. Shims and
  launchers named `php.exe` (Chocolatey, Scoop) are reported as `WARN`
  instead of being misread as an ancient PHP.
- Compares each install with the fixed releases:

| Branch | Fixed in |
| --- | --- |
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | no upstream fix (end of life) |

---

## Requirements

- Windows Server 2016 or later / Windows 10 or later.
- Windows PowerShell 5.1 (also runs on PowerShell 7).
- An **elevated** session (`#Requires -RunAsAdministrator`). Without it,
  profile and service folders cannot be read and the result would be
  inconclusive.

---

## Quick start

```powershell
# Scan all local fixed drives
.\Scan-PHP2Shell.ps1

# Scan specific folders only
.\Scan-PHP2Shell.ps1 -Path 'D:\Web', 'C:\php'

# Only the installs that need attention, as objects
.\Scan-PHP2Shell.ps1 -PassThru | Where-Object Status -ne 'UNAFFECTED'

# From an RMM tool or scheduled task
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Scan-PHP2Shell.ps1
```

> **Note:** with `-File`, `-Path` and `-ExcludePath` take **one** value
> only. A list (`-ExcludePath 'D:\A','D:\B'`) fails parameter binding and
> exits with code 1, which reads as NEEDS PATCH. Pass several folders with
> `-Command` instead:
>
> ```powershell
> powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\Tools\Scan-PHP2Shell.ps1' -ExcludePath 'D:\A','D:\B'; exit $LASTEXITCODE"
> ```
>
> `exit $LASTEXITCODE` passes the exit code on. This is the form for cmd and
> most RMM tools; when launching from a PowerShell prompt, write the `$` as
> `` `$ ``.

---

## Parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `-Path` | all local fixed drives | Folders to scan instead. |
| `-ExcludePath` | | Extra folders to leave out (full paths). |
| `-LogRoot` | `<script folder>\Logs` | Folder for the transcript and CSV files. |
| `-PassThru` | | Also write one result object per install to the pipeline. |

Always excluded on each scanned drive (not readable even when elevated, never
hold PHP):

- `System Volume Information`, `$Recycle.Bin`, `Recovery`
- `Windows\CSC`, `Windows\System32\LogFiles\WMI\RtBackup`,
  `Windows\System32\WebThreatDefSvc`, `Windows\System32\config\BFS`,
  `Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc`
- `ProgramData\Microsoft\Windows\SystemData`,
  `ProgramData\Microsoft\Windows\CapabilityAccessManager`
- `ProgramData\Microsoft\Windows Defender Advanced Threat Protection` and
  `Program Files\Windows Defender Advanced Threat Protection` (Defender for
  Endpoint)

Other folders that stay unreadable on a given host (vendor software, for
example) go in `-ExcludePath`; check the `-skipped.csv` first.

Full help: `Get-Help .\Scan-PHP2Shell.ps1 -Full`

---

## Status values

| Status | Meaning |
| --- | --- |
| `UNAFFECTED` | At or above the fixed release for its branch. |
| `NEEDS PATCH` | Below the fixed release, or an end-of-life branch (`EndOfLife = True`). |
| `WARN` | Needs a manual check: not identified as PHP, version unreadable, cloud placeholder, or a branch the advisory does not cover (8.6+). |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No affected install found and every folder was readable. |
| `1` | At least one install needs patching. |
| `2` | Inconclusive: an install needs a manual check, or folders could not be read. |
| `3` | Script error (bad `-Path`, unexpected failure). See the transcript. |

`1` wins over `2`: a host with one vulnerable install and some unreadable
folders still reports `1`.

---

## Output

In `-LogRoot`, per run:

| File | Content |
| --- | --- |
| `Scan-PHP2Shell-<host>-<time>.log` | Transcript of the run. |
| `Scan-PHP2Shell-<host>-<time>.csv` | One row per install: ComputerName, Status, Version, Branch, FixedIn, EndOfLife, Action, InstallDir, Files, Note. Only written when PHP was found. |
| `Scan-PHP2Shell-<host>-<time>-skipped.csv` | Folders that could not be read, with the reason. Only written when there are any. |

The host name is in the file names and in every row, so CSVs from many
servers can be collected into one folder and merged with
`Get-ChildItem *.csv -Exclude *-skipped.csv | Import-Csv`.

CSV files are UTF-8 with BOM (Excel-friendly). Console output is ASCII only.

---

## Limitations

- **php.ini mitigations are not evaluated.** An install with a
  configuration workaround still shows `NEEDS PATCH`.
- **Vendor backports** of the fix to end-of-life branches keep the old
  version number and still show `NEEDS PATCH`; check them by hand.
- Reparse points (junctions, symlinks) are not followed. Volumes mounted
  without a drive letter are only scanned when passed with `-Path`.
- Cloud placeholder files (OneDrive Files On-Demand) are not read, since
  reading would download them. They show as `WARN`.
- The fixed versions are built into the script. A later advisory needs a
  new script version.

---

## Sources

- php.net release announcements, 2026-10-21 (`php.net/archive/2026.php`)
- Windows builds: <https://windows.php.net/downloads/releases/releases.json>
- [NCSC-NL php2shell](https://github.com/NCSC-NL/php2shell)

---

## License

MIT (c) 2026 Tobias Tillstam, [Tillnet](https://tillnet.se). See [LICENSE](LICENSE).
