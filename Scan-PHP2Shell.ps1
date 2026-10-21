#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Finds PHP installs on a Windows host and reports whether they are affected
    by PHP2Shell (CVE-2026-109618, CVE-2026-109619).

.DESCRIPTION
    Walks local fixed drives (or the folders given with -Path) and looks for
    PHP binaries: php.exe, php-cgi.exe, php-win.exe and the engine DLLs
    (php5/php7/php8, thread-safe and non-thread-safe). Each file's version
    resource is read with FileVersionInfo; no PHP binary is ever executed.

    Files are grouped per folder into one install. A file counts as PHP only
    when its version resource says The PHP Group / PHP, so shims and
    launchers named php.exe (Chocolatey, Scoop, ...) are reported as WARN
    instead of being misread as an old PHP. The lowest PHP version in a
    folder decides its status.

    Each install is compared with the fixed releases published by the PHP
    project on 2026-10-21: 8.5.12, 8.4.27, 8.3.36, 8.2.35.

      UNAFFECTED   at or above the fixed release for its branch
      NEEDS PATCH  below the fixed release, or an end-of-life branch
                   (8.1 and older, no upstream fix)
      WARN         not identified as PHP, version unreadable, cloud
                   placeholder, or a branch the advisory does not cover

    Results go to the console, a transcript and a CSV. Folders that could
    not be read go to a second CSV. Config-based mitigations in php.ini are
    not evaluated.

    The script changes nothing on the host apart from writing its own log
    and CSV files, so -WhatIf has no effect on the scan.

.PARAMETER Path
    Folders to scan instead of all local fixed drives.

.PARAMETER ExcludePath
    Extra folders to leave out of the scan, on top of the built-in system
    folders on each scanned drive (System Volume Information, $Recycle.Bin,
    Recovery, and Windows, ProgramData and Defender for Endpoint folders
    that stay unreadable when elevated; see $SystemExcludes).

.PARAMETER LogRoot
    Folder for the transcript and CSV files. Default: Logs next to the
    script, or under the current location when the script folder is unknown.

.PARAMETER PassThru
    Also write one result object per install to the pipeline.

.EXAMPLE
    .\Scan-PHP2Shell.ps1
    Scans all local fixed drives. Exit code 0, 1, 2 or 3 (see NOTES).

.EXAMPLE
    .\Scan-PHP2Shell.ps1 -Path 'D:\Web', 'C:\php' -Verbose
    Scans two folders only.

.EXAMPLE
    .\Scan-PHP2Shell.ps1 -PassThru | Where-Object Status -ne 'UNAFFECTED'
    Scans and returns the installs that need attention as objects.

.NOTES
    Author        : Tobias Tillstam, Tillnet
    Webpage       : https://tillnet.se
    GitHub        : https://github.com/tobiastillstam
    Company       : Tillnet
    License       : MIT
    Version       : 1.0.1
    Date Created  : 2026-10-21
    Last Modified : 2026-10-22

    Change Log
    ----------
    1.0.1 (2026-10-22) - System excludes extended from an elevated run:
                         Defender for Endpoint, WebThreatDefSvc, config\BFS,
                         LocalService Ngc, ProgramData SystemData and
                         CapabilityAccessManager.
    1.0.0 (2026-10-21) - Initial release.

    Operational notes:
    - Exit code: 0 = no affected install found, everything readable;
      1 = at least one install needs patching; 2 = inconclusive (an install
      needs a manual check, or folders could not be read); 3 = script error.
      Errors are logged and give exit code 3 instead of being rethrown
      (a rethrow would give exit code 1 and read as NEEDS PATCH).
    - Output in <LogRoot>: Scan-PHP2Shell-<host>-<time>.log (transcript),
      .csv (one row per install) and -skipped.csv (unreadable folders, only
      when there are any). CSV files are UTF-8 with BOM.
    - Reparse points (junctions, symlinks, mount folders) are not followed.
      Volumes mounted without a drive letter are only scanned via -Path.
    - Cloud placeholder files (OneDrive Files On-Demand) are not read, since
      reading them would download them; they are reported as WARN.
    - Long paths (over 260 characters) are handled with \\?\ paths.
    - Read-only on the host. Elevation is required so that profile and
      service folders can be read; without it many folders are skipped and
      the result is inconclusive.
    - Sources: php.net/archive/2026.php (2026-10-21),
      windows.php.net/downloads/releases/releases.json.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Folders to scan instead of all local fixed drives.
    [Parameter(Mandatory = $false)]
    [string[]]$Path,

    # Extra folders to leave out of the scan (full paths).
    [Parameter(Mandatory = $false)]
    [string[]]$ExcludePath,

    # Folder for the transcript and CSV files. Default: <script folder>\Logs.
    [Parameter(Mandatory = $false)]
    [string]$LogRoot,

    # Also write one result object per install to the pipeline.
    [Parameter(Mandatory = $false)]
    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

$ScriptVersion = '1.0.1'
$AdvisoryDate  = '2026-10-21'

# Fixed upstream release per supported branch.
$FixedRelease = @{
    '8.5' = [version]'8.5.12'
    '8.4' = [version]'8.4.27'
    '8.3' = [version]'8.3.36'
    '8.2' = [version]'8.2.35'
}

# File names that identify a PHP install (CLI, CGI, engine DLLs).
$PhpFileNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($n in 'php.exe', 'php-cgi.exe', 'php-win.exe',
               'php5.dll', 'php5ts.dll', 'php7.dll', 'php7ts.dll', 'php8.dll', 'php8ts.dll') {
    [void]$PhpFileNames.Add($n)
}

# Folders below each drive root that are not readable even when elevated
# and never hold a PHP install. Defender for Endpoint folders are excluded
# whole, since its locked subfolders change between platform versions.
$SystemExcludes = @(
    'System Volume Information'
    '$Recycle.Bin'
    'Recovery'
    'Windows\CSC'
    'Windows\System32\LogFiles\WMI\RtBackup'
    'Windows\System32\WebThreatDefSvc'
    'Windows\System32\config\BFS'
    'Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc'
    'ProgramData\Microsoft\Windows\SystemData'
    'ProgramData\Microsoft\Windows\CapabilityAccessManager'
    'ProgramData\Microsoft\Windows Defender Advanced Threat Protection'
    'Program Files\Windows Defender Advanced Threat Protection'
)

# Attributes of cloud placeholders: Offline, RecallOnOpen, RecallOnDataAccess.
$PlaceholderMask = 0x1000 -bor 0x40000 -bor 0x400000

$StatusOrder = @{ 'NEEDS PATCH' = 0; 'WARN' = 1; 'UNAFFECTED' = 2 }

# -------------------------------------------------------------------------
# Helper functions: output and paths
# -------------------------------------------------------------------------

function ConvertTo-Ascii {
    param([string]$Text)
    if (-not $Text) { return $Text }
    # Fold accents (a-ring -> a), replace anything else non-ASCII with '?'.
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.Normalize([Text.NormalizationForm]::FormD).ToCharArray()) {
        if ([Globalization.CharUnicodeInfo]::GetUnicodeCategory($c) -eq 'NonSpacingMark') { continue }
        if ([int]$c -lt 128) { [void]$sb.Append($c) } else { [void]$sb.Append('?') }
    }
    $sb.ToString()
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    Write-Host ('{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, (ConvertTo-Ascii $Message))
}

function Stop-RunTranscript {
    # PS 7 Stop-Transcript honours -WhatIf (PS 5.1 has no such parameter).
    $p = @{}
    if ((Get-Command Stop-Transcript).Parameters.ContainsKey('WhatIf')) { $p['WhatIf'] = $false }
    Stop-Transcript @p | Out-Null
}

function Get-LongPath {
    param([string]$LiteralPath)
    if ($LiteralPath.StartsWith('\\?\')) { return $LiteralPath }
    if ($LiteralPath.StartsWith('\\')) { return '\\?\UNC\' + $LiteralPath.Substring(2) }
    '\\?\' + $LiteralPath
}

function Get-DisplayPath {
    param([string]$LiteralPath)
    if ($LiteralPath.StartsWith('\\?\UNC\')) { return '\\' + $LiteralPath.Substring(8) }
    if ($LiteralPath.StartsWith('\\?\')) { return $LiteralPath.Substring(4) }
    $LiteralPath
}

function Get-InnerMessage {
    param([System.Exception]$Exception)
    while ($Exception.InnerException) { $Exception = $Exception.InnerException }
    $Exception.Message
}

# -------------------------------------------------------------------------
# Helper functions: scan and classify
# -------------------------------------------------------------------------

function Find-PhpFile {
    # Iterative walk (no recursion depth limit). Writes FileInfo objects for
    # matching files; unreadable folders are added to $Skipped.
    param([string]$Root, $ExcludeSet, $Skipped)

    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push((Get-LongPath $Root))
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        $script:DirCount++
        if (($script:DirCount % 2000) -eq 0) {
            Write-Progress -Activity 'Scanning for PHP binaries' -Status "$($script:DirCount) folders" -CurrentOperation (Get-DisplayPath $dir)
        }
        try {
            $info = New-Object System.IO.DirectoryInfo $dir
            foreach ($file in $info.EnumerateFiles('php*')) {
                if ($PhpFileNames.Contains($file.Name)) { $file }
            }
            foreach ($sub in $info.EnumerateDirectories()) {
                if ($sub.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
                $display = Get-DisplayPath $sub.FullName
                if ($ExcludeSet.Contains($display)) {
                    Write-Log "Excluded: $display"
                    continue
                }
                $stack.Push($sub.FullName)
            }
        }
        catch {
            $Skipped.Add([pscustomobject]@{
                ComputerName = $env:COMPUTERNAME
                Path         = Get-DisplayPath $dir
                Reason       = Get-InnerMessage $_.Exception
            })
        }
    }
}

function Get-PhpFileInfo {
    # Reads the version resource of one file. Never executes it.
    param([System.IO.FileInfo]$File)

    $result = [pscustomobject]@{
        Name      = $File.Name
        Directory = Get-DisplayPath $File.DirectoryName
        Version   = $null
        IsPhp     = $false
        Detail    = ''
    }
    if (([int]$File.Attributes -band $PlaceholderMask) -ne 0) {
        $result.Detail = 'cloud placeholder, not read (reading would download it)'
        return $result
    }
    try {
        $fv = [Diagnostics.FileVersionInfo]::GetVersionInfo($File.FullName)
    }
    catch {
        $result.Detail = "version resource unreadable: $(Get-InnerMessage $_.Exception)"
        return $result
    }

    $raw = if ($fv.FileVersion) { $fv.FileVersion } else { $fv.ProductVersion }
    $result.IsPhp = ($fv.CompanyName -eq 'The PHP Group') -or ($fv.ProductName -eq 'PHP')
    if ($raw -match '^\s*(\d+)\.(\d+)\.(\d+)') {
        $result.Version = [version]('{0}.{1}.{2}' -f $Matches[1], $Matches[2], $Matches[3])
    }
    if (-not $result.IsPhp) {
        $result.Detail = "not identified as a PHP build (company '$($fv.CompanyName)', product '$($fv.ProductName)', version '$raw'); possibly a shim or launcher"
    }
    elseif (-not $result.Version) {
        $result.Detail = "version could not be read ('$raw')"
    }
    $result
}

function Get-InstallStatus {
    # One result row per folder. The lowest identified PHP version decides.
    param([string]$InstallDir, [object[]]$FileInfo)

    $php   = @($FileInfo | Where-Object { $_.IsPhp -and $_.Version })
    $other = @($FileInfo | Where-Object { -not ($_.IsPhp -and $_.Version) })
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($f in $other) { $notes.Add("$($f.Name): $($f.Detail)") }

    $row = [ordered]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'WARN'
        Version      = ''
        Branch       = ''
        FixedIn      = ''
        EndOfLife    = $false
        Action       = 'check by hand'
        InstallDir   = $InstallDir
        Files        = (@($FileInfo | ForEach-Object { $_.Name } | Sort-Object) -join ', ')
        Note         = ''
    }

    if ($php.Count -eq 0) {
        $row.Note = $notes -join '; '
        return [pscustomobject]$row
    }

    $versions = @($php | ForEach-Object { $_.Version } | Sort-Object -Unique)
    $low = $versions[0]
    if ($versions.Count -gt 1) {
        $notes.Insert(0, "mixed versions in folder: $($versions -join ', '); lowest used")
    }
    $branch = '{0}.{1}' -f $low.Major, $low.Minor
    $row.Version = $low.ToString()
    $row.Branch  = $branch

    if (($low.Major -eq 8) -and $FixedRelease.ContainsKey($branch)) {
        $fix = $FixedRelease[$branch]
        $row.FixedIn = $fix.ToString()
        if ($low -ge $fix) {
            $row.Status = 'UNAFFECTED'
            $row.Action = 'none'
        }
        else {
            $row.Status = 'NEEDS PATCH'
            $row.Action = "update to $fix or later"
        }
    }
    elseif ((($low.Major -eq 8) -and ($low.Minor -ge 6)) -or ($low.Major -gt 8)) {
        $row.Action = 'branch not covered by the advisory; check php.net'
    }
    else {
        $row.Status    = 'NEEDS PATCH'
        $row.EndOfLife = $true
        $row.FixedIn   = 'none (end of life)'
        $row.Action    = 'upgrade to a supported branch (8.2.35, 8.3.36, 8.4.27, 8.5.12) or apply a vendor backport'
    }
    $row.Note = $notes -join '; '
    [pscustomobject]$row
}

# -------------------------------------------------------------------------
# Begin script body
# -------------------------------------------------------------------------

Write-Verbose "Starting $($MyInvocation.MyCommand.Name)"

$script:ExitCode = 3
$script:DirCount = 0
$transcriptStarted = $false

try {
    # --- Output folder and transcript --------------------------------------
    if (-not $LogRoot) {
        $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        $LogRoot = Join-Path $base 'Logs'
    }
    $LogRoot = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($LogRoot)
    if (-not (Test-Path -LiteralPath $LogRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $LogRoot -Force -WhatIf:$false -Confirm:$false | Out-Null
    }
    $baseName       = 'Scan-PHP2Shell-{0}-{1}' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $transcriptPath = Join-Path $LogRoot "$baseName.log"
    $csvPath        = Join-Path $LogRoot "$baseName.csv"
    $skippedPath    = Join-Path $LogRoot "$baseName-skipped.csv"

    Start-Transcript -LiteralPath $transcriptPath -WhatIf:$false -Confirm:$false | Out-Null
    $transcriptStarted = $true

    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    Write-Log "Scan-PHP2Shell $ScriptVersion on $env:COMPUTERNAME (PowerShell $($PSVersionTable.PSVersion), elevated: $isAdmin)"
    Write-Log ("Advisory {0}: fixed releases {1}" -f $AdvisoryDate,
        (($FixedRelease.Values | Sort-Object -Descending | ForEach-Object { $_.ToString() }) -join ', '))

    # --- Scan roots and exclusions -----------------------------------------
    $roots = New-Object System.Collections.Generic.List[string]
    if ($Path) {
        foreach ($p in $Path) {
            $full = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($p)
            if (-not (Test-Path -LiteralPath $full -PathType Container)) {
                throw "Path not found or not a folder: $full"
            }
            $roots.Add($full)
        }
    }
    else {
        $drives = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' |
                    Select-Object -ExpandProperty DeviceID)
        foreach ($d in $drives) { $roots.Add("$d\") }
    }
    if ($roots.Count -eq 0) { throw 'No local fixed drives found to scan.' }

    $excludeSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $roots) {
        $driveRoot = [IO.Path]::GetPathRoot($r)
        foreach ($rel in $SystemExcludes) { [void]$excludeSet.Add((Join-Path $driveRoot $rel)) }
    }
    foreach ($x in $ExcludePath) {
        [void]$excludeSet.Add($PSCmdlet.GetUnresolvedProviderPathFromPSPath($x).TrimEnd('\'))
    }
    Write-Log "Scanning: $($roots -join ', ')"
    Write-Verbose "Exclusions: $(@($excludeSet) -join ', ')"

    # --- Scan ---------------------------------------------------------------
    $sw      = [Diagnostics.Stopwatch]::StartNew()
    $skipped = New-Object System.Collections.Generic.List[object]
    $files   = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roots) {
        Write-Progress -Activity 'Scanning for PHP binaries' -Status $r
        foreach ($f in (Find-PhpFile -Root $r -ExcludeSet $excludeSet -Skipped $skipped)) {
            Write-Verbose "Found: $(Get-DisplayPath $f.FullName)"
            $files.Add((Get-PhpFileInfo -File $f))
        }
    }
    Write-Progress -Activity 'Scanning for PHP binaries' -Completed
    Write-Log ("Scanned {0} folders in {1:N0} s: {2} PHP file(s), {3} folder(s) unreadable" -f
        $script:DirCount, $sw.Elapsed.TotalSeconds, $files.Count, $skipped.Count)

    # --- Classify and report -----------------------------------------------
    $results = @($files | Group-Object -Property Directory | ForEach-Object {
        Get-InstallStatus -InstallDir $_.Name -FileInfo $_.Group
    } | Sort-Object -Property @{ Expression = { $StatusOrder[$_.Status] } }, InstallDir)

    $csvEncoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
    if ($results.Count -gt 0) {
        Write-Log ''
        foreach ($r in $results) {
            $level = if ($r.Status -eq 'UNAFFECTED') { 'INFO' } else { 'WARN' }
            $ver   = if ($r.Version) { $r.Version } else { 'unknown' }
            $eol   = if ($r.EndOfLife) { ' (end of life)' } else { '' }
            Write-Log ('{0,-11}  {1}{2}  {3}  [{4}]' -f $r.Status, $ver, $eol, $r.InstallDir, $r.Files) $level
            if ($r.Status -ne 'UNAFFECTED') { Write-Log "             action: $($r.Action)" $level }
            if ($r.Note) { Write-Log "             note: $($r.Note)" $level }
        }
        $results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
        Write-Log ''
        Write-Log "Results: $csvPath"
    }

    if ($skipped.Count -gt 0) {
        $skipped | Export-Csv -LiteralPath $skippedPath -NoTypeInformation -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
        Write-Log "$($skipped.Count) folder(s) could not be read; results may be incomplete. List: $skippedPath" 'WARN'
        foreach ($s in ($skipped | Select-Object -First 10)) { Write-Log "  skipped: $($s.Path) ($($s.Reason))" 'WARN' }
        if ($skipped.Count -gt 10) { Write-Log "  ... and $($skipped.Count - 10) more" 'WARN' }
    }

    # --- Verdict and exit code ---------------------------------------------
    $needs = @($results | Where-Object { $_.Status -eq 'NEEDS PATCH' })
    $eols  = @($needs | Where-Object { $_.EndOfLife })
    $warns = @($results | Where-Object { $_.Status -eq 'WARN' })
    Write-Log ''
    if ($needs.Count -gt 0) {
        $script:ExitCode = 1
        Write-Log "RESULT: NEEDS PATCH - $($needs.Count) install(s) need patching, $($eols.Count) of them end of life" 'WARN'
    }
    elseif (($warns.Count -gt 0) -or ($skipped.Count -gt 0)) {
        $script:ExitCode = 2
        Write-Log "RESULT: INCONCLUSIVE - $($warns.Count) install(s) need a manual check, $($skipped.Count) folder(s) could not be read" 'WARN'
    }
    elseif ($results.Count -eq 0) {
        $script:ExitCode = 0
        Write-Log 'RESULT: UNAFFECTED - no PHP binaries found'
    }
    else {
        $script:ExitCode = 0
        Write-Log "RESULT: UNAFFECTED - $($results.Count) install(s), all at or above the fixed releases"
    }
    Write-Log "Exit code $($script:ExitCode)"

    if ($PassThru) { $results }
}
catch {
    # Logged and reported, not rethrown: a rethrow gives exit code 1, which
    # means NEEDS PATCH to a caller.
    $script:ExitCode = 3
    Write-Log "Fatal: $(Get-InnerMessage $_.Exception)" 'ERROR'
    Write-Log "$($_.ScriptStackTrace)" 'ERROR'
    Write-Log "Exit code $($script:ExitCode)" 'ERROR'
    Write-Error -ErrorRecord $_ -ErrorAction Continue
}
finally {
    if ($transcriptStarted) {
        Stop-RunTranscript
    }
    Write-Verbose "Finished $($MyInvocation.MyCommand.Name)"
}

exit $script:ExitCode
