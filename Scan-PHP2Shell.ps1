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

    Before the walk, places that point at PHP are read: IIS
    applicationHost.config (FastCGI applications and handler mappings),
    Apache httpd.conf and its includes (LoadModule, LoadFile, FcgidWrapper,
    PHPIniDir), services (direct and through NSSM), the machine PATH and
    installed-programs entries for PHP or a PHP stack. The binaries at those
    locations are read even when the walk does not reach them (outside
    -Path, excluded, a share, behind a junction), and every install lists
    what points at it in ReferencedBy. A reference that leads to no PHP is
    reported as WARN.

    Each install is compared with the fixed releases published by the PHP
    project on 2026-10-21: 8.5.12, 8.4.27, 8.3.36, 8.2.35.

      UNAFFECTED   at or above the fixed release for its branch
      NEEDS PATCH  below the fixed release, or an end-of-life branch
                   (8.1 and older, no upstream fix)
      WARN         not identified as PHP, version unreadable, cloud
                   placeholder, a branch the advisory does not cover, or
                   a reference (IIS, Apache, service, installed program)
                   that leads to no PHP

    Results go to the console, a transcript and a CSV. Folders and config
    sources that could not be read go to a second CSV. Config-based mitigations in php.ini are
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

.PARAMETER SkipReferences
    Walk the disk only; do not read IIS, Apache, services, PATH or
    installed programs.

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
    Version       : 1.1.0
    Date Created  : 2026-10-21
    Last Modified : 2026-10-22

    Change Log
    ----------
    1.1.0 (2026-10-22) - Reference check: IIS, Apache, services, machine
                         PATH and installed programs are read; referenced
                         binaries are classified even outside the walk.
                         New CSV column ReferencedBy, new -SkipReferences.
                         A reference that leads to no PHP is WARN.
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
    - References: a 32-bit PowerShell on 64-bit Windows reads IIS through
      Sysnative and the registry through both views, so a 32-bit RMM agent
      sees the same as a 64-bit session. IIS shared configuration
      (redirection.config) is followed. Apache conditional blocks
      (<IfModule>, <IfDefine>) count as active; services started with
      -f / -d use a config this script does not read. Site web.config
      handler mappings and IIS Express are not read.
    - IIS / Apache parsing idea from Check-PhpVersion by Code Ape
      (github.com/fardinbarashi/PHP-CVE-2026-109618-and-CVE-2026-109619,
      MIT). Unlike that tool, no found binary is ever run.
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
    [switch]$PassThru,

    # Walk the disk only; do not read IIS, Apache, services, PATH or programs.
    [Parameter(Mandatory = $false)]
    [switch]$SkipReferences
)

$ErrorActionPreference = 'Stop'

# -------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------

$ScriptVersion = '1.1.0'
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

function Add-Skipped {
    # One row of the -skipped.csv: a folder or config source not read.
    param($Skipped, [string]$LiteralPath, [System.Exception]$Exception)
    $Skipped.Add([pscustomobject]@{
        ComputerName = $env:COMPUTERNAME
        Path         = $LiteralPath
        Reason       = Get-InnerMessage $Exception
    })
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
            Add-Skipped $Skipped (Get-DisplayPath $dir) $_.Exception
        }
    }
}

function Get-PhpFileInFolder {
    # PHP binaries directly in one folder, no recursion. Nothing when the
    # folder does not exist; throws when it cannot be read.
    param([string]$Folder)
    $info = New-Object System.IO.DirectoryInfo (Get-LongPath $Folder)
    if (-not $info.Exists) { return }
    foreach ($file in $info.EnumerateFiles('php*')) {
        if ($PhpFileNames.Contains($file.Name)) { $file }
    }
}

function Get-PhpFileInfo {
    # Reads the version resource of one file. Never executes it.
    param([System.IO.FileInfo]$File)

    $result = [pscustomobject]@{
        Name      = $File.Name
        Path      = Get-DisplayPath $File.FullName
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

function New-ResultRow {
    # Every row gets the same columns: Export-Csv takes them from the first.
    param([string]$InstallDir)
    [ordered]@{
        ComputerName = $env:COMPUTERNAME
        Status       = 'WARN'
        Version      = ''
        Branch       = ''
        FixedIn      = ''
        EndOfLife    = $false
        Action       = 'check by hand'
        InstallDir   = $InstallDir
        Files        = ''
        ReferencedBy = ''
        Note         = ''
    }
}

function Get-InstallStatus {
    # One result row per folder. The lowest identified PHP version decides.
    param([string]$InstallDir, [object[]]$FileInfo)

    $php   = @($FileInfo | Where-Object { $_.IsPhp -and $_.Version })
    $other = @($FileInfo | Where-Object { -not ($_.IsPhp -and $_.Version) })
    $notes = New-Object System.Collections.Generic.List[string]
    foreach ($f in $other) { $notes.Add("$($f.Name): $($f.Detail)") }

    $row = New-ResultRow -InstallDir $InstallDir
    $row.Files = (@($FileInfo | ForEach-Object { $_.Name } | Sort-Object) -join ', ')

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
# Helper functions: references (IIS, Apache, services, PATH, programs)
# -------------------------------------------------------------------------

function ConvertTo-RefPath {
    # Expands %VARS%, turns / into \ and makes the path absolute against
    # $BaseDir. Returns $null for an empty or unrootable value.
    param([string]$Value, [string]$BaseDir)
    if (-not $Value) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($Value.Trim().Trim('"')).Replace('/', '\')
    if (-not $p) { return $null }
    if (-not [IO.Path]::IsPathRooted($p)) {
        if (-not $BaseDir) { return $null }
        $p = [IO.Path]::Combine($BaseDir, $p)
    }
    try { $p = [IO.Path]::GetFullPath($p) } catch { Write-Verbose "Path kept as written: $p" }
    if ($p.Length -gt 3) { $p = $p.TrimEnd('\') }
    $p
}

function Get-LeafName {
    # File name of a path as written; never throws on odd characters.
    param([string]$LiteralPath)
    $LiteralPath -replace '^.*[\\/]', ''
}

function Get-ExePath {
    # The executable of a command line (service PathName, UninstallString).
    param([string]$CommandLine)
    if (-not $CommandLine) { return $null }
    if ($CommandLine -match '^\s*"([^"]+)"') { return $Matches[1] }
    if ($CommandLine -match '^\s*(.+?\.exe)(\s|$)') { return $Matches[1] }
    ($CommandLine.Trim() -split '\s+')[0]
}

function Test-UnderPath {
    param([string]$LiteralPath, [string]$Parent)
    $Parent = $Parent.TrimEnd('\')
    ($LiteralPath -eq $Parent) -or $LiteralPath.StartsWith($Parent + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Test-PathCovered {
    # True when the walk reaches this folder: under a root, not excluded.
    param([string]$LiteralPath, $Roots, $ExcludeSet)
    foreach ($x in $ExcludeSet) { if (Test-UnderPath $LiteralPath $x) { return $false } }
    foreach ($r in $Roots) { if (Test-UnderPath $LiteralPath $r) { return $true } }
    $false
}

function New-PhpRef {
    # Kind: file (one binary), dir (a folder holding PHP), tree (PHP may sit
    # anywhere below), none (location unknown; Problem says why).
    # WarnIfMissing: WARN when the target is missing or unreadable.
    # WarnIfNoPhp:   WARN when the target exists but holds no PHP.
    param([string]$Kind, [string]$Category, [string]$Source, [string]$Target,
          [bool]$WarnIfMissing = $true, [bool]$WarnIfNoPhp = $true, [string]$Problem = '')
    $folder = $Target
    if ($Kind -eq 'file') { $folder = [IO.Path]::GetDirectoryName($Target) }
    [pscustomobject]@{
        Kind          = $Kind
        Category      = $Category
        Source        = $Source
        Target        = $Target
        Folder        = $folder
        WarnIfMissing = $WarnIfMissing
        WarnIfNoPhp   = $WarnIfNoPhp
        Problem       = $Problem
    }
}

function Get-IisConfigPath {
    # applicationHost.config, following IIS shared configuration. A 32-bit
    # PowerShell on 64-bit Windows sees SysWOW64 as System32, which has no
    # IIS config, so it goes through Sysnative.
    $sys = Join-Path $env:windir 'System32'
    if ([Environment]::Is64BitOperatingSystem -and (-not [Environment]::Is64BitProcess)) {
        $sys = Join-Path $env:windir 'Sysnative'
    }
    $dir = Join-Path $sys 'inetsrv\config'
    $redirect = Join-Path $dir 'redirection.config'
    if (Test-Path -LiteralPath $redirect -PathType Leaf) {
        $text = [regex]::Replace([IO.File]::ReadAllText($redirect), '(?s)<!--.*?-->', '')
        if ($text -match '(?is)<configurationRedirection\b[^>]*>') {
            $tag = $Matches[0]
            if (($tag -match '\benabled\s*=\s*"true"') -and ($tag -match '\bpath\s*=\s*"([^"]+)"')) {
                $dir = ConvertTo-RefPath $Matches[1]
            }
        }
    }
    Join-Path $dir 'applicationHost.config'
}

function Get-IisPhpReference {
    # FastCGI applications (fullPath) and handler mappings (scriptProcessor)
    # that point at php*.exe. XML comments are stripped first.
    param([string]$ConfigPath)
    $text = [regex]::Replace([IO.File]::ReadAllText($ConfigPath), '(?s)<!--.*?-->', '')
    foreach ($m in [regex]::Matches($text, '(?i)\b(fullPath|scriptProcessor)\s*=\s*(["''])(.*?)\2')) {
        $exe = ConvertTo-RefPath (($m.Groups[3].Value -split '\|')[0])
        if ((-not $exe) -or ((Get-LeafName $exe) -notlike 'php*.exe')) { continue }
        $source = if ($m.Groups[1].Value -eq 'fullPath') { 'IIS FastCGI application' } else { 'IIS handler mapping' }
        New-PhpRef 'file' 'IIS' $source $exe
    }
}

function Split-ApacheArg {
    # Apache directive arguments: "quoted with spaces" or bare words.
    param([string]$Text)
    foreach ($m in [regex]::Matches($Text, '"([^"]*)"|(\S+)')) {
        if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Groups[2].Value }
    }
}

function Expand-ApacheVar {
    # ${NAME} from Define, then from the environment. Unknown names stay.
    param([string]$Text, [hashtable]$Defines)
    $out = $Text
    foreach ($m in [regex]::Matches($Text, '\$\{(\w+)\}')) {
        $name  = $m.Groups[1].Value
        $value = if ($Defines.ContainsKey($name)) { $Defines[$name] } else { [Environment]::GetEnvironmentVariable($name) }
        if ($null -ne $value) { $out = $out.Replace($m.Value, $value) }
    }
    $out
}

function Add-ApacheRef {
    param([hashtable]$State, [string]$Kind, [string]$Directive, [string]$Value, [string]$File, [bool]$Strict = $true)
    $source   = "Apache $Directive in $File"
    $expanded = Expand-ApacheVar $Value $State.Defines
    if ($expanded -match '\$\{') {
        $State.Refs.Add((New-PhpRef 'none' 'Apache' $source $Value $Strict $Strict "unresolved variable in '$Value'"))
        return
    }
    $State.Refs.Add((New-PhpRef $Kind 'Apache' $source (ConvertTo-RefPath $expanded $State.Root) $Strict $Strict))
}

function Read-ApacheConf {
    # Reads one config file in order and follows Include / IncludeOptional
    # as httpd does, so Define values are known where they are used and
    # files that are never included are not read. <IfModule> and <IfDefine>
    # blocks count as active.
    param([string]$File, [hashtable]$State, $Skipped)
    if (-not $State.Seen.Add($File)) { return }
    try { $lines = [IO.File]::ReadAllLines($File) }
    catch { Add-Skipped $Skipped $File $_.Exception; return }

    foreach ($line in $lines) {
        if ($line -notmatch '^\s*(\w+)\s+(.+?)\s*$') { continue }
        $directive = $Matches[1]
        $argv = @(Split-ApacheArg $Matches[2])
        if ($argv.Count -eq 0) { continue }

        if ($directive -eq 'Define') {
            if ($argv.Count -ge 2) { $State.Defines[$argv[0]] = Expand-ApacheVar $argv[1] $State.Defines }
        }
        elseif ($directive -eq 'ServerRoot') {
            $root = ConvertTo-RefPath (Expand-ApacheVar $argv[0] $State.Defines)
            if ($root) { $State.Root = $root }
        }
        elseif (($directive -eq 'Include') -or ($directive -eq 'IncludeOptional')) {
            $inc = Expand-ApacheVar $argv[0] $State.Defines
            if ($inc -match '\$\{') {
                Write-Log "Apache: Include with unresolved variable not followed: '$($argv[0])' in $File" 'WARN'
                continue
            }
            $inc = ConvertTo-RefPath $inc $State.Root
            $targets = @()
            if ($inc -match '[*?]') {
                $targets = @(Get-ChildItem -Path $inc -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.FullName })
            }
            elseif (Test-Path -LiteralPath $inc -PathType Container) {
                $targets = @(Get-ChildItem -LiteralPath $inc -File -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $_.FullName })
            }
            elseif (Test-Path -LiteralPath $inc -PathType Leaf) {
                $targets = @($inc)
            }
            else {
                Write-Verbose "Apache: Include target not found: $inc ($File)"
            }
            foreach ($t in $targets) { Read-ApacheConf -File $t -State $State -Skipped $Skipped }
        }
        elseif ($directive -eq 'LoadModule') {
            if (($argv.Count -ge 2) -and ($argv[0] -like 'php*_module')) { Add-ApacheRef $State 'file' 'LoadModule' $argv[1] $File }
        }
        elseif ($directive -eq 'LoadFile') {
            if ((Get-LeafName $argv[0]) -like 'php*.dll') { Add-ApacheRef $State 'file' 'LoadFile' $argv[0] $File }
        }
        elseif ($directive -eq 'FcgidWrapper') {
            if ((Get-LeafName $argv[0]) -like 'php*.exe') { Add-ApacheRef $State 'file' 'FcgidWrapper' $argv[0] $File }
        }
        elseif ($directive -eq 'PHPIniDir') {
            # php.ini may live apart from the binaries: annotate only.
            Add-ApacheRef $State 'dir' 'PHPIniDir' $argv[0] $File $false
        }
    }
}

function Get-ApachePhpReference {
    param([string]$ServerRoot, $Skipped)
    $state = @{
        Root    = $ServerRoot
        Defines = @{}
        Seen    = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        Refs    = New-Object System.Collections.Generic.List[object]
    }
    $conf = Join-Path $ServerRoot 'conf\httpd.conf'
    if (Test-Path -LiteralPath $conf -PathType Leaf) {
        Read-ApacheConf -File $conf -State $state -Skipped $Skipped
    }
    $state.Refs
}

function Get-UninstallPhpReference {
    # Installed-programs entries for PHP itself or a PHP stack. Both
    # registry views are read so a 32-bit host process sees 64-bit entries,
    # plus the per-user entries of loaded profiles.
    $keys = New-Object System.Collections.Generic.List[object]
    foreach ($view in [Microsoft.Win32.RegistryView]::Registry64, [Microsoft.Win32.RegistryView]::Registry32) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $view)
        $k = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
        if ($k) { $keys.Add($k) }
    }
    foreach ($sid in [Microsoft.Win32.Registry]::Users.GetSubKeyNames()) {
        if ($sid -like '*_Classes') { continue }
        $k = [Microsoft.Win32.Registry]::Users.OpenSubKey("$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall")
        if ($k) { $keys.Add($k) }
    }

    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($k in $keys) {
        foreach ($sub in $k.GetSubKeyNames()) {
            $e = $k.OpenSubKey($sub)
            if (-not $e) { continue }
            $name = "$($e.GetValue('DisplayName'))".Trim()
            # PHP itself ('PHP 8.3.6', 'PHP (x64)'), not 'PHP Manager', 'PHP Tools ...'
            $isPhp   = $name -match '^PHP(\s*$|\s+v?\d|\s*\()'
            $isStack = $name -match 'XAMPP|WampServer|Laragon|AMPPS|Uniform Server|Bitnami WAMP'
            if (-not ($isPhp -or $isStack)) { continue }

            $ver = "$($e.GetValue('DisplayVersion'))".Trim()
            $loc = "$($e.GetValue('InstallLocation'))".Trim()
            if (-not $loc) {
                $exe = Get-ExePath "$($e.GetValue('UninstallString'))"
                if ($exe -and ((Get-LeafName $exe) -notlike 'msiexec*')) { $loc = Split-Path -Path $exe -Parent }
            }
            $source = "Installed programs: $name"
            if ($ver -and ($name -notlike "*$ver*")) { $source += " $ver" }
            $path = ConvertTo-RefPath $loc
            if (-not $seen.Add("$source|$path")) { continue }

            if ($path) {
                # A stack without PHP (some Bitnami stacks) is fine; a missing folder is not.
                New-PhpRef 'tree' 'Programs' $source $path $true $isPhp
            }
            elseif ($isPhp) {
                New-PhpRef 'none' 'Programs' $source '(no install folder recorded)' $true $true 'no install folder recorded'
            }
            else {
                Write-Verbose "$source has no install folder recorded"
            }
        }
    }
}

function Get-PhpReference {
    # Collects everything that points at PHP. Each source is read on its
    # own; one that cannot be read goes to $Skipped (inconclusive).
    param($Skipped)
    $refs        = New-Object System.Collections.Generic.List[object]
    $apacheRoots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

    # --- IIS ---
    $iis = 'IIS applicationHost.config'
    try {
        $iis = Get-IisConfigPath
        if (Test-Path -LiteralPath $iis -PathType Leaf) {
            foreach ($r in @(Get-IisPhpReference -ConfigPath $iis)) { $refs.Add($r) }
        }
        else { Write-Verbose "IIS: no $iis" }
    }
    catch { Add-Skipped $Skipped $iis $_.Exception }

    # --- Services (and Apache roots of httpd services) ---
    try {
        foreach ($svc in @(Get-CimInstance -ClassName Win32_Service)) {
            $exe = Get-ExePath $svc.PathName
            if (-not $exe) { continue }
            $leaf = Get-LeafName $exe
            if ($leaf -eq 'httpd.exe') {
                [void]$apacheRoots.Add((Split-Path -Path (Split-Path -Path $exe -Parent) -Parent))
            }
            elseif ($leaf -like 'php*.exe') {
                $p = ConvertTo-RefPath $exe
                if ($p) { $refs.Add((New-PhpRef 'file' 'Service' "Service $($svc.Name)" $p)) }
            }
            elseif ($leaf -like 'nssm*.exe') {
                $param = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)\Parameters" -ErrorAction SilentlyContinue
                if ($param -and $param.Application -and ((Get-LeafName $param.Application) -like 'php*.exe')) {
                    $p = ConvertTo-RefPath $param.Application
                    if ($p) { $refs.Add((New-PhpRef 'file' 'Service' "Service $($svc.Name) (NSSM)" $p)) }
                }
            }
        }
    }
    catch { Add-Skipped $Skipped 'Win32_Service' $_.Exception }

    # --- Apache: running httpd, then the usual install folders ---
    try {
        foreach ($proc in @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'httpd.exe'")) {
            if ($proc.ExecutablePath) {
                [void]$apacheRoots.Add((Split-Path -Path (Split-Path -Path $proc.ExecutablePath -Parent) -Parent))
            }
        }
    }
    catch { Add-Skipped $Skipped 'Win32_Process' $_.Exception }
    $sd = $env:SystemDrive
    $known = @("$sd\Apache24", "$sd\Apache2", "$sd\Apache", "$sd\xampp\apache", "$sd\UniServerZ\core\apache2",
               "$sd\wamp\bin\apache\*", "$sd\wamp64\bin\apache\*", "$sd\laragon\bin\apache\*")
    foreach ($pf in $env:ProgramFiles, $env:ProgramW6432, ${env:ProgramFiles(x86)}) {
        if ($pf) { $known += "$pf\Apache Software Foundation\*" }
    }
    foreach ($k in $known) {
        foreach ($d in @(Get-Item -Path $k -ErrorAction SilentlyContinue)) {
            if ($d.PSIsContainer) { [void]$apacheRoots.Add($d.FullName.TrimEnd('\')) }
        }
    }
    foreach ($root in $apacheRoots) {
        try {
            foreach ($r in @(Get-ApachePhpReference -ServerRoot $root -Skipped $Skipped)) { $refs.Add($r) }
        }
        catch { Add-Skipped $Skipped "$root\conf" $_.Exception }
    }

    # --- Machine PATH (only entries that hold PHP; local folders only) ---
    foreach ($entry in ("$([Environment]::GetEnvironmentVariable('Path', 'Machine'))" -split ';')) {
        $d = ConvertTo-RefPath $entry
        if ((-not $d) -or $d.StartsWith('\\')) { continue }
        try {
            if (@(Get-PhpFileInFolder -Folder $d).Count -gt 0) { $refs.Add((New-PhpRef 'dir' 'PATH' 'Machine PATH' $d $false $false)) }
        }
        catch { Write-Verbose "PATH entry not readable: $d" }
    }

    # --- Installed programs ---
    try {
        foreach ($r in @(Get-UninstallPhpReference)) { $refs.Add($r) }
    }
    catch { Add-Skipped $Skipped 'Installed programs (Uninstall registry keys)' $_.Exception }

    # --- Dedupe and log ---
    $unique = New-Object System.Collections.Generic.List[object]
    $keys   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $refs) {
        if ($keys.Add("$($r.Kind)|$($r.Source)|$($r.Target)")) { $unique.Add($r) }
    }
    $summary = @($unique | Group-Object -Property Category | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', '
    if ($unique.Count -eq 0) { $summary = 'none' }
    Write-Log "References to PHP: $summary (Apache roots checked: $($apacheRoots.Count))"
    foreach ($r in $unique) { Write-Log "  $($r.Source) -> $($r.Target)" }
    $unique
}

function Add-ReferencedFile {
    # Reads the PHP binaries at a referenced location into $Files, so they
    # are classified even when the walk does not reach them. Sets
    # $Ref.Problem when the location is missing or unreadable.
    param($Ref, $Files, $Seen, $Roots, $ExcludeSet, $Skipped)
    try {
        $found = @()
        if ($Ref.Kind -eq 'file') {
            $fi = New-Object System.IO.FileInfo (Get-LongPath $Ref.Target)
            if ($fi.Exists) { $found = @($fi) + @(Get-PhpFileInFolder -Folder $Ref.Folder) }
            else { $Ref.Problem = "$($Ref.Target) not found or not accessible" }
        }
        elseif (($Ref.Kind -eq 'dir') -or ($Ref.Kind -eq 'tree')) {
            if (-not [IO.Directory]::Exists((Get-LongPath $Ref.Target))) {
                $Ref.Problem = "$($Ref.Target) not found or not accessible"
            }
            elseif ($Ref.Kind -eq 'dir') {
                $found = @(Get-PhpFileInFolder -Folder $Ref.Target)
            }
            elseif (-not (Test-PathCovered -LiteralPath $Ref.Target -Roots $Roots -ExcludeSet $ExcludeSet)) {
                Write-Log "Scanning referenced folder outside the walk: $($Ref.Target) ($($Ref.Source))"
                $found = @(Find-PhpFile -Root $Ref.Target -ExcludeSet $ExcludeSet -Skipped $Skipped)
            }
        }
        foreach ($f in $found) {
            $info = Get-PhpFileInfo -File $f
            if ($Seen.Add($info.Path)) {
                Write-Verbose "Found via reference: $($info.Path)"
                $Files.Add($info)
            }
        }
    }
    catch {
        $Ref.Problem = "$($Ref.Target) not readable: $(Get-InnerMessage $_.Exception)"
    }
}

function Add-RowValue {
    # Appends a value to a '; '-separated row field, once.
    param($Row, [string]$Name, [string]$Value)
    $parts = @("$($Row.$Name)" -split '; ' | Where-Object { $_ })
    if ($parts -notcontains $Value) { $Row.$Name = (@($parts) + $Value) -join '; ' }
}

function Merge-PhpReference {
    # Adds each reference's source to the installs it points at. One that
    # leads nowhere is a WARN: on the install row when that folder holds
    # PHP (UNAFFECTED becomes WARN), otherwise on a row of its own.
    # Returns the extra rows.
    param([object[]]$Refs, [object[]]$Rows)
    $extra = @{}
    foreach ($ref in $Refs) {
        $matched = @($Rows | Where-Object {
            if ($ref.Kind -eq 'tree') { Test-UnderPath $_.InstallDir $ref.Folder } else { $_.InstallDir -eq $ref.Folder }
        })
        foreach ($m in $matched) { Add-RowValue $m 'ReferencedBy' $ref.Source }

        $problem = $ref.Problem
        $warn    = $ref.WarnIfMissing
        if ((-not $problem) -and ($matched.Count -eq 0)) {
            $problem = "no PHP binaries found in $($ref.Target)"
            if ($ref.Kind -eq 'tree') { $problem = "no PHP binaries found under $($ref.Target)" }
            $warn = $ref.WarnIfNoPhp
        }
        if (-not $problem) { continue }
        if (-not $warn) {
            Write-Log "Reference not counted: $($ref.Source): $problem"
            continue
        }

        if ($matched.Count -gt 0) {
            foreach ($m in $matched) {
                Add-RowValue $m 'Note' "$($ref.Source): $problem"
                if ($m.Status -eq 'UNAFFECTED') {
                    $m.Status = 'WARN'
                    $m.Action = 'check by hand: a reference to this install leads to a missing file'
                }
            }
            continue
        }
        if (-not $extra.ContainsKey($ref.Folder)) {
            $row = [pscustomobject](New-ResultRow -InstallDir $ref.Folder)
            $row.Action = 'check by hand: PHP is referenced here but was not found'
            $extra[$ref.Folder] = $row
        }
        Add-RowValue $extra[$ref.Folder] 'ReferencedBy' $ref.Source
        Add-RowValue $extra[$ref.Folder] 'Note' "$($ref.Source): $problem"
    }
    $extra.Values
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

    # --- References (IIS, Apache, services, PATH, programs) ----------------
    $skipped = New-Object System.Collections.Generic.List[object]
    $refs    = @()
    if ($SkipReferences) { Write-Log 'Reference check skipped (-SkipReferences)' }
    else { $refs = @(Get-PhpReference -Skipped $skipped) }

    # --- Scan ---------------------------------------------------------------
    $sw      = [Diagnostics.Stopwatch]::StartNew()
    $files   = New-Object System.Collections.Generic.List[object]
    foreach ($r in $roots) {
        Write-Progress -Activity 'Scanning for PHP binaries' -Status $r
        foreach ($f in (Find-PhpFile -Root $r -ExcludeSet $excludeSet -Skipped $skipped)) {
            Write-Verbose "Found: $(Get-DisplayPath $f.FullName)"
            $files.Add((Get-PhpFileInfo -File $f))
        }
    }
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($f in $files) { [void]$seen.Add($f.Path) }
    foreach ($ref in $refs) {
        Add-ReferencedFile -Ref $ref -Files $files -Seen $seen -Roots $roots -ExcludeSet $excludeSet -Skipped $skipped
    }
    Write-Progress -Activity 'Scanning for PHP binaries' -Completed
    Write-Log ("Scanned {0} folders in {1:N0} s: {2} PHP file(s), {3} location(s) unreadable" -f
        $script:DirCount, $sw.Elapsed.TotalSeconds, $files.Count, $skipped.Count)

    # --- Classify and report -----------------------------------------------
    $rows = @($files | Group-Object -Property Directory | ForEach-Object {
        Get-InstallStatus -InstallDir $_.Name -FileInfo $_.Group
    })
    if ($refs.Count -gt 0) { $rows += @(Merge-PhpReference -Refs $refs -Rows $rows) }
    $results = @($rows | Sort-Object -Property @{ Expression = { $StatusOrder[$_.Status] } }, InstallDir)

    $csvEncoding = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
    if ($results.Count -gt 0) {
        Write-Log ''
        foreach ($r in $results) {
            $level = if ($r.Status -eq 'UNAFFECTED') { 'INFO' } else { 'WARN' }
            $ver   = if ($r.Version) { $r.Version } else { 'unknown' }
            $eol   = if ($r.EndOfLife) { ' (end of life)' } else { '' }
            Write-Log ('{0,-11}  {1}{2}  {3}  [{4}]' -f $r.Status, $ver, $eol, $r.InstallDir, $r.Files) $level
            if ($r.Status -ne 'UNAFFECTED') { Write-Log "             action: $($r.Action)" $level }
            if ($r.ReferencedBy) { Write-Log "             referenced by: $($r.ReferencedBy)" $level }
            if ($r.Note) { Write-Log "             note: $($r.Note)" $level }
        }
        $results | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
        Write-Log ''
        Write-Log "Results: $csvPath"
    }

    if ($skipped.Count -gt 0) {
        $skipped | Export-Csv -LiteralPath $skippedPath -NoTypeInformation -Encoding $csvEncoding -WhatIf:$false -Confirm:$false
        Write-Log "$($skipped.Count) location(s) could not be read; results may be incomplete. List: $skippedPath" 'WARN'
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
        Write-Log "RESULT: INCONCLUSIVE - $($warns.Count) install(s) need a manual check, $($skipped.Count) location(s) could not be read" 'WARN'
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
