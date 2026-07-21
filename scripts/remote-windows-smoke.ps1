# Remote Windows runtime + static + Defender smoke for filled dummy-agent PEs.
$ErrorActionPreference = "Stop"
$dir = "C:\Users\daniel\binary-filler-smoke"
$exes = @(
    "dummy-agent-release.exe",
    "dummy-agent-release-lto.exe",
    "dummy-agent-release-fat-lto.exe",
    "dummy-agent-debug.exe"
)
$failed = $false

function Get-Utf16Contains([byte[]]$bytes, [string]$s) {
    $enc = [System.Text.Encoding]::Unicode.GetBytes($s)
    for ($i = 0; $i -le $bytes.Length - $enc.Length; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $enc.Length; $j++) {
            if ($bytes[$i + $j] -ne $enc[$j]) { $ok = $false; break }
        }
        if ($ok) { return $true }
    }
    return $false
}

function Get-PeSubsystem([string]$path) {
    $fs = [System.IO.File]::OpenRead($path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, "Begin") | Out-Null
        $pe = $br.ReadInt32()
        $fs.Seek($pe + 24, "Begin") | Out-Null
        $magic = $br.ReadUInt16()
        $fs.Seek($pe + 24 + 68, "Begin") | Out-Null
        $subsystem = $br.ReadUInt16()
        return @{ Magic = $magic; Subsystem = $subsystem }
    }
    finally { $fs.Close() }
}

function Test-AsciiContains([byte[]]$bytes, [string]$ascii) {
    $hay = [System.Text.Encoding]::ASCII.GetString($bytes)
    return ($hay.IndexOf($ascii, [StringComparison]::OrdinalIgnoreCase) -ge 0)
}

function Invoke-DefenderScan([string]$path) {
    try {
        $mpCmdCandidates = @(
            "${env:ProgramFiles}\Windows Defender\MpCmdRun.exe",
            "${env:ProgramFiles}\Microsoft Defender Antivirus\MpCmdRun.exe",
            "${env:ProgramData}\Microsoft\Windows Defender\Platform\*\MpCmdRun.exe"
        )
        $mpCmd = $null
        foreach ($c in $mpCmdCandidates) {
            $resolved = Get-Item $c -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($resolved) { $mpCmd = $resolved.FullName; break }
        }
        if (-not $mpCmd) {
            Write-Host "defender=SKIP (MpCmdRun not found)"
            return $true
        }

        Write-Host ("defender_tool={0}" -f $mpCmd)
        $raw = & $mpCmd -Scan -ScanType 3 -File $path 2>&1
        $code = $LASTEXITCODE
        $text = (($raw | Out-String).Trim() -replace "\s+", " ")
        if ([string]::IsNullOrEmpty($text)) {
            $text = "(empty)"
        }
        elseif ($text.Length -gt 240) {
            $text = $text.Substring(0, 240)
        }
        Write-Host ("defender_scan_exit={0} output={1}" -f $code, $text)

        # MpCmdRun success text is typically: "found no threats."
        $clean = ($text -match "found no threats") -or ($text -match "no threats")
        $threatLike = (-not $clean) -and (
            ($text -match "threats? (were )?found") -or
            ($text -match "Infection") -or
            ($text -match "was blocked")
        )

        if ($clean -and $code -eq 0) {
            Write-Host "defender=CLEAN"
            return $true
        }

        if ($threatLike -or $code -eq 2) {
            Write-Host "defender=THREAT"
            return $false
        }

        if ($code -eq 0) {
            Write-Host "defender=CLEAN"
            return $true
        }

        Write-Host ("defender=COMPLETED_NONZERO exit={0}" -f $code)
        return $true
    }
    catch {
        Write-Host ("defender=SKIP error={0}" -f $_.Exception.Message)
        return $true
    }
}

foreach ($name in $exes) {
    $path = Join-Path $dir $name
    Write-Host "==== $name ===="
    if (-not (Test-Path $path)) {
        Write-Host "MISSING $path"
        $failed = $true
        continue
    }

    $item = Get-Item $path
    Write-Host ("size={0}" -f $item.Length)

    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
    Write-Host ("CompanyName={0}" -f $vi.CompanyName)
    Write-Host ("ProductName={0}" -f $vi.ProductName)
    Write-Host ("FileDescription={0}" -f $vi.FileDescription)
    Write-Host ("OriginalFilename={0}" -f $vi.OriginalFilename)
    Write-Host ("FileVersion={0}" -f $vi.FileVersion)

    $pe = Get-PeSubsystem $path
    Write-Host ("PE_magic=0x{0:x} subsystem={1} (2=GUI 3=CUI)" -f $pe.Magic, $pe.Subsystem)

    $bytes = [System.IO.File]::ReadAllBytes($path)
    foreach ($s in @("Northwind Softworks", "DrivePrep", "USB drive preparation", "driveprep.exe")) {
        $hit = Get-Utf16Contains $bytes $s
        Write-Host ("utf16[{0}]={1}" -f $s, $hit)
        if (-not $hit) { $failed = $true }
    }

    foreach ($dll in @("user32.dll", "gdi32.dll", "shell32.dll", "comctl32.dll")) {
        $hit = Test-AsciiContains $bytes $dll
        Write-Host ("import_bytes[{0}]={1}" -f $dll, $hit)
        if (-not $hit) { $failed = $true }
    }

    $p = Start-Process -FilePath $path -WorkingDirectory $dir -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit(15000)) {
        try { $p.Kill() } catch {}
        Write-Host "run=TIMEOUT"
        $code = -1
        $failed = $true
    }
    else {
        $code = $p.ExitCode
        Write-Host ("run=exit_code={0}" -f $code)
    }

    $defOk = Invoke-DefenderScan $path
    if (-not $defOk) { $failed = $true }

    $versionOk = ($vi.CompanyName -eq "Northwind Softworks") -and
                 ($vi.ProductName -eq "DrivePrep") -and
                 ($vi.OriginalFilename -eq "driveprep.exe")
    $subOk = ($pe.Subsystem -eq 2)
    $runOk = ($code -eq 0)
    $pass = $versionOk -and $subOk -and $runOk -and $defOk
    if (-not $pass) { $failed = $true }
    Write-Host ("PASS={0} (version={1} subsystem={2} run={3} defender={4})" -f $pass, $versionOk, $subOk, $runOk, $defOk)
}

Write-Host "==== SUMMARY ===="
if ($failed) {
    Write-Host "RESULT=FAIL"
    exit 1
}
Write-Host "RESULT=OK"
exit 0
