<# :
@echo off
rem Hybrid batch/PowerShell: cmd runs these lines, PowerShell sees them as a comment.
set "SELF=%~f0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create([IO.File]::ReadAllText($env:SELF, [Text.Encoding]::UTF8)))"
echo.
pause
exit /b
#>
# unhide-usb.bat
# Επαναφέρει αρχεία που έκρυψε USB virus και διαγράφει ύποπτα shortcuts/autorun.inf
# Χρήση: διπλό κλικ στο unhide-usb.bat

#Requires -Version 5.0

$ErrorActionPreference = 'Stop'

function Write-Section($text) {
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host $text -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

# ---- 1. Εντοπισμός removable drives ----
Write-Section "Εντοπισμός Removable Drives"

$drives = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=2" |
    Where-Object { $_.Size -gt 0 }

if (-not $drives) {
    Write-Host "Δεν βρέθηκε κανένα συνδεδεμένο USB drive." -ForegroundColor Yellow
    exit 0
}

$i = 0
$choices = @()
foreach ($d in $drives) {
    $i++
    $sizeGB = [math]::Round($d.Size / 1GB, 2)
    $freeGB = [math]::Round($d.FreeSpace / 1GB, 2)
    $label  = if ($d.VolumeName) { $d.VolumeName } else { "(no label)" }
    Write-Host ("  [{0}] {1}  {2}  {3} GB free / {4} GB" -f $i, $d.DeviceID, $label, $freeGB, $sizeGB)
    $choices += $d
}

Write-Host ""
$sel = Read-Host "Επίλεξε drive (1-$i) ή Q για έξοδο"
if ($sel -match '^[Qq]') { exit 0 }
if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $i) {
    Write-Host "Άκυρη επιλογή." -ForegroundColor Red
    exit 1
}

$drive = $choices[[int]$sel - 1]
$root  = "$($drive.DeviceID)\"
Write-Host "Επιλέχθηκε: $root" -ForegroundColor Green

# ---- 2. Unhide όλων των αρχείων & φακέλων ----
Write-Section "Επαναφορά κρυμμένων αρχείων"

$unhideCount = 0
$failCount   = 0

Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        $attrs = $_.Attributes
        $needsFix = ($attrs -band [IO.FileAttributes]::Hidden) -or
                    ($attrs -band [IO.FileAttributes]::System)
        if ($needsFix) {
            $new = $attrs -band (-bnot ([IO.FileAttributes]::Hidden))
            $new = $new   -band (-bnot ([IO.FileAttributes]::System))
            $_.Attributes = $new
            $unhideCount++
        }
    } catch {
        $failCount++
    }
}

Write-Host "Έγινε unhide σε $unhideCount αντικείμενα." -ForegroundColor Green
if ($failCount -gt 0) {
    Write-Host "$failCount αντικείμενα δεν μπόρεσαν να αλλαχτούν (πιθανά protected)." -ForegroundColor Yellow
}

# ---- 3. Εντοπισμός & διαγραφή ύποπτων αρχείων ----
Write-Section "Διαγραφή Malware Artifacts"

$deleted   = @()
$skipped   = @()

# 3a. autorun.inf στο root
$autorun = Join-Path $root 'autorun.inf'
if (Test-Path -LiteralPath $autorun) {
    try {
        Remove-Item -LiteralPath $autorun -Force -ErrorAction Stop
        $deleted += $autorun
    } catch {
        $skipped += "$autorun ($($_.Exception.Message))"
    }
}

# 3b. Ύποπτα .lnk shortcuts: εκείνα που έχουν το ίδιο όνομα με υπαρκτό φάκελο
# στο ίδιο directory (κλασικό μοτίβο USB virus)
$folders = Get-ChildItem -LiteralPath $root -Recurse -Force -Directory -ErrorAction SilentlyContinue
$folderMap = @{}
foreach ($f in $folders) {
    $key = (Join-Path $f.Parent.FullName $f.Name).ToLower()
    $folderMap[$key] = $true
}

$shortcuts = Get-ChildItem -LiteralPath $root -Recurse -Force -Filter '*.lnk' -ErrorAction SilentlyContinue
$shell = New-Object -ComObject WScript.Shell

foreach ($lnk in $shortcuts) {
    $baseName = [IO.Path]::GetFileNameWithoutExtension($lnk.Name)
    $twin = (Join-Path $lnk.DirectoryName $baseName).ToLower()
    $isVirus = $false
    $reason  = ''

    # Ταυτώνυμο shortcut με υπαρκτό φάκελο => σχεδόν σίγουρα malware
    if ($folderMap.ContainsKey($twin)) {
        $isVirus = $true
        $reason  = 'shortcut to twin folder'
    } else {
        # Έλεγχος target για ύποπτα args (cmd.exe, powershell, rundll32 κλπ.)
        try {
            $sc = $shell.CreateShortcut($lnk.FullName)
            $target = "$($sc.TargetPath) $($sc.Arguments)".ToLower()
            if ($target -match 'cmd\.exe|powershell|rundll32|wscript|cscript|mshta') {
                $isVirus = $true
                $reason  = "suspicious target: $($sc.TargetPath)"
            }
        } catch { }
    }

    if ($isVirus) {
        try {
            Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop
            $deleted += "$($lnk.FullName)  [$reason]"
        } catch {
            $skipped += "$($lnk.FullName) ($($_.Exception.Message))"
        }
    }
}

[Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null

# 3c. .exe με ονόματα που μιμούνται φακέλους (ίδιο μοτίβο)
$exes = Get-ChildItem -LiteralPath $root -Recurse -Force -Filter '*.exe' -ErrorAction SilentlyContinue
foreach ($exe in $exes) {
    $baseName = [IO.Path]::GetFileNameWithoutExtension($exe.Name)
    $twin = (Join-Path $exe.DirectoryName $baseName).ToLower()
    if ($folderMap.ContainsKey($twin)) {
        try {
            Remove-Item -LiteralPath $exe.FullName -Force -ErrorAction Stop
            $deleted += "$($exe.FullName)  [exe twin folder]"
        } catch {
            $skipped += "$($exe.FullName) ($($_.Exception.Message))"
        }
    }
}

# ---- 4. Σύνοψη ----
Write-Section "Σύνοψη"

Write-Host "Drive καθαρίστηκε: $root" -ForegroundColor Green
Write-Host "Αρχεία/φάκελοι επανεμφανίστηκαν: $unhideCount"
Write-Host "Malware artifacts διαγραμμένα:   $($deleted.Count)"

if ($deleted.Count -gt 0) {
    Write-Host ""
    Write-Host "Διαγραμμένα:" -ForegroundColor Yellow
    $deleted | ForEach-Object { Write-Host "  - $_" }
}
if ($skipped.Count -gt 0) {
    Write-Host ""
    Write-Host "Παρέλειψα (δες χειροκίνητα):" -ForegroundColor Yellow
    $skipped | ForEach-Object { Write-Host "  - $_" }
}

Write-Host ""
Write-Host "Έτοιμο. Πριν χρησιμοποιήσεις το USB σε άλλο PC, κάνε ένα antivirus scan." -ForegroundColor Cyan
