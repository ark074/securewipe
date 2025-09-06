# PowerShell: create a VHDX for Windows testing
$VHD = Join-Path $PSScriptRoot 'demo\test.vhdx'
New-Item -ItemType Directory -Path (Join-Path $PSScriptRoot 'demo') -Force | Out-Null
if (-Not (Test-Path $VHD)) {
    New-VHD -Path $VHD -SizeBytes 1GB -Dynamic | Out-Null
    Mount-VHD -Path $VHD | Out-Null
    $disk = Get-Disk | Where-Object PartitionStyle -Eq 'Raw' | Select-Object -Last 1
    Initialize-Disk -Number $disk.Number -PartitionStyle MBR -PassThru | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -Confirm:$false
    Write-Host "Created and mounted VHDX at $VHD"
} else { Write-Host "VHD already exists." }
