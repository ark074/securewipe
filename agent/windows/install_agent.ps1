param([string]$InstallDir = "$PSScriptRoot\agent")
Write-Host "Install SecureWipe agent (Windows) - placeholder"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Write-Host "Copy the agent executable to $InstallDir and create a scheduled task or service to run it as SYSTEM."
