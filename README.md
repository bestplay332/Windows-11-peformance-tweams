# ⚛️ Windows 11 Nuclear Purge (2026 Edition)

A high-performance PowerShell framework designed to strip Windows 11 of background telemetry, AI-driven data collection, and system-wide latency. 100% native commands. No third-party executables. Zero bloat.

### ⚠️ IMPORTANT: Create a Restore Point First
Before running this script, manually create a System Restore point.

### 🚀 How to Run:
1. Right-click **Start** > **Terminal (Admin)** or **PowerShell (Admin)**.
2. Copy the entire code block below.
3. Paste it into the window and hit **Enter**.
4. **Restart your PC** once the repair finishes.

```powershell
# ============================================================
# THE 2026 NUCLEAR MEGA-SCRIPT: ULTIMATE PERFORMANCE & PURGE
# ============================================================

Write-Host "INITIALIZING SYSTEM SURGERY... STRIPPING WINDOWS TO THE CORE." -ForegroundColor Red

# --- 1. THE "SLOP" & CACHE PURGE ---
net stop wuauserv; net stop bits
$Purge = @("$env:TEMP\*", "C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Windows\SoftwareDistribution\Download\*", "$env:LOCALAPPDATA\IconCache.db", "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*")
foreach ($P in $Purge) { Remove-Item $P -Recurse -Force -ErrorAction SilentlyContinue }

# --- 2. KILL AI, COPILOT, ADS & FORCED UPDATES ---
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f

# --- 3. KERNEL & HARDWARE PRIORITY ---
Disable-MMAgent -mc
reg add "HKLM\System\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61

# --- 4. NETWORK & FILE SYSTEM SPEED ---
$Interfaces = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
Get-ChildItem $Interfaces | ForEach-Object {
    New-ItemProperty -Path $_.PSPath -Name "TcpAckFrequency" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path $_.PSPath -Name "TCPNoDelay" -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
}
netsh int tcp set global rss=enabled
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 1
bcdedit /set disabledynamictick yes

# --- 5. AESTHETICS & MINIMAL BAR ---
reg add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "" /f
reg add "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve

# --- 6. DISABLE DEFENDER & BACKGROUND NOISE ---
Set-MpPreference -DisableRealtimeMonitoring $true
powercfg -h off
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f

# --- 7. FINAL SYSTEM POLISH ---
Write-Host "REPAIRING KERNEL INTEGRITY..." -ForegroundColor Yellow
DISM.exe /Online /Cleanup-image /Restorehealth | Out-Null
sfc /scannow
stop-process -name explorer -force

Write-Host "NUCLEAR MEGA-TWEAK COMPLETE. YOUR PC IS NOW OPTIMIZED." -ForegroundColor Gold
