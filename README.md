# ⚛️ Windows 11 Atomic Zero (Universal 2026)
**Ultimate Optimization for Intel/AMD CPUs & NVIDIA/AMD/Intel GPUs.**

---

## ⚠️ STEP 1: CREATE A RESTORE POINT (MANDATORY)
Before running this script, you **MUST** create a safety net:
1. Press the **Windows Key**, type "Create a restore point", and hit Enter.
2. Click **Create**, name it "Before Atomic Zero", and click **Create** again.

---

## 🛠️ How to Run:
1. Right-click **Start** > **Terminal (Admin)**.
2. Copy the entire code block below and paste it.
3. **Restart your PC** to finalize the kernel changes.

```powershell
# ============================================================
# ATOMIC ZERO - UNIVERSAL 2026 WINDOWS 11 PURGE 
# ============================================================
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: PLEASE RUN AS ADMINISTRATOR." -ForegroundColor Red; exit
}
Write-Host "INITIALIZING GLOBAL SYSTEM PURGE..." -ForegroundColor Red

# --- 1. AUTO-RESTORE & CACHE PURGE ---
Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description "BeforeAtomicZero" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue
net stop wuauserv; net stop bits
$Purge = @("$env:TEMP\*", "C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Windows\SoftwareDistribution\Download\*")
foreach ($P in $Purge) { Remove-Item $P -Recurse -Force -ErrorAction SilentlyContinue }

# --- 2. KILL AI, ADS & UPDATES ---
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f

# --- 3. HARDWARE & LATENCY (IRQ8 / HAGS / POWER) ---
Disable-MMAgent -mc
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
powercfg -setactive scheme_current
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d 1 /f
bcdedit /set disabledynamictick yes
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f

# --- 4. NETWORK & FILE SYSTEM ---
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xffffffff /f
netsh int tcp set global autotuninglevel=normal

# --- 5. AESTHETIC BLACKOUT ---
reg add "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

# --- 6. FINAL REPAIR ---
DISM.exe /Online /Cleanup-image /Restorehealth; sfc /scannow; stop-process -name explorer -force
Write-Host "PURGE COMPLETE. RESTART YOUR PC." -ForegroundColor Gold
