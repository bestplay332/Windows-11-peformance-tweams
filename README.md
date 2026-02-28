# ⚛️ Windows 11 Atomic Zero (Universal 2026)

**Ultimate System Optimization for Intel/AMD CPUs & NVIDIA/AMD/Intel GPUs.** This is a 100% native PowerShell framework designed to strip Windows 11 of background telemetry, AI-driven data collection, and system-wide latency.

---

## ⚠️ STEP 1: CREATE A RESTORE POINT (MANDATORY)
Before running any system-level script, you **MUST** create a restore point. This is your safety net.
1. Press the **Windows Key**, type "Create a restore point", and hit Enter.
2. Click **Create**, name it "Before Atomic Zero", and click **Create** again.

---

## 🚀 Key Features:
* **Universal CPU Support:** Disables Core Parking and Power Throttling for all Intel & AMD chips.
* **Input Latency Kill:** Forces **IRQ8 (System Timer)** to High Priority for crisp mouse movement.
* **GPU Scheduling:** Enables **HAGS** (Hardware-Accelerated GPU Scheduling) via Registry.
* **The Blackout:** Strips UI animations and sets a solid black UI for max FPS.
* **No Forced Updates:** Reclaims control over Windows Update restarts.

---

## 🛠️ How to Run:
1. Right-click **Start** > **Terminal (Admin)**.
2. Copy the entire code block below.
3. Paste it into the terminal and hit **Enter**.
4. **Restart your PC** to finalize the kernel changes.

```powershell
# ============================================================
# ATOMIC ZERO - UNIVERSAL 2026 WINDOWS 11 PURGE 
# Optimized for All Modern CPUs (Intel/AMD) & GPUs (NVIDIA/AMD)
# ============================================================

# --- 0. ADMIN CHECK ---
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: PLEASE RUN AS ADMINISTRATOR." -ForegroundColor Red
    exit
}

Write-Host "INITIALIZING GLOBAL SYSTEM PURGE... RECLAIMING HARDWARE." -ForegroundColor Red

# --- 1. AUTOMATIC RESTORE POINT (FOR SAFETY) ---
Write-Host "[*] Creating System Restore Point..." -ForegroundColor Gold
Enable-ComputerRestore -Drive "C:\" -ErrorAction SilentlyContinue
Checkpoint-Computer -Description "BeforeAtomicZeroUniversal" -RestorePointType "MODIFY_SETTINGS" -ErrorAction SilentlyContinue

# --- 2. GLOBAL CACHE & SLOP PURGE ---
Write-Host "[*] Wiping System Slop & App Caches..." -ForegroundColor Cyan
net stop wuauserv; net stop bits
$PurgePaths = @("$env:TEMP\*", "C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Windows\SoftwareDistribution\Download\*", "$env:LOCALAPPDATA\IconCache.db")
foreach ($Path in $PurgePaths) { Remove-Item $Path -Recurse -Force -ErrorAction SilentlyContinue }

# --- 3. KILL 2026 AI BLOAT & FORCED UPDATES ---
Write-Host "[*] Nuking AI Data Analysis & Forced Updates..." -ForegroundColor Cyan
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f

# --- 4. UNIVERSAL CPU OPTIMIZATION ---
Write-Host "[*] Optimizing Kernel Scheduling & Power States..." -ForegroundColor Cyan
Disable-MMAgent -mc
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 1 /f
powercfg -setacvalueindex scheme_current sub_processor CPMINCORES 100
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null
powercfg -setactive scheme_current

# --- 5. UNIVERSAL GPU & INPUT LATENCY (IRQ PRIORITY) ---
Write-Host "[*] Shifting Hardware Interrupts to High Priority..." -ForegroundColor Cyan
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d 1 /f
bcdedit /set disabledynamictick yes
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t REG_DWORD /d 2 /f

# --- 6. NETWORK & SSD PERFORMANCE ---
Write-Host "[*] Accelerating I/O and Network Packets..." -ForegroundColor Cyan
fsutil behavior set disable8dot3 1
fsutil behavior set disablelastaccess 1
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xffffffff /f
netsh int tcp set global autotuninglevel=normal

# --- 7. AESTHETIC BLACKOUT (THE ULTIMATE MINIMALIST UI) ---
Write-Host "[*] Stripping UI Bloat (Blackout Mode)..." -ForegroundColor Cyan
reg add "HKCU\Control Panel\Desktop" /v "Wallpaper" /t REG_SZ /d "" /f
reg add "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideIcons" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\


