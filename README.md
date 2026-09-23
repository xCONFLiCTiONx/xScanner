# xScanner

**xScanner** is a lightweight, on-demand Windows malware scanner built with C# and WPF (.NET 8.0). It provides fast, efficient system scanning without acting as a resident background antivirus service or kernel driver.

---

## Key Features

- **ClamAV Integration**: Uses ClamAV (`clamscan` / `freshclam`) as its core malware detection engine with automatic definition updates.
- **Smart Scan Caching (SQLite)**: Tracks file paths, sizes, modification timestamps, SHA-256 hashes, and ClamAV definition versions. Unchanged files are efficiently skipped in subsequent scans.
- **Lightweight Static Analysis**: Analyzes PE files (`.exe`, `.dll`, `.sys`, `.scr`, `.com`) for architecture, sections, entropy, imports, suspicious API usage, and Authenticode signatures.
- **Real-Time Logging & Progress Updates**: Keeps the user fully informed with live progress tracking (current file being scanned, files scanned, files skipped, threats found) and maintains complete scan history and detection logs.
- **Graceful Error Handling**: Safely handles locked, busy, or permission-restricted files during enumeration and scanning without crashing or interrupting the scan workflow.
- **Suspicious File Escalation**: Automatically deep-dives into surrounding directories, temp locations, and persistence mechanisms when suspicious activity is detected.
- **Secure Quarantine**: Isolates detected threats in a dedicated quarantine directory with atomic file operations, supporting restoration or permanent deletion.
- **Task Scheduler Integration**: Supports automated background scans via Windows Task Scheduler (`/scheduled` command-line argument) and exits cleanly upon completion.

---

## Scan Modes

### 1. Basic Scan
Covers high-risk persistence and malware locations automatically:
- Windows Startup folders (`User` and `Common`)
- Registry Run / RunOnce keys (`HKCU`, `HKLM`, `WOW6432Node`)
- Temporary and AppData directories (`%TEMP%`, `%APPDATA%`, `%LOCALAPPDATA%`)
- User folders (`Downloads`, `Desktop`)

### 2. Full Scan
- Searches all accessible local fixed drives.
- Supports recursive directory exclusions configured via settings (e.g., `C:\Games\`, `D:\VirtualMachines\`).

---

## Real-Time Logging & User Updates

xScanner keeps the end user informed at every step:
- **Live UI Feedback:** During a scan, the UI displays the active file being processed (`TxtProgress`), count of files scanned, and threats detected.
- **Skipped Files Logging:** Files verified against the SQLite cache as unchanged are skipped to maximize speed.
- **Scan History:** Completed scan records (start/end time, duration, examined, scanned, skipped, threats detected, suspicious files, definition version) are stored and viewable in the **History Window**.
- **Inaccessible File Handling:** Files protected by system permissions or locked by other applications are safely caught and bypassed using robust exception handling, ensuring uninterrupted scan execution.

---

## Project Structure

```text
xScanner/
│
├── App.xaml / App.xaml.cs          # WPF Application & CLI task runner (/scheduled)
├── Database/
│   ├── ScanDatabase.sqlite        # Local SQLite scan catalog & settings
│   └── Models/                    # FileRecord, ScanRecord, DetectionRecord, QuarantineRecord
├── Engines/
│   └── ClamAV/                    # ClamAvManager (clamscan & freshclam integration)
├── Analysis/
│   ├── PEAnalyzer.cs              # PE header, section, entropy & import analysis
│   └── Heuristics.cs              # SHA-256 hashing & heuristic checks
├── Core/
│   ├── FileSystem/                # FileEnumerator (Basic scan locations & full scan drives)
│   ├── ScanEngine/                # ScanOrchestrator (coordinates scans & progress)
│   ├── ScanCache/                 # ScanCacheManager (change detection & caching)
│   ├── ScanScheduler/             # SchedulerManager (Windows Task Scheduler integration)
│   └── ScanEscalation/            # EscalationManager (deep investigation of threats)
├── Quarantine/
│   └── QuarantineManager.Manager  # Secure isolation, restore & deletion
└── UI/
    ├── MainWindow.xaml            # Main dashboard & live progress
    ├── SettingsWindow.xaml        # Exclusions, schedules & definitions
    ├── QuarantineWindow.xaml      # Quarantined threat management
    └── HistoryWindow.xaml         # Past scan logs & results
```

---

## Normal Workflow

1. **Launch:** Start xScanner or trigger via Windows Task Scheduler (`/scheduled`).
2. **Update Definitions:** Automatically checks for and installs available ClamAV definition updates.
3. **Scan Execution:** Enumerates target files (Basic or Full), checking the SQLite cache.
4. **Caching & Skipping:** Unchanged files are skipped; new/modified files undergo static analysis and ClamAV scanning.
5. **Escalation & Quarantine:** Suspicious files trigger deep escalation; confirmed threats are safely isolated in quarantine.
6. **Reporting & Exit:** Scan metrics are logged to SQLite, history is updated, and the application exits cleanly.
