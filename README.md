# xScanner

xScanner — Development Specification  
Overview

Build xScanner, a lightweight Windows malware scanner written in C# / WPF.

The purpose is to provide a simple, on-demand malware scanner without installing or operating as a resident antivirus.

xScanner should:

Use ClamAV as its malware detection engine.  
Automatically update ClamAV definitions.  
Perform scheduled scans through Windows Task Scheduler.  
Maintain a local SQLite scan database so unchanged files do not needlessly get rescanned.  
Perform additional static analysis of executable files.  
Automatically investigate suspicious files more deeply.  
Provide quarantine and restore functionality.  
Provide simple scan history and results.  
Have no resident protection, kernel driver, or background antivirus service.

Microsoft Defender should not be used as a scanning engine. It remains the user's existing antivirus.

Scan Modes

There are only two scan modes.

Basic Scan

Basic Scan covers the locations most relevant to normal malware detection and persistence.

Include appropriate Windows locations such as:

Startup folders  
Registry Run / RunOnce locations  
Scheduled-task persistence  
Service-related persistence  
Common user application/startup locations  
%TEMP%  
%APPDATA%  
%LOCALAPPDATA%  
Downloads  
Desktop  
Other relevant Windows persistence locations

The locations should be predefined by xScanner.

The user should not need to configure individual locations.

Full Scan

Full Scan searches all accessible local drives.

The user can exclude directories from Full Scan.

Directory exclusions are recursive.

Example:

C:\Games\  
D:\VirtualMachines\  
F:\Backup\

There is no need for individual file exclusions.

Automatic Scanning

Provide a simple setting:

Automatic Scan

Disabled  
Basic  
Full

The user selects the desired mode and schedule.

Example:

Every day  
2:00 AM

Use Windows Task Scheduler to launch:

xScanner.exe /scheduled

xScanner should perform the scan and exit when finished.

It should not remain running as a resident background process.

Before scanning, automatically check for and install available ClamAV definition updates.

Scan Database

Use SQLite to maintain a local scan catalog.

Track information such as:

File path  
File size  
Last modified time  
SHA-256  
Last scan time  
Scan result  
ClamAV definition version

Before scanning a file, determine whether it has already been scanned and whether the file has changed.

Unchanged files with a valid previous result should normally be skipped.

New or changed files should be scanned.

The database should also allow xScanner to determine when previously scanned files need to be reconsidered after relevant definition updates.

Scan Process

The general process should be:

Start Scan  
 │  
 ├── Update ClamAV definitions  
 │  
 ├── Determine scan locations  
 │  
 ├── Enumerate files  
 │  
 ├── Check scan database  
 │  
 ├── Skip unchanged files with valid results  
 │  
 └── Scan new/changed files  
 │  
 ├── Static analysis  
 │  
 └── ClamAV  
 │  
 ▼  
 Results

The first scan may take considerable time.

Subsequent scans should be significantly faster because xScanner remembers previously scanned files.

Static Analysis

For applicable executable files, perform lightweight static analysis.

Analyze PE files such as:

.exe  
.dll  
.sys  
.scr  
.com

Potential analysis includes:

PE architecture  
Digital signatures  
Authenticode certificates  
PE sections  
Section permissions  
Entropy  
Imports  
Suspicious API usage  
Embedded executables  
Packing indicators  
Overlay data  
Other useful static indicators

Static analysis should identify suspicious characteristics rather than automatically declaring a file malware.

Suspicious File Escalation

If ClamAV detects a threat or static analysis identifies significant suspicious characteristics, xScanner should automatically perform a deeper investigation.

For a suspicious file:

Scan the containing directory recursively.  
Examine related files.  
Examine relevant temporary/staging locations.  
Examine relevant persistence locations.  
Analyze recently modified files that may be associated with the suspicious activity.  
Run ClamAV against relevant files that have not already been cleared by the current scan state.

Do not execute suspicious files.

The escalation should be based on static and filesystem analysis.

Quarantine

Provide a dedicated quarantine directory managed by xScanner.

For detected threats:

Original file  
 ↓  
Quarantine  
 ↓  
Record detection information in SQLite

Store information necessary to restore the original file if the user chooses to do so.

The UI should provide:

Restore  
Delete Permanently

Do not automatically delete detected files.

User Interface

Keep the interface extremely simple.

Main window:

┌─────────────────────────────────────────────┐  
│ xScanner ⚙ │  
├─────────────────────────────────────────────┤  
│ │  
│ PC STATUS │  
│ │  
│ CLEAN │  
│ │  
│ Last Scan: September 23, 2026 │  
│ Files Scanned: 184,392 │  
│ Threats Found: 0 │  
│ │  
│ ┌───────────┐ ┌───────────┐ │  
│ │ BASIC │ │ FULL │ │  
│ │ SCAN │ │ SCAN │ │  
│ └───────────┘ └───────────┘ │  
│ │  
│ Scan Progress │  
│ │  
├─────────────────────────────────────────────┤  
│ ClamAV: Current Last Update: Today │  
└─────────────────────────────────────────────┘

Settings should contain:

Automatic scan mode  
Schedule  
Full-scan exclusions  
Definition update settings  
Quarantine settings  
General application settings

Avoid unnecessary scan profiles and configuration.

Scan Results

Display useful information during and after scanning:

Files examined  
Files scanned  
Files skipped  
Threats detected  
Suspicious files  
Scan duration  
ClamAV definition version

For an individual detection:

File:  
C:\Users\User\Downloads\example.exe

ClamAV:  
THREAT DETECTED

Detection:  
Trojan.Example

Static Analysis:  
Suspicious

Action:  
QUARANTINED

For a previously scanned file:

Previously scanned  
No changes detected  
Previous result: Clean  
Skipped  
Project Structure  
xScanner  
│  
├── xScanner.exe  
│  
├── Core  
│ ├── ScanEngine  
│ ├── ScanCache  
│ ├── ScanScheduler  
│ └── ScanEscalation  
│  
├── Engines  
│ └── ClamAV  
│  
├── Analysis  
│ ├── PEAnalyzer  
│ ├── Authenticode  
│ └── Heuristics  
│  
├── Database  
│ └── SQLite  
│  
├── Quarantine  
│  
└── UI

The resulting application should feel like a small, fast malware scanner, not a second antivirus suite.

The normal workflow should be:

Install xScanner  
 ↓  
Definitions update automatically  
 ↓  
Choose Basic or Full automatic scan  
 ↓  
xScanner runs on schedule  
 ↓  
Previously checked files are efficiently skipped  
 ↓  
New/changed/suspicious files are investigated  
 ↓  
Threats are quarantined  
 ↓  
xScanner exits

That's the spec I'd hand directly to the coding agent.


xScanner Implementation Plan (Revised)
Build a lightweight Windows malware scanner written in C# / WPF (.NET 8.0 Windows) using ClamAV, SQLite, static PE analysis, quarantine, and Windows Task Scheduler integration.
User Review Required & Incorporated Feedback
•
Target Framework: .net8.0-windows with WPF.
•
ClamAV Engine: Expected at xScanner\Engines\ClamAV\ (clamscan.exe, freshclam.exe, etc.), configurable via Settings.
•
Scan Cache Logic: Tracks path, size, modification time, SHA-256, and ClamAV definition version. Unchanged files with valid results are skipped; definition updates or file modifications trigger re-evaluation.
•
Basic Scan Locations: Centralized in BasicScanLocations (Startup, RegistryPersistence, ScheduledTasks, Services, Temp, AppData, LocalAppData, Downloads, Desktop).
•
Escalation Boundaries: Explicit boundaries for suspicious file investigation (containing directory, temp/staging, persistence, recently modified related files) without execution.
•
Quarantine Safety: Atomic move into quarantine, verify copy, record DB entry, mark original as quarantined, with restricted directory permissions.
Proposed Changes & Project Structure
xScanner
│
├── xScanner.sln
├── xScanner.csproj
│
├── App.xaml
├── App.xaml.cs
│
├── Database
│   ├── ScanDatabase.cs
│   └── Models
│       ├── FileRecord.cs
│       ├── ScanRecord.cs
│       ├── DetectionRecord.cs
│       ├── DefinitionRecord.cs
│       └── QuarantineRecord.cs
│
├── Engines
│   └── ClamAV
│       └── ClamAvManager.cs
│
├── Analysis
│   ├── PEAnalyzer.cs
│   └── Heuristics.cs
│
├── Core
│   ├── FileSystem
│   │   └── FileEnumerator.cs
│   │
│   ├── ScanEngine
│   │   └── ScanOrchestrator.cs
│   │
│   ├── ScanCache
│   │   └── ScanCacheManager.cs
│   │
│   ├── ScanScheduler
│   │   └── SchedulerManager.cs
│   │
│   └── ScanEscalation
│       └── EscalationManager.cs
│
├── Quarantine
│   └── QuarantineManager.cs
│
└── UI
    ├── MainWindow.xaml
    ├── MainWindow.xaml.cs
    ├── SettingsWindow.xaml
    ├── SettingsWindow.xaml.cs
    ├── QuarantineWindow.xaml
    ├── QuarantineWindow.xaml.cs
    ├── HistoryWindow.xaml
    └── HistoryWindow.xaml.cs
Implementation Order
1.
Project + WPF shell (xScanner.csproj, xScanner.sln, App.xaml, App.xaml.cs)
2.
SQLite database & data models (ScanDatabase.cs, Models/*)
3.
ClamAV integration (ClamAvManager.cs)
4.
File enumeration & Basic Scan locations (FileEnumerator.cs)
5.
Scan/cache system (ScanCacheManager.cs, ScanOrchestrator.cs)
6.
Full Scan + recursive exclusions
7.
PE analysis (PEAnalyzer.cs, Heuristics.cs)
8.
Suspicious-file escalation (EscalationManager.cs)
9.
Quarantine (QuarantineManager.cs)
10.
Scheduler (SchedulerManager.cs, /scheduled CLI argument)
11.
WPF UI integration (MainWindow, SettingsWindow, QuarantineWindow, HistoryWindow)
12.
Testing and Polish
Verification Plan
Automated Tests
•
Build verification via dotnet build.
Manual Verification
•
Run xScanner.exe and test UI navigation, Basic Scan, ClamAV status, quarantine, and settings.


xScanner Implementation Walkthrough
xScanner — Lightweight Windows malware scanner written in C# / WPF (.NET 8.0 Windows) has been successfully built according to the specification.
Changes Made
Project Setup
•
Created xScanner.csproj targeting net8.0-windows with WPF enabled and NuGet packages (Microsoft.Data.Sqlite, CommunityToolkit.Mvvm).
•
Created xScanner.sln.
•
Created App.xaml and App.xaml.cs with headless /scheduled task runner support and UI startup.
Database & Models
•
Implemented ScanDatabase.cs using SQLite for scan caching, history, settings, exclusions, detections, and quarantine records.
•
Implemented models (FileRecord.cs, ScanRecord.cs, DetectionRecord.cs, DefinitionRecord.cs, QuarantineRecord.cs).
Engines & Analysis
•
Implemented ClamAvManager.cs for ClamAV integration (freshclam definition updates and clamscan file scanning).
•
Implemented PEAnalyzer.cs and Heuristics.cs for lightweight static PE analysis (architecture, sections, entropy, imports, suspicious APIs, Authenticode digital signatures, Writable/Executable sections).
Core Engine, Cache, Escalation, Scheduler & FileSystem
•
Implemented FileEnumerator.cs for centralized Basic Scan locations (Startup, Registry Run/RunOnce, Scheduled tasks, Services, Temp, AppData, LocalAppData, Downloads, Desktop) and Full Scan drive enumeration with recursive exclusions.
•
Implemented ScanCacheManager.cs to track path, size, modification time, SHA-256, and ClamAV definition version to efficiently skip unchanged files.
•
Implemented ScanOrchestrator.cs to coordinate scanning, progress reporting, static analysis, ClamAV detection, escalation, and quarantine.
•
Implemented EscalationManager.cs for deep investigation of suspicious files (recursive directory scanning, temp/staging inspection).
•
Implemented SchedulerManager.cs using schtasks.exe for Windows Task Scheduler integration.
Quarantine
•
Implemented QuarantineManager.cs for secure isolation of threats, atomic move with verification, restoration, and permanent deletion.
WPF User Interface
•
Implemented MainWindow.xaml / MainWindow.xaml.cs matching the clean UI wireframe specification (PC status, scan progress, Basic & Full scan controls, ClamAV definition status).
•
Implemented SettingsWindow.xaml / SettingsWindow.xaml.cs for automatic scan modes, full scan exclusions, and ClamAV paths.
•
Implemented QuarantineWindow.xaml / QuarantineWindow.xaml.cs for threat quarantine management (Restore & Delete Permanently).
•
Implemented HistoryWindow.xaml / HistoryWindow.xaml.cs for scan history and results.
Validation Results
Automated Build Verification
•
Successfully built xScanner.csproj with .NET 8.0 SDK (dotnet build xScanner.csproj), resulting in bin\Debug\net8.0-windows\xScanner.dll without any compiler or XAML errors.