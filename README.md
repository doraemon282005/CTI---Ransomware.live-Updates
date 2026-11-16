# Ransomware.live telecom CTI monitor

This Python utility polls the authenticated ransomware.live API for recent records whose
organization, sector/activity, website, or group contains a configured telecom keyword.
It does not infer sector relevance from unrelated text and reports missing API fields as
`Not available in ransomware.live data`.

The ransomware.live API does not expose a universal incident-criticality field in the
queried victim response. The monitor therefore includes every confirmed telecom keyword
match rather than guessing a severity or silently excluding a potentially important event.

## Setup

1. Install Python 3.11 or newer.
2. Create an environment and install dependencies:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\python.exe -m pip install -r requirements.txt
   ```
3. Copy `.env.example` to `.env` and paste the API key into `RANSOMWARE_LIVE_API_KEY`.
4. Test manually:

   ```powershell
   .\.venv\Scripts\python.exe main.py --run-once
   ```

Generated files are under `reports\YYYY-MM-DD\` (one PDF per event) and
`reports\master_events.xlsx`. Each run fetches the recent feed again and limits the
popup/report set to events discovered within the configured reporting window (default:
6 hours), while retaining historical entries in the workbook by event ID. Older PDFs are
removed only if they were generated inside that same reporting window, and repeat runs
update the matching row instead of adding duplicates.

## Automatic scheduled operation

To run on fixed daily times (08:30, 14:30, 20:30, and 02:30 IST), open PowerShell in
the project directory and register a Windows Task Scheduler task:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install_task.ps1
```

The installer requires the virtual environment at `.venv\` and the Windows time zone
set to India Standard Time. It registers an interactive-user task so the popup can be
displayed. Rerun the installer to update the task if it was previously installed.
Manual runs remain available at any time with:

```powershell
.\.venv\Scripts\python.exe main.py --run-once
```

To configure the task manually instead, use:

- **Program:** `C:\path\to\project\.venv\Scripts\python.exe`
- **Arguments:** `C:\path\to\project\main.py --run-once`
- **Start in:** `C:\path\to\project`
- Add four daily triggers at 08:30, 14:30, 20:30, and 02:30 (Windows time zone must be IST).

The task must run in the interactive user session for the Tk popup to be visible.
If an onion proxy is available, set `ONION_PROXY=http://127.0.0.1:9050` (or the
appropriate proxy URL). Onion URLs are only included after a successful HTTP check;
without a proxy they are omitted rather than presented as working.
