# Raptor Guard — Windows Event Log Threat Monitoring & Dashboard

A complete end-to-end local SIEM/Threat Monitoring system that reads Windows Event Logs, detects threats using automated security rules, stores results in SQLite, and displays live events in a web dashboard.

## Quick Start Setup

1. Extract the downloaded `raptor_guard_system.zip` into a folder.
2. Open terminal in the directory and install required dependencies:
   ```bash
   pip install pywin32 flask
   ```

## Running the System

### Step 1: Start Log Collector & Security Engine (Admin Terminal)
Open PowerShell or Command Prompt **as Administrator** (required to read Windows Security logs) and run:
```bash
python main.py
```

### Step 2: Start Web Dashboard (Standard Terminal)
In a standard terminal window, run:
```bash
python app.py
```

### Step 3: View Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```
