# proctor-monitor

Consent-based test-session monitor for macOS and Windows. Run it straight from the server, nothing is saved locally:

```bash
python3 -m pip install -q psutil pynput && python3 -c "$(curl -fsSL https://raw.githubusercontent.com/Dhruv-ux-dev/proctor-monitor/main/proctor_monitor.py)" --check
```

Prints `RESULT: FLAGGED` with reasons (exit code 1) or `RESULT: CLEAN` (exit code 0).
