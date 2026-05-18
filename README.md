# ScanLens

ScanLens is a self-contained Python web app for parsing Nmap/security scan
artifacts, extracting CVEs, and checking vendor vulnerability status for RHEL
and Ubuntu.

Everything lives in `server.py`: backend, parser, CVE checker, API, HTML, CSS,
and JavaScript. There are no third-party Python dependencies.

## Features

- Upload `.xml`, `.txt`, `.nmap`, `.json`, logs, or raw text scan artifacts.
- Create multiple in-browser workspaces and bulk parse several files into each
  workspace.
- Keep browser sessions server-side: uploads and workspace JSON are stored under
  `sessions/<session-id>/`.
- Export a workspace into a hard-to-guess `/<uuid>` report URL, with the report
  JSON stored in that session folder.
- Render exported reports as executive dashboards focused on attention-needed
  items, hiding fixed/not-affected noise from the main view.
- Parse Nmap XML, appended Nmap XML, Nmap normal text output, lightweight
  ports JSON, ssh-audit JSON, CVE inventory JSON, empty placeholders, and
  generic JSON payloads.
- Normalize hosts, ports, services, scripts, and scan summaries into one
  combined unique analysis per workspace.
- Extract CVEs from the combined workspace output, any parsed field, or raw
  artifact content.
- Check each CVE individually against:
  - Red Hat: `https://access.redhat.com/hydra/rest/securitydata/cve/{CVE-ID}.json`
  - Ubuntu: `https://ubuntu.com/security/cves/{CVE-ID}.json`
- Classify results as `Affected`, `Fixed`, `Not affected`, `Deferred`,
  `Out of support`, `Not found`, `Lookup failed`, `Not listed`, or `Unknown`.
- Light theme by default, with a dark mode toggle.
- Detailed debug logs printed in the terminal by default.

## Run Locally

```bash
python3 server.py --host 0.0.0.0 --port 8000
```

Open:

```text
http://localhost:8000
```

On Windows with the bundled Codex runtime:

```powershell
& "C:\Users\almas\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" server.py --host 127.0.0.1 --port 8000
```

## Linux Systemd Example

Create `/etc/systemd/system/scanlens.service`:

```ini
[Unit]
Description=ScanLens scan dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/scanlens
ExecStart=/usr/bin/python3 /opt/scanlens/server.py --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=3
User=scanlens
Group=scanlens

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now scanlens
sudo journalctl -u scanlens -f
```

## Repository Shape

```text
server.py
README.md
.gitignore
requirements.txt
```

Runtime uploads are written to `sessions/<session-id>/` and ignored by git.
Exported reports are stored as `sessions/<session-id>/report_<uuid>.json` and
served at `/<uuid>` with a simplified dashboard for non-technical readers.
Sample scan files may be kept locally for testing, but the application itself is
only `server.py`.
