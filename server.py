#!/usr/bin/env python3
"""Self-contained Nmap scan dashboard.

One file, zero third-party dependencies:
- Upload XML, TXT, NMAP, JSON, or any text-like scan artifact.
- Normalize scan data into hosts/ports/scripts.
- Extract CVEs.
- Cross-check each CVE against Red Hat or Ubuntu security endpoints.
- Serve a modern inline web UI with light mode by default and a dark theme toggle.
"""

from __future__ import annotations

import argparse
import html
import json
import logging
import os
import re
import sys
import threading
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree as ET


APP_NAME = "ScanLens"
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
LOG = logging.getLogger("scanlens")
BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"
SESSIONS_ROOT = BASE_DIR / "sessions"
SESSION_COOKIE = "scanlens_session"
SESSION_ID_RE = re.compile(r"^[a-f0-9]{32}$")
REPORT_ID_RE = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$")
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

NMAP_RUN_RE = re.compile(r"<nmaprun\b.*?</nmaprun>", re.IGNORECASE | re.DOTALL)
NMAP_TEXT_RUN_RE = re.compile(r"(?=^# Nmap .*? scan initiated|^Starting Nmap\s+)", re.IGNORECASE | re.MULTILINE)
NMAP_REPORT_RE = re.compile(r"^Nmap scan report for\s+(.+)$", re.IGNORECASE)
NMAP_PORT_RE = re.compile(
    r"^(?P<portid>\d+)/(?P<protocol>tcp|udp)\s+(?P<state>\S+)\s+(?P<service>\S+)(?:\s+(?P<details>.*))?$",
    re.IGNORECASE,
)
NMAP_INIT_RE = re.compile(r"^# Nmap (?P<version>\S+) scan initiated (?P<startstr>.*?) as: (?P<args>.*)$", re.IGNORECASE)
NMAP_DONE_RE = re.compile(r"^Nmap done:\s+(?P<summary>.*? scanned in (?P<elapsed>[\d.]+) seconds)$", re.IGNORECASE)
NMAP_DONE_HASH_RE = re.compile(
    r"^# Nmap done at (?P<timestr>.*?) -- (?P<summary>.*? scanned in (?P<elapsed>[\d.]+) seconds)$",
    re.IGNORECASE,
)
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
JSON_DOUBLE_COMMA_RE = re.compile(r"(?:,\s*){2,}")
JSON_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")

RHEL_VERSIONS = ["6", "7", "8", "9", "10"]
UBUNTU_RELEASES = {
    "18.04": ["18.04", "bionic"],
    "20.04": ["20.04", "focal"],
    "22.04": ["22.04", "jammy"],
    "24.04": ["24.04", "noble"],
    "26.04": ["26.04", "resolute"],
}
GROQ_BASE_URL_DEFAULT = "https://api.groq.com/openai/v1"
GROQ_MODEL_DEFAULT = "openai/gpt-oss-20b"
GROQ_TIMEOUT_SECONDS = 35
GROQ_MIN_INTERVAL_SECONDS = 2.0
GROQ_MAX_ATTEMPTS = 2
GROQ_VENDOR_JSON_LIMIT = 18000
GROQ_RATE_LOCK = threading.Lock()
GROQ_NEXT_ALLOWED_AT = 0.0


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def load_env_file(path: Path = ENV_PATH) -> dict[str, str]:
    loaded: dict[str, str] = {}
    if not path.exists():
        LOG.info("env_file missing path=%s", session_relative(path))
        return loaded
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            LOG.warning("env_file ignored invalid_key line=%s path=%s", line_no, session_relative(path))
            continue
        if key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    LOG.info("env_file loaded path=%s keys=%s", session_relative(path), sorted(loaded))
    return loaded


def env_truthy(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def new_session_id() -> str:
    return uuid.uuid4().hex


def new_report_id() -> str:
    return str(uuid.uuid4())


def sanitize_filename(filename: str) -> str:
    name = Path(filename or "uploaded-scan").name
    name = SAFE_FILENAME_RE.sub("_", name).strip("._")
    return name or "uploaded-scan"


def session_directory(session_id: str) -> Path:
    if not SESSION_ID_RE.fullmatch(session_id):
        raise ValueError("Invalid session id.")
    root = SESSIONS_ROOT.resolve()
    path = (root / session_id).resolve()
    if root != path and root not in path.parents:
        raise ValueError("Session path escaped sessions directory.")
    path.mkdir(parents=True, exist_ok=True)
    return path


def session_relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(BASE_DIR.resolve()).as_posix()
    except ValueError:
        return str(path)


def unique_session_file(session_id: str, filename: str, index: int) -> Path:
    directory = session_directory(session_id)
    safe_name = sanitize_filename(filename)
    base = f"{utc_stamp()}_{index:03d}_{safe_name}"
    path = directory / base
    counter = 1
    while path.exists():
        stem = Path(base).stem
        suffix = Path(base).suffix
        path = directory / f"{stem}_{counter}{suffix}"
        counter += 1
    return path


def write_json_file(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def update_session_manifest(session_id: str, uploads: list[dict[str, Any]], workspace: dict[str, Any] | None = None) -> None:
    directory = session_directory(session_id)
    manifest_path = directory / "session.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}
    else:
        manifest = {}
    manifest.setdefault("session_id", session_id)
    manifest.setdefault("created_at", utc_stamp())
    manifest["updated_at"] = utc_stamp()
    manifest.setdefault("uploads", [])
    manifest.setdefault("workspaces", [])
    manifest.setdefault("reports", [])
    manifest["uploads"].extend(uploads)
    if workspace:
        if workspace.get("kind") == "report":
            manifest["reports"].append(workspace)
        else:
            manifest["workspaces"].append(workspace)
    write_json_file(manifest_path, manifest)


def report_path(session_id: str, report_id: str) -> Path:
    if not REPORT_ID_RE.fullmatch(report_id):
        raise ValueError("Invalid report id.")
    return session_directory(session_id) / f"report_{report_id}.json"


def find_report(report_id: str) -> Path | None:
    if not REPORT_ID_RE.fullmatch(report_id):
        return None
    root = SESSIONS_ROOT.resolve()
    if not root.exists():
        return None
    for candidate in root.glob(f"*/report_{report_id}.json"):
        resolved = candidate.resolve()
        if root == resolved or root in resolved.parents:
            return resolved
    return None


def coerce(value: str | None) -> Any:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return ""
    if re.fullmatch(r"[+-]?\d+", text):
        try:
            return int(text)
        except ValueError:
            return value
    if re.fullmatch(r"[+-]?(?:\d+\.\d*|\d*\.\d+)", text):
        try:
            return float(text)
        except ValueError:
            return value
    return value


def attrs(element: ET.Element) -> dict[str, Any]:
    string_keys = {"version", "xmloutputversion"}
    return {key: value if key in string_keys else coerce(value) for key, value in element.attrib.items()}


def text_of(element: ET.Element) -> str | None:
    text = element.text.strip() if element.text else ""
    return text or None


def children(element: ET.Element, tag: str) -> list[ET.Element]:
    return list(element.findall(tag))


def child(element: ET.Element, tag: str) -> ET.Element | None:
    return element.find(tag)


def normalize_service_name(name: str) -> str:
    return name.rstrip("?") or name


def parse_nse_value(element: ET.Element) -> Any:
    if element.tag == "elem":
        value = text_of(element)
        if element.attrib:
            data = attrs(element)
            data["value"] = coerce(value) if isinstance(value, str) else value
            return data
        return coerce(value) if isinstance(value, str) else value

    if element.tag != "table":
        return generic_xml(element)

    keyed: dict[str, Any] = {}
    values: list[Any] = []
    for nested in list(element):
        parsed = parse_nse_value(nested)
        key = nested.attrib.get("key")
        if key:
            value = parsed.get("value") if isinstance(parsed, dict) and set(parsed) == {"key", "value"} else parsed
            if key in keyed:
                if not isinstance(keyed[key], list):
                    keyed[key] = [keyed[key]]
                keyed[key].append(value)
            else:
                keyed[key] = value
        else:
            values.append(parsed)

    table_attrs = attrs(element)
    if table_attrs:
        out: dict[str, Any] = {"attributes": table_attrs}
        if keyed:
            out["items"] = keyed
        if values:
            out["values"] = values
        return out
    if keyed and not values:
        return keyed
    if values and not keyed:
        return values
    return {"items": keyed, "values": values}


def generic_xml(element: ET.Element) -> Any:
    if not list(element) and not element.attrib:
        return coerce(text_of(element))
    data: dict[str, Any] = {}
    if element.attrib:
        data["attributes"] = attrs(element)
    text = text_of(element)
    if text:
        data["text"] = coerce(text)
    for nested in list(element):
        parsed = generic_xml(nested)
        if nested.tag in data:
            if not isinstance(data[nested.tag], list):
                data[nested.tag] = [data[nested.tag]]
            data[nested.tag].append(parsed)
        else:
            data[nested.tag] = parsed
    return data


def parse_xml_runs(scan_text: str) -> list[ET.Element]:
    chunks = NMAP_RUN_RE.findall(scan_text)
    if not chunks:
        try:
            root = ET.fromstring(scan_text)
        except ET.ParseError as exc:
            raise ValueError(f"Could not parse XML: {exc}") from exc
        if root.tag != "nmaprun":
            raise ValueError(f"Expected nmaprun XML, got {root.tag!r}.")
        return [root]

    roots: list[ET.Element] = []
    for index, chunk in enumerate(chunks, start=1):
        try:
            roots.append(ET.fromstring(chunk))
        except ET.ParseError as exc:
            raise ValueError(f"Could not parse appended nmaprun #{index}: {exc}") from exc
    return roots


def parse_xml_port(port: ET.Element) -> dict[str, Any]:
    state = child(port, "state")
    service_node = child(port, "service")
    service = attrs(service_node) if service_node is not None else {}
    if service_node is not None:
        service["cpes"] = [item for item in (text_of(cpe) for cpe in children(service_node, "cpe")) if item]
        if "name" in service:
            service["name"] = normalize_service_name(str(service["name"]))

    item = attrs(port)
    if str(item.get("portid", "")).isdigit():
        item["portid"] = int(item["portid"])
    item["state"] = attrs(state) if state is not None else {}
    item["service"] = service
    scripts = []
    for script in children(port, "script"):
        parsed = attrs(script)
        nested = [parse_nse_value(node) for node in list(script)]
        if nested:
            parsed["data"] = nested
        scripts.append(parsed)
    if scripts:
        item["scripts"] = scripts
    return item


def parse_xml_host(host: ET.Element) -> dict[str, Any]:
    ports_node = child(host, "ports")
    ports: list[dict[str, Any]] = []
    extraports: list[dict[str, Any]] = []
    if ports_node is not None:
        for extraport in children(ports_node, "extraports"):
            data = attrs(extraport)
            reasons = [attrs(reason) for reason in children(extraport, "extrareasons")]
            if reasons:
                data["reasons"] = reasons
            extraports.append(data)
        ports = [parse_xml_port(port) for port in children(ports_node, "port")]

    data = attrs(host)
    status = child(host, "status")
    data["status"] = attrs(status) if status is not None else {"state": "unknown"}
    data["addresses"] = [attrs(address) for address in children(host, "address")]
    hostnames_node = child(host, "hostnames")
    data["hostnames"] = [attrs(name) for name in children(hostnames_node, "hostname")] if hostnames_node is not None else []
    data["ports"] = ports
    data["extraports"] = extraports

    os_node = child(host, "os")
    if os_node is not None:
        matches = []
        for match in children(os_node, "osmatch"):
            match_data = attrs(match)
            classes = []
            for osclass in children(match, "osclass"):
                class_data = attrs(osclass)
                class_data["cpes"] = [item for item in (text_of(cpe) for cpe in children(osclass, "cpe")) if item]
                classes.append(class_data)
            if classes:
                match_data["classes"] = classes
            matches.append(match_data)
        if matches:
            data["os_matches"] = matches
    return data


def parse_xml_run(root: ET.Element, index: int) -> dict[str, Any]:
    data = attrs(root)
    data["run_index"] = index
    data["source_format"] = "xml"
    data["scaninfo"] = [attrs(scan) for scan in children(root, "scaninfo")]
    data["hosts"] = [parse_xml_host(host) for host in children(root, "host")]
    runstats = child(root, "runstats")
    if runstats is not None:
        data["runstats"] = {}
        finished = child(runstats, "finished")
        hosts = child(runstats, "hosts")
        if finished is not None:
            data["runstats"]["finished"] = attrs(finished)
        if hosts is not None:
            data["runstats"]["hosts"] = attrs(hosts)
    return data


def split_text_runs(text: str) -> list[str]:
    cleaned = strip_ansi(text)
    parts = [part.strip() for part in NMAP_TEXT_RUN_RE.split(cleaned) if part.strip()]
    return parts or [cleaned.strip()]


def parse_target(target: str) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    hostnames: list[dict[str, Any]] = []
    match = re.fullmatch(r"(.+?)\s+\(([^)]+)\)", target.strip())
    if match:
        hostnames.append({"name": match.group(1).strip(), "type": "user"})
        address = match.group(2).strip()
    else:
        address = target.strip()
    addrtype = "ipv6" if ":" in address else "ipv4"
    return address, [{"addr": address, "addrtype": addrtype}], hostnames


def parse_script_line(line: str) -> tuple[str | None, str, bool] | None:
    stripped = line.lstrip()
    if not stripped.startswith("|"):
        return None
    content = stripped[1:]
    if content.startswith("_"):
        content = content[1:]
    if content.startswith(" "):
        content = content[1:]
    is_continuation = content.startswith(" ") or content.startswith("_")
    content = content.strip()
    if not content:
        return None
    if not is_continuation and ":" in content:
        script_id, output = content.split(":", 1)
        return script_id.strip(), output.strip(), True
    return None, content, False


def parse_text_done(line: str) -> dict[str, Any] | None:
    stripped = line.strip()
    for pattern in (NMAP_DONE_HASH_RE, NMAP_DONE_RE):
        match = pattern.match(stripped)
        if not match:
            continue
        data = match.groupdict()
        finished = {
            "summary": stripped.lstrip("# "),
            "elapsed": float(data["elapsed"]),
            "exit": "success",
        }
        if data.get("timestr"):
            finished["timestr"] = data["timestr"]
        return {"finished": finished}
    return None


def parse_text_host(lines: list[str]) -> dict[str, Any] | None:
    match = NMAP_REPORT_RE.match(lines[0].strip()) if lines else None
    if not match:
        return None

    address, addresses, hostnames = parse_target(match.group(1))
    host: dict[str, Any] = {
        "address": address,
        "addresses": addresses,
        "hostnames": hostnames,
        "status": {"state": "unknown"},
        "ports": [],
        "extraports": [],
        "notes": [],
    }
    current_port: dict[str, Any] | None = None
    in_ports_table = False
    os_matches = []

    for raw_line in lines[1:]:
        line = strip_ansi(raw_line.rstrip())
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if lower.startswith("host is up"):
            host["status"] = {"state": "up", "details": stripped}
            continue
        if lower.startswith("host is down"):
            host["status"] = {"state": "down", "details": stripped}
            continue
        if lower.startswith("not shown:"):
            host["extraports"].append({"summary": stripped})
            continue
        if stripped.upper().startswith("PORT") and "STATE" in stripped.upper():
            in_ports_table = True
            continue

        port_match = NMAP_PORT_RE.match(stripped)
        if in_ports_table and port_match:
            details = (port_match.group("details") or "").strip()
            service = {"name": normalize_service_name(port_match.group("service"))}
            if details:
                service["details"] = details
            current_port = {
                "protocol": port_match.group("protocol").lower(),
                "portid": int(port_match.group("portid")),
                "state": {"state": port_match.group("state")},
                "service": service,
                "scripts": [],
            }
            host["ports"].append(current_port)
            continue

        script = parse_script_line(line)
        if script and current_port is not None:
            script_id, output, is_new = script
            if is_new and script_id:
                current_port["scripts"].append({"id": script_id, "output": output})
            elif current_port["scripts"]:
                current_port["scripts"][-1]["output"] = (current_port["scripts"][-1].get("output", "") + "\n" + output).strip()
            continue

        if lower.startswith(("running:", "os details:", "aggressive os guesses:", "device type:")) and ":" in stripped:
            key, value = stripped.split(":", 1)
            os_matches.append({"source": key.strip(), "name": value.strip()})
            continue
        host["notes"].append(stripped)

    if os_matches:
        host["os_matches"] = os_matches
    if not host["notes"]:
        host.pop("notes", None)
    return host


def parse_text_run(text: str, index: int) -> dict[str, Any]:
    lines = text.splitlines()
    run: dict[str, Any] = {"run_index": index, "scanner": "nmap", "source_format": "text", "scaninfo": [], "hosts": []}
    for line in lines[:10]:
        init = NMAP_INIT_RE.match(line.strip())
        if init:
            run.update({"version": init.group("version"), "startstr": init.group("startstr"), "args": init.group("args")})
            break
        if line.lower().startswith("starting nmap"):
            run["startstr"] = line.strip()
            break

    current_host_lines: list[str] = []
    for raw_line in lines:
        if NMAP_REPORT_RE.match(raw_line.strip()):
            if current_host_lines:
                parsed = parse_text_host(current_host_lines)
                if parsed:
                    run["hosts"].append(parsed)
            current_host_lines = [raw_line]
            continue
        done = parse_text_done(raw_line)
        if done:
            run["runstats"] = done
            continue
        if current_host_lines:
            current_host_lines.append(raw_line)

    if current_host_lines:
        parsed = parse_text_host(current_host_lines)
        if parsed:
            run["hosts"].append(parsed)
    return run


def parse_text_runs(text: str) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for run_text in split_text_runs(text):
        if not run_text or "Nmap scan report for" not in run_text:
            continue
        run = parse_text_run(run_text, len(runs) + 1)
        if run["hosts"]:
            runs.append(run)
    if runs:
        return runs
    return [{
        "run_index": 1,
        "source_format": "text",
        "scanner": "unknown",
        "scaninfo": [],
        "hosts": [],
        "raw_text": strip_ansi(text),
    }]


def looks_like_xml(text: str) -> bool:
    stripped = text.lstrip()
    return stripped.startswith("<") or "<nmaprun" in text[:3000].lower()


def primary_address(host: dict[str, Any]) -> str | None:
    for address in host.get("addresses", []):
        if address.get("addrtype") == "ipv4":
            return str(address.get("addr"))
    if host.get("addresses"):
        return str(host["addresses"][0].get("addr"))
    if host.get("address"):
        return str(host["address"])
    return None


def merge_non_empty(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base or {})
    for key, value in (incoming or {}).items():
        if value in (None, "", [], {}):
            continue
        merged[key] = value
    return merged


def flatten_hosts(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    hosts_by_addr: dict[str, dict[str, Any]] = {}
    for run in runs:
        for host in run.get("hosts", []):
            address = primary_address(host)
            if not address:
                continue
            current = hosts_by_addr.setdefault(address, {
                "address": address,
                "addresses": host.get("addresses", []),
                "hostnames": [],
                "status": host.get("status", {}),
                "ports": {},
                "os_matches": [],
                "seen_in_runs": [],
            })
            current["seen_in_runs"].append(run.get("run_index", 1))
            current["hostnames"].extend(host.get("hostnames", []))
            if host.get("status"):
                current["status"] = host["status"]
            for match in host.get("os_matches", []):
                if match not in current["os_matches"]:
                    current["os_matches"].append(match)
            for port in host.get("ports", []):
                key = f"{port.get('protocol')}/{port.get('portid')}"
                stored = current["ports"].setdefault(key, {
                    "protocol": port.get("protocol"),
                    "portid": port.get("portid"),
                    "state": port.get("state", {}),
                    "service": port.get("service", {}),
                    "scripts": [],
                    "seen_in_runs": [],
                })
                stored["state"] = port.get("state", stored["state"])
                stored["service"] = merge_non_empty(stored.get("service", {}), port.get("service", {}))
                stored["seen_in_runs"].append(run.get("run_index", 1))
                for script in port.get("scripts", []):
                    if script not in stored["scripts"]:
                        stored["scripts"].append(script)

    flattened = []
    for host in hosts_by_addr.values():
        host["seen_in_runs"] = sorted(set(host["seen_in_runs"]))
        unique_hostnames = []
        for item in host["hostnames"]:
            if item not in unique_hostnames:
                unique_hostnames.append(item)
        host["hostnames"] = unique_hostnames
        ports = list(host["ports"].values())
        for port in ports:
            port["seen_in_runs"] = sorted(set(port["seen_in_runs"]))
        host["ports"] = sorted(ports, key=lambda item: (str(item.get("protocol", "")), int(item.get("portid") or 0)))
        flattened.append(host)
    return sorted(flattened, key=lambda item: item["address"])


def empty_analysis(source_name: str, input_type: str = "empty") -> dict[str, Any]:
    return {
        "summary": build_summary(source_name, input_type, [], [], ""),
        "hosts": [],
        "runs": [],
        "raw": "",
    }


def build_summary(source_name: str, input_type: str, runs: list[dict[str, Any]], hosts: list[dict[str, Any]], raw: object = None) -> dict[str, Any]:
    state_counts = Counter()
    service_counts = Counter()
    open_ports = 0
    script_count = 0
    for host in hosts:
        for port in host.get("ports", []):
            state = port.get("state", {}).get("state", "unknown")
            state_counts[state] += 1
            if state == "open":
                open_ports += 1
            service = port.get("service", {}).get("name")
            if service:
                service_counts[str(service)] += 1
            script_count += len(port.get("scripts", []))
    return {
        "source_file": source_name,
        "input_type": input_type,
        "run_count": len(runs),
        "host_count": len(hosts),
        "open_port_count": open_ports,
        "script_count": script_count,
        "cve_count": len(extract_cves(raw if raw is not None else {"runs": runs, "hosts": hosts})),
        "port_state_counts": dict(sorted(state_counts.items())),
        "service_counts": dict(sorted(service_counts.items())),
    }


def load_json_lenient(scan_text: str, source_name: str) -> Any:
    try:
        return json.loads(scan_text)
    except json.JSONDecodeError as first_error:
        cleaned = JSON_DOUBLE_COMMA_RE.sub(",", scan_text)
        cleaned = JSON_TRAILING_COMMA_RE.sub(r"\1", cleaned)
        if cleaned == scan_text:
            raise
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            raise first_error
        LOG.warning("json_repair applied file=%s original_error=%s", source_name, first_error)
        return data


def normalize_json_port(port: dict[str, Any]) -> dict[str, Any]:
    port_id = port.get("portid", port.get("port", port.get("number")))
    protocol = str(port.get("protocol", port.get("proto", "tcp")) or "tcp").lower()
    state_value = port.get("state", port.get("status", port.get("state_state", "unknown")))
    state = state_value if isinstance(state_value, dict) else {"state": str(state_value or "unknown")}
    if port.get("reason") and isinstance(state, dict):
        state.setdefault("reason", port.get("reason"))
    if port.get("ttl") and isinstance(state, dict):
        state.setdefault("reason_ttl", port.get("ttl"))

    service_value = port.get("service", port.get("name", ""))
    service = service_value if isinstance(service_value, dict) else {"name": normalize_service_name(str(service_value or ""))}
    if not service.get("name") and port.get("product"):
        service["name"] = normalize_service_name(str(port.get("product")))

    out = {
        "protocol": protocol,
        "portid": int(port_id) if str(port_id).isdigit() else port_id,
        "state": state,
        "service": service,
        "scripts": port.get("scripts", []),
    }
    for key in ("timestamp", "reason", "ttl", "raw"):
        if key in port:
            out[key] = port[key]
    return out


def normalize_json_host(record: dict[str, Any]) -> dict[str, Any] | None:
    address = record.get("ip") or record.get("address") or record.get("host") or record.get("target")
    if not address and isinstance(record.get("addresses"), list) and record["addresses"]:
        address = record["addresses"][0].get("addr") if isinstance(record["addresses"][0], dict) else record["addresses"][0]
    if not address:
        return None
    address = str(address)
    host = {
        "address": address,
        "addresses": record.get("addresses") or [{"addr": address, "addrtype": "ipv6" if ":" in address else "ipv4"}],
        "hostnames": record.get("hostnames", []),
        "status": record.get("status") if isinstance(record.get("status"), dict) else {"state": record.get("status", "up")},
        "ports": [normalize_json_port(port) for port in record.get("ports", []) if isinstance(port, dict)],
        "extraports": record.get("extraports", []),
    }
    if record.get("os_matches"):
        host["os_matches"] = record["os_matches"]
    return host


def has_json_host_shape(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(({"ip", "address", "host", "target"} & set(value)) and isinstance(value.get("ports", []), list))
    return False


def normalize_json_scan(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | None:
    records: list[dict[str, Any]]
    if isinstance(data, list) and any(has_json_host_shape(item) for item in data):
        records = [item for item in data if isinstance(item, dict)]
    elif isinstance(data, dict) and has_json_host_shape(data):
        records = [data]
    elif isinstance(data, dict) and isinstance(data.get("hosts"), list):
        hosts = [normalize_json_host(item) for item in data["hosts"] if isinstance(item, dict)]
        hosts = [host for host in hosts if host]
        runs = [{"run_index": 1, "source_format": "json", "scanner": data.get("scanner", "json"), "scaninfo": [], "hosts": hosts, "raw_json": data}]
        return runs, flatten_hosts(runs)
    else:
        return None

    runs = []
    for index, record in enumerate(records, start=1):
        host = normalize_json_host(record)
        if not host:
            continue
        run = {
            "run_index": index,
            "source_format": "json",
            "scanner": record.get("scanner", "json"),
            "start": record.get("timestamp") or record.get("start"),
            "scaninfo": [],
            "hosts": [host],
        }
        runs.append(run)
    return runs, flatten_hosts(runs)


def looks_like_ssh_audit(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    markers = {"banner", "kex", "key", "enc", "mac", "fingerprints", "recommendations", "target"}
    return bool(markers & set(data)) and any(key in data for key in ("kex", "key", "enc", "mac", "banner"))


def parse_ssh_audit_target(data: dict[str, Any]) -> tuple[str, int]:
    target = str(data.get("target") or data.get("host") or data.get("hostname") or data.get("ip") or "unknown-host").strip()
    port = data.get("port") or 22
    if target.startswith("[") and "]:" in target:
        host_part, port_part = target.rsplit(":", 1)
        target = host_part.strip("[]")
        if str(port_part).isdigit():
            port = int(port_part)
    elif target.count(":") == 1:
        host_part, port_part = target.rsplit(":", 1)
        if port_part.isdigit():
            target = host_part
            port = int(port_part)
    return target or "unknown-host", int(port) if str(port).isdigit() else 22


def ssh_audit_service(banner: Any) -> dict[str, Any]:
    service = {"name": "ssh"}
    if isinstance(banner, dict):
        raw = str(banner.get("raw") or "").strip()
        software = str(banner.get("software") or "").strip()
        protocol = str(banner.get("protocol") or "").strip()
        if software:
            product, _, version = software.replace("_", " ").partition(" ")
            service["product"] = product or software
            if version:
                service["version"] = version
        if raw:
            service["details"] = raw
        if protocol:
            service["extrainfo"] = f"protocol {protocol}"
    return service


def note_lines(notes: Any) -> list[str]:
    lines: list[str] = []
    if isinstance(notes, dict):
        for level in ("fail", "warn", "info"):
            values = notes.get(level) or []
            if isinstance(values, str):
                values = [values]
            for value in values:
                lines.append(f"{level.upper()}: {value}")
    elif isinstance(notes, list):
        lines.extend(str(item) for item in notes)
    elif notes:
        lines.append(str(notes))
    return lines


def ssh_audit_algorithm_script(script_id: str, title: str, algorithms: Any) -> dict[str, Any] | None:
    if not isinstance(algorithms, list) or not algorithms:
        return None
    lines = [title]
    for item in algorithms:
        if not isinstance(item, dict):
            lines.append(f"- {item}")
            continue
        name = item.get("algorithm") or item.get("name") or "unknown"
        suffix = f" ({item.get('keysize')} bits)" if item.get("keysize") else ""
        lines.append(f"- {name}{suffix}")
        for line in note_lines(item.get("notes")):
            lines.append(f"  {line}")
    return {"id": script_id, "output": "\n".join(lines)}


def ssh_audit_fingerprint_script(fingerprints: Any) -> dict[str, Any] | None:
    if not isinstance(fingerprints, list) or not fingerprints:
        return None
    lines = ["Host key fingerprints"]
    for item in fingerprints:
        if isinstance(item, dict):
            lines.append(f"- {item.get('hostkey', 'unknown')} {item.get('hash_alg', '')}: {item.get('hash', '')}".strip())
    return {"id": "ssh-audit-fingerprints", "output": "\n".join(lines)}


def ssh_audit_recommendation_script(recommendations: Any) -> dict[str, Any] | None:
    if not isinstance(recommendations, dict) or not recommendations:
        return None
    lines = ["ssh-audit recommendations"]
    for severity, actions in recommendations.items():
        if not isinstance(actions, dict):
            continue
        for action, groups in actions.items():
            if not isinstance(groups, dict):
                continue
            for group, items in groups.items():
                if not isinstance(items, list):
                    continue
                for item in items:
                    name = item.get("name") if isinstance(item, dict) else item
                    notes = item.get("notes") if isinstance(item, dict) else ""
                    detail = f" - {notes}" if notes else ""
                    lines.append(f"- {severity.upper()} {action.upper()} {group}: {name}{detail}")
    return {"id": "ssh-audit-recommendations", "output": "\n".join(lines)}


def normalize_ssh_audit_json(data: dict[str, Any], source_name: str) -> dict[str, Any]:
    address, port_id = parse_ssh_audit_target(data)
    scripts = []
    banner = data.get("banner")
    if isinstance(banner, dict):
        scripts.append({"id": "ssh-audit-banner", "output": json.dumps(banner, indent=2, ensure_ascii=False)})
    for script_id, title, key in (
        ("ssh-audit-kex", "Key exchange algorithms", "kex"),
        ("ssh-audit-host-keys", "Host key algorithms", "key"),
        ("ssh-audit-encryption", "Encryption algorithms", "enc"),
        ("ssh-audit-mac", "MAC algorithms", "mac"),
        ("ssh-audit-compression", "Compression algorithms", "compression"),
    ):
        script = ssh_audit_algorithm_script(script_id, title, data.get(key))
        if script:
            scripts.append(script)
    for script in (
        ssh_audit_fingerprint_script(data.get("fingerprints")),
        ssh_audit_recommendation_script(data.get("recommendations")),
    ):
        if script:
            scripts.append(script)
    if data.get("additional_notes"):
        scripts.append({"id": "ssh-audit-notes", "output": "\n\n".join(str(item) for item in data.get("additional_notes") or [])})
    if data.get("cves"):
        scripts.append({"id": "ssh-audit-cves", "output": json.dumps(data.get("cves"), indent=2, ensure_ascii=False)})

    host = {
        "address": address,
        "addresses": [{"addr": address, "addrtype": "ipv6" if ":" in address else "ipv4"}],
        "hostnames": [],
        "status": {"state": "up"},
        "ports": [{
            "protocol": "tcp",
            "portid": port_id,
            "state": {"state": "open"},
            "service": ssh_audit_service(data.get("banner")),
            "scripts": scripts,
        }],
        "extraports": [],
    }
    run = {
        "run_index": 1,
        "source_format": "ssh-audit-json",
        "scanner": "ssh-audit",
        "scaninfo": [{"type": "ssh-audit", "protocol": "tcp", "services": str(port_id)}],
        "hosts": [host],
        "raw_json": data,
    }
    hosts = flatten_hosts([run])
    cve_inventory = [{"cve": cve, "summary": "Found in ssh-audit output."} for cve in extract_cves(data)]
    out = {"summary": build_summary(source_name, "ssh-audit-json", [run], hosts, data), "hosts": hosts, "runs": [run], "raw": data}
    if cve_inventory:
        out["cve_inventory"] = cve_inventory
    return out


def collect_cve_inventory(data: Any) -> list[dict[str, Any]]:
    inventory: dict[str, dict[str, Any]] = {}

    def english_description(raw_nvd: Any) -> str:
        try:
            descriptions = raw_nvd["vulnerabilities"][0]["cve"].get("descriptions", [])
        except (KeyError, IndexError, TypeError):
            return ""
        for item in descriptions:
            if item.get("lang") == "en":
                return str(item.get("value") or "")
        return ""

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            cve = normalize_cve(item.get("cve") or item.get("id") or item.get("name") or "")
            if cve:
                record = inventory.setdefault(cve, {"cve": cve})
                if item.get("nvd_severity"):
                    record["severity"] = item["nvd_severity"]
                if item.get("base_score") is not None:
                    record["score"] = item["base_score"]
                summary = item.get("summary") or item.get("description") or english_description(item.get("raw_nvd"))
                if summary:
                    record["summary"] = summary
            for nested in item.values():
                walk(nested)
        elif isinstance(item, list):
            for nested in item:
                walk(nested)

    walk(data)
    return sorted(inventory.values(), key=lambda item: item["cve"])


def normalize_existing_json(data: Any, source_name: str) -> dict[str, Any]:
    if isinstance(data, dict) and {"summary", "hosts", "runs"}.issubset(data):
        out = data
        out.setdefault("summary", {})
        out["summary"].setdefault("source_file", source_name)
        out["summary"].setdefault("input_type", "json")
        out["summary"]["cve_count"] = len(extract_cves(out))
        return out
    if looks_like_ssh_audit(data):
        return normalize_ssh_audit_json(data, source_name)
    scan = normalize_json_scan(data)
    if scan:
        runs, hosts = scan
        return {"summary": build_summary(source_name, "json", runs, hosts, data), "hosts": hosts, "runs": runs, "raw": data}
    cve_inventory = collect_cve_inventory(data)
    runs = [{"run_index": 1, "source_format": "json", "scanner": "unknown", "scaninfo": [], "hosts": [], "raw_json": data}]
    hosts: list[dict[str, Any]] = []
    out = {"summary": build_summary(source_name, "json", runs, hosts, data), "hosts": hosts, "runs": runs, "raw": data}
    if cve_inventory:
        out["cve_inventory"] = cve_inventory
    return out


def renumber_runs(runs: list[dict[str, Any]], source_name: str, start_index: int) -> list[dict[str, Any]]:
    renumbered = []
    for offset, run in enumerate(runs, start=0):
        item = dict(run)
        item["original_run_index"] = run.get("run_index")
        item["run_index"] = start_index + offset
        item["source_file"] = source_name
        for host in item.get("hosts", []):
            if isinstance(host, dict):
                host.setdefault("source_file", source_name)
        renumbered.append(item)
    return renumbered


def merge_parsed_documents(documents: list[dict[str, Any]], workspace_name: str = "Workspace") -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    files = []
    cve_inventory: dict[str, dict[str, Any]] = {}
    raw_items = []

    for document in documents:
        summary = document.get("summary", {})
        source_name = str(summary.get("source_file") or "uploaded file")
        source_runs = document.get("runs", [])
        files.append({
            "name": source_name,
            "input_type": summary.get("input_type", "unknown"),
            "run_count": summary.get("run_count", len(source_runs)),
            "host_count": summary.get("host_count", 0),
            "open_port_count": summary.get("open_port_count", 0),
            "script_count": summary.get("script_count", 0),
            "cve_count": summary.get("cve_count", 0),
        })
        runs.extend(renumber_runs(source_runs, source_name, len(runs) + 1))
        raw_items.append({"source_file": source_name, "data": document.get("raw", document)})
        for item in document.get("cve_inventory", []):
            cve = normalize_cve(item.get("cve", ""))
            if cve and cve not in cve_inventory:
                cve_inventory[cve] = item

    hosts = flatten_hosts(runs)
    raw = {"files": raw_items, "cve_inventory": list(cve_inventory.values())}
    merged = {
        "summary": build_summary(workspace_name, "workspace", runs, hosts, {"runs": runs, "raw": raw}),
        "hosts": hosts,
        "runs": runs,
        "files": files,
        "raw": raw,
    }
    if cve_inventory:
        merged["cve_inventory"] = sorted(cve_inventory.values(), key=lambda item: item["cve"])
    merged["summary"]["file_count"] = len(files)
    return merged


def convert_content(scan_text: str, source_name: str = "uploaded file") -> dict[str, Any]:
    if not scan_text.strip():
        LOG.warning("empty_input file=%s", source_name)
        return empty_analysis(source_name)

    stripped = scan_text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return normalize_existing_json(load_json_lenient(scan_text, source_name), source_name)
        except json.JSONDecodeError:
            LOG.debug("json parse failed; falling back to text parser", exc_info=True)

    if looks_like_xml(scan_text):
        roots = parse_xml_runs(scan_text)
        runs = [parse_xml_run(root, index) for index, root in enumerate(roots, start=1)]
        hosts = flatten_hosts(runs)
        return {"summary": build_summary(source_name, "xml", runs, hosts), "hosts": hosts, "runs": runs}

    runs = parse_text_runs(scan_text)
    hosts = flatten_hosts(runs)
    return {"summary": build_summary(source_name, "text", runs, hosts, scan_text), "hosts": hosts, "runs": runs}


def normalize_cve(value: object) -> str | None:
    match = CVE_RE.search(str(value))
    return match.group(0).upper() if match else None


def extract_cves(value: object) -> list[str]:
    found: set[str] = set()

    def walk(item: object) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                walk(key)
                walk(nested)
        elif isinstance(item, list):
            for nested in item:
                walk(nested)
        elif item is not None:
            for match in CVE_RE.findall(str(item)):
                found.add(match.upper())

    walk(value)
    return sorted(found)


def report_risk(summary: dict[str, Any], cves: list[str], check_results: list[dict[str, Any]]) -> tuple[str, str]:
    classifications = [classify_status(item.get("classification") or item.get("status")) for item in check_results if isinstance(item, dict)]
    if any(item == "Affected" for item in classifications):
        return "Action needed", "At least one checked vulnerability appears to affect the selected operating system version."
    if cves and not check_results:
        return "Review needed", "The scan found CVE references, but they have not all been checked against the chosen operating system."
    if cves:
        return "Monitor", "The scan found CVE references. Review the listed items and keep the system patched."
    if int(summary.get("open_port_count") or 0) > 0:
        return "No CVEs found", "Open network services were found, but this report did not identify CVE references in the uploaded evidence."
    return "Low signal", "The uploaded evidence did not show open ports or CVE references."


def summarize_report_for_people(report: dict[str, Any]) -> dict[str, Any]:
    workspace = report.get("workspace") if isinstance(report.get("workspace"), dict) else {}
    summary = workspace.get("summary", {}) if isinstance(workspace.get("summary"), dict) else {}
    check_results = report.get("check_results") if isinstance(report.get("check_results"), list) else []
    cves = report.get("cves") if isinstance(report.get("cves"), list) else extract_cves(workspace)
    risk, meaning = report_risk(summary, cves, check_results)
    affected = [item for item in check_results if classify_status(item.get("classification") or item.get("status")) == "Affected"]
    fixed = [item for item in check_results if classify_status(item.get("classification") or item.get("status")) == "Fixed"]
    not_affected = [item for item in check_results if classify_status(item.get("classification") or item.get("status")) == "Not affected"]
    return {
        "risk": risk,
        "meaning": meaning,
        "files": summary.get("file_count", 0),
        "hosts": summary.get("host_count", 0),
        "open_ports": summary.get("open_port_count", 0),
        "cves": len(cves),
        "affected": len(affected),
        "fixed": len(fixed),
        "not_affected": len(not_affected),
    }


def h(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def html_list(items: object) -> str:
    if not isinstance(items, list) or not items:
        return "<li>No specific items were generated.</li>"
    return "".join(f"<li>{h(item)}</li>" for item in items[:5])


def render_public_report(report: dict[str, Any]) -> str:
    people = summarize_report_for_people(report)
    workspace = report.get("workspace") if isinstance(report.get("workspace"), dict) else {}
    summary = workspace.get("summary", {}) if isinstance(workspace.get("summary"), dict) else {}
    hosts = workspace.get("hosts", []) if isinstance(workspace.get("hosts"), list) else []
    files = workspace.get("files", []) if isinstance(workspace.get("files"), list) else []
    cves = report.get("cves") if isinstance(report.get("cves"), list) else extract_cves(workspace)
    check_results = report.get("check_results") if isinstance(report.get("check_results"), list) else []

    service_counts = summary.get("service_counts", {}) if isinstance(summary.get("service_counts"), dict) else {}
    checked_by_cve = {item.get("cve"): item for item in check_results if isinstance(item, dict)}
    attention = []
    quiet_count = 0

    if check_results:
        for item in check_results:
            if not isinstance(item, dict):
                continue
            classification = classify_status(item.get("classification") or item.get("status"))
            if classification in {"Fixed", "Not affected", "Not found"}:
                quiet_count += 1
                continue
            attention.append({
                "kind": "vulnerability",
                "label": item.get("cve", "Unknown CVE"),
                "severity": classification,
                "why": item.get("summary") or "This item needs review because the vendor status was not clearly safe.",
                "next": "Confirm whether this affects the operating system version, then patch or document the exception.",
            })
    else:
        for cve in cves:
            attention.append({
                "kind": "vulnerability",
                "label": cve,
                "severity": "Needs vendor check",
                "why": "This CVE was found in the scan evidence, but it has not been checked against RHEL or Ubuntu yet.",
                "next": "Run the advisory status check for the target operating system and version.",
            })

    for host in hosts:
        if not isinstance(host, dict):
            continue
        for port in host.get("ports", []):
            if not isinstance(port, dict):
                continue
            service = port.get("service", {}) if isinstance(port.get("service"), dict) else {}
            port_id = str(port.get("portid", ""))
            service_name = str(service.get("name") or "unknown")
            scripts = "\n".join(str(script.get("output", "")) for script in port.get("scripts", []) if isinstance(script, dict)).lower()
            if any(term in scripts for term in ("fail:", "weak cipher", "broken sha-1", "backdoored", "dheat", "terrapin")):
                attention.append({
                    "kind": "service exposure",
                    "label": f"{host.get('address', 'Unknown')}:{port_id} {service_name}",
                    "severity": "Hardening needed",
                    "why": "The scan notes weak or risky SSH/security settings for this service.",
                    "next": "Remove weak algorithms, confirm rate limiting, and keep the service patched.",
                })

    severity_rank = {"Affected": 0, "Hardening needed": 1, "Needs vendor check": 2, "Lookup failed": 3, "Unknown": 4, "Deferred": 5, "Not listed": 6, "Out of support": 7}
    attention = sorted(attention, key=lambda item: severity_rank.get(item["severity"], 9))[:18]
    attention_cards = []
    for item in attention:
        css = item["severity"].lower().replace(" ", "-")
        attention_cards.append(
            f"<article class='attention-card {h(css)}'><div><span class='eyebrow'>{h(item['kind'])}</span><h3>{h(item['label'])}</h3></div>"
            f"<span class='pill {h(css)}'>{h(item['severity'])}</span><p>{h(item['why'])}</p><strong>Next step</strong><p>{h(item['next'])}</p></article>"
        )
    if not attention_cards:
        attention_cards.append("<article class='attention-card calm'><span class='eyebrow'>status</span><h3>No attention-needed items</h3><p>The checked evidence did not produce any active or uncertain items. Keep normal patching and monitoring in place.</p></article>")

    key_services = sorted(service_counts.items(), key=lambda item: item[1], reverse=True)[:6]
    services = "".join(f"<span class='service-chip'>{h(name)} <b>{h(count)}</b></span>" for name, count in key_services)
    if not services:
        services = "<span class='service-chip'>No named services</span>"

    top_hosts = []
    for host in hosts[:6]:
        ports = host.get("ports", []) if isinstance(host, dict) else []
        open_ports = [f"{port.get('portid')}/{port.get('protocol', 'tcp')}" for port in ports if isinstance(port, dict)]
        top_hosts.append(f"<li><strong>{h(host.get('address', 'Unknown'))}</strong><span>{h(', '.join(open_ports[:8]) or 'No ports listed')}</span></li>")
    if not top_hosts:
        top_hosts.append("<li><strong>No systems identified</strong><span>Upload evidence with host data for system-level context.</span></li>")

    evidence_note = f"{len(files)} evidence file(s) reviewed"
    if len(files) == 1:
        evidence_note = "1 evidence file reviewed"

    ai_report = report.get("ai_report") if isinstance(report.get("ai_report"), dict) else {}
    if ai_report.get("status") == "ok":
        ai_section = f"""
  <section class="card ai-card" style="margin-top:14px">
    <span class="eyebrow">AI-assisted summary</span>
    <h2>{h(ai_report.get('headline') or 'Executive summary')}</h2>
    <p>{h(ai_report.get('executive_summary'))}</p>
    <p class="quiet">{h(ai_report.get('business_impact'))}</p>
    <div class="ai-grid">
      <div><strong>Top priorities</strong><ul>{html_list(ai_report.get('top_priorities'))}</ul></div>
      <div><strong>Recommended next steps</strong><ul>{html_list(ai_report.get('recommended_next_steps'))}</ul></div>
    </div>
    <p class="quiet">Generated by {h(ai_report.get('model'))} with {h(ai_report.get('confidence'))} confidence from the stored scan evidence.</p>
  </section>"""
    elif ai_report.get("enabled") and ai_report.get("message"):
        ai_section = f"""
  <section class="card" style="margin-top:14px">
    <span class="eyebrow">AI-assisted summary</span>
    <h2>Summary unavailable</h2>
    <p class="quiet">{h(ai_report.get('message'))}</p>
  </section>"""
    else:
        ai_section = ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanLens Report {h(report.get('report_id'))}</title>
<style>
:root{{--bg:#f5f7fb;--panel:#fff;--panel2:#f9fbfd;--text:#101828;--muted:#667085;--line:#d7e0ea;--accent:#0f766e;--bad:#b42318;--warn:#b7791f;--ok:#0f766e;--ink:#111827;--shadow:0 22px 70px rgba(16,24,40,.10)}}*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(180deg,#eef5fb 0,#f7f9fc 360px,var(--bg) 100%);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}}main{{max-width:1180px;margin:0 auto;padding:30px}}.hero{{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;align-items:stretch;padding:20px 0}}.hero-panel,.card,.attention-card{{background:rgba(255,255,255,.94);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow)}}.hero-panel{{padding:28px}}h1{{font-size:42px;line-height:1.05;margin:0 0 12px;letter-spacing:0}}h2{{font-size:18px;margin:0 0 14px}}h3{{font-size:17px;margin:4px 0 0}}p{{line-height:1.58}}.muted{{color:var(--muted)}}.eyebrow{{display:inline-flex;color:var(--muted);font-size:12px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}}.risk-badge{{display:inline-flex;align-items:center;min-height:34px;border-radius:999px;padding:0 12px;font-weight:850;color:#fff;background:var(--ok)}}.risk-badge.action-needed{{background:var(--bad)}}.risk-badge.review-needed,.risk-badge.monitor{{background:var(--warn);color:#211700}}.summary{{display:grid;gap:10px;padding:18px}}.summary b{{font-size:34px;display:block}}.summary span{{color:var(--muted);font-size:12px;font-weight:850;text-transform:uppercase}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}}.card{{padding:16px}}.metric{{min-height:116px}}.metric b{{font-size:32px;display:block}}.metric span{{color:var(--muted);font-size:12px;text-transform:uppercase;font-weight:850}}.ai-card{{border-left:6px solid var(--accent)}}.ai-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.ai-grid ul{{margin:10px 0 0;padding-left:20px;color:var(--muted);line-height:1.6}}.attention-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;align-items:start}}.attention-card{{padding:16px;display:grid;align-content:start;gap:10px;border-left:6px solid var(--warn)}}.attention-card.affected,.attention-card.action-needed,.attention-card.lookup-failed{{border-left-color:var(--bad)}}.attention-card.calm{{border-left-color:var(--ok)}}.attention-card p{{margin:0;color:var(--muted)}}.pill{{display:inline-flex;align-items:center;justify-content:center;justify-self:start;align-self:start;width:auto;max-width:100%;min-height:26px;border-radius:999px;padding:5px 10px;background:#64748b;color:white;font-size:12px;line-height:1.15;font-weight:850}}.pill.affected,.pill.action-needed,.pill.lookup-failed{{background:var(--bad)}}.pill.hardening-needed,.pill.needs-vendor-check,.pill.review-needed,.pill.monitor,.pill.unknown,.pill.deferred,.pill.not-listed,.pill.out-of-support{{background:var(--warn);color:#211700}}.service-row{{display:flex;flex-wrap:wrap;gap:8px}}.service-chip{{display:inline-flex;gap:8px;align-items:center;border:1px solid var(--line);border-radius:999px;background:var(--panel2);padding:8px 11px;color:var(--muted)}}.service-chip b{{color:var(--text)}}.host-list{{display:grid;gap:8px;padding:0;list-style:none;margin:0}}.host-list li{{display:flex;justify-content:space-between;gap:14px;border:1px solid var(--line);border-radius:12px;padding:11px;background:var(--panel2)}}.quiet{{color:var(--muted);font-size:13px}}@media(max-width:850px){{main{{padding:18px}}.hero,.grid,.attention-grid,.ai-grid{{grid-template-columns:1fr}}h1{{font-size:32px}}}}
</style>
</head>
<body>
<main>
  <section class="hero">
    <div class="hero-panel">
      <span class="eyebrow">ScanLens shared report · {h(report.get('created_at'))}</span>
      <h1>{h(report.get('workspace_name') or summary.get('source_file') or 'Workspace report')}</h1>
      <span class="risk-badge {h(people['risk']).lower().replace(' ', '-')}">{h(people['risk'])}</span>
      <p>{h(people['meaning'])}</p>
      <p class="quiet">This page is intentionally focused on attention-needed items. Details that are already fixed or not affected are kept out of the main view.</p>
    </div>
    <aside class="summary card">
      <div><b>{h(len(attention))}</b><span>Attention items</span></div>
      <div><b>{h(quiet_count)}</b><span>Cleared or low-priority items hidden</span></div>
      <p class="quiet">{h(evidence_note)} · link is hard to guess, but anyone with the URL can view it.</p>
    </aside>
  </section>
  <section class="grid">
    <div class="card metric"><b>{h(people['files'])}</b><span>Files reviewed</span></div>
    <div class="card metric"><b>{h(people['hosts'])}</b><span>Systems found</span></div>
    <div class="card metric"><b>{h(people['open_ports'])}</b><span>Open services</span></div>
    <div class="card metric"><b>{h(people['cves'])}</b><span>CVE references</span></div>
  </section>
  {ai_section}
  <section class="card" style="margin-top:14px">
    <span class="eyebrow">Priority queue</span>
    <h2>Only items needing attention</h2>
    <div class="attention-grid">{''.join(attention_cards)}</div>
  </section>
  <section class="grid" style="grid-template-columns:1.2fr .8fr;margin-top:14px">
    <div class="card">
      <span class="eyebrow">Exposure snapshot</span>
      <h2>Systems with reachable services</h2>
      <ul class="host-list">{''.join(top_hosts)}</ul>
    </div>
    <div class="card">
      <span class="eyebrow">Services</span>
      <h2>Observed service types</h2>
      <div class="service-row">{services}</div>
    </div>
  </section>
  <section class="card" style="margin-top:18px">
    <span class="eyebrow">Recommended response</span>
    <h2>Suggested next steps</h2>
    <p>Resolve affected items first, run vendor checks for anything marked “Needs vendor check,” and apply hardening for services with weak algorithms or risky configuration. Keep fixed or not-affected items in the JSON export for audit evidence, but they do not need executive attention here.</p>
  </section>
</main>
</body>
</html>"""


def classify_status(status: object) -> str:
    text = str(status or "").strip().lower().replace("_", " ")
    if not text:
        return "Unknown"
    if "lookup failed" in text:
        return "Lookup failed"
    if "not found" in text or "404" in text:
        return "Not found"
    if "out of support" in text or "end of life" in text:
        return "Out of support"
    if "deferred" in text or "will not fix" in text or "ignored" in text:
        return "Deferred"
    if text in {"affected", "new", "needed", "vulnerable", "needs evaluation", "needs-triage", "needs triage"}:
        return "Affected"
    if "work in progress" in text:
        return "Affected"
    if "not affected" in text or "not in release" in text or text == "dne":
        return "Not affected"
    if "fixed" in text or "released" in text or "resolved" in text:
        return "Fixed"
    if "not listed" in text:
        return "Not listed"
    return "Unknown"


def enrich(result: dict[str, Any]) -> dict[str, Any]:
    result["classification"] = classify_status(result.get("status"))
    result["is_actionable"] = result["classification"] == "Affected"
    return result


def fetch_json(url: str) -> dict[str, Any]:
    started = time.perf_counter()
    LOG.debug("vendor_request start url=%s", url)
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "scanlens/1.0"})
    with urlopen(request, timeout=20) as response:
        body = response.read()
        LOG.debug("vendor_request done url=%s status=%s bytes=%s elapsed_ms=%.1f", url, getattr(response, "status", "unknown"), len(body), elapsed_ms(started))
        return json.loads(body.decode("utf-8"))


def compact_json(value: object, limit: int = GROQ_VENDOR_JSON_LIMIT) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated {len(text) - limit} chars]"


def parse_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start >= 0 and end > start:
            try:
                value = json.loads(stripped[start : end + 1])
                return value if isinstance(value, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def valid_ai_classification(value: object) -> str:
    allowed = {"Affected", "Fixed", "Not affected", "Deferred", "Out of support", "Not found", "Not listed", "Unknown", "Lookup failed"}
    classification = classify_status(value)
    return classification if classification in allowed else "Unknown"


def groq_enabled() -> bool:
    if env_truthy("GROQ_DISABLED"):
        return False
    return bool(os.environ.get("GROQ_API_KEY", "").strip())


def retry_after_seconds(exc: HTTPError) -> float:
    header = exc.headers.get("Retry-After") if exc.headers else None
    if not header:
        return GROQ_MIN_INTERVAL_SECONDS
    try:
        return max(GROQ_MIN_INTERVAL_SECONDS, min(float(header), 30.0))
    except ValueError:
        return GROQ_MIN_INTERVAL_SECONDS


def wait_for_groq_slot() -> None:
    global GROQ_NEXT_ALLOWED_AT
    now = time.monotonic()
    wait_seconds = max(0.0, GROQ_NEXT_ALLOWED_AT - now)
    if wait_seconds > 0:
        LOG.info("groq_rate_limit wait_seconds=%.2f", wait_seconds)
        time.sleep(wait_seconds)


def groq_chat_completion(payload: dict[str, Any]) -> dict[str, Any]:
    base_url = os.environ.get("GROQ_BASE_URL", GROQ_BASE_URL_DEFAULT).rstrip("/")
    url = f"{base_url}/chat/completions"
    key = os.environ.get("GROQ_API_KEY", "").strip()
    if not key:
        raise ValueError("GROQ_API_KEY is not configured.")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    started = time.perf_counter()
    LOG.debug("groq_request start url=%s model=%s bytes=%s", url, payload.get("model"), len(body))
    request = Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "scanlens/1.0",
        },
        method="POST",
    )
    global GROQ_NEXT_ALLOWED_AT
    with GROQ_RATE_LOCK:
        for attempt in range(1, GROQ_MAX_ATTEMPTS + 1):
            wait_for_groq_slot()
            try:
                with urlopen(request, timeout=GROQ_TIMEOUT_SECONDS) as response:
                    response_body = response.read()
                    GROQ_NEXT_ALLOWED_AT = time.monotonic() + GROQ_MIN_INTERVAL_SECONDS
                    LOG.debug("groq_request done status=%s bytes=%s attempt=%s elapsed_ms=%.1f", getattr(response, "status", "unknown"), len(response_body), attempt, elapsed_ms(started))
                    return json.loads(response_body.decode("utf-8"))
            except HTTPError as exc:
                GROQ_NEXT_ALLOWED_AT = time.monotonic() + GROQ_MIN_INTERVAL_SECONDS
                if exc.code == 429 and attempt < GROQ_MAX_ATTEMPTS:
                    wait_seconds = retry_after_seconds(exc)
                    GROQ_NEXT_ALLOWED_AT = time.monotonic() + wait_seconds
                    LOG.warning("groq_request rate_limited attempt=%s retry_in=%.2f", attempt, wait_seconds)
                    continue
                raise
    raise RuntimeError("Groq request failed before completion.")


def groq_analyze_cve(cve: str, distro: str, version: str, vendor_result: dict[str, Any], vendor_json: dict[str, Any]) -> dict[str, Any]:
    if not groq_enabled():
        return {
            "enabled": False,
            "status": "disabled",
            "model": os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT),
            "message": "Set GROQ_API_KEY in .env to enable AI cross-checking.",
        }

    model = os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT).strip() or GROQ_MODEL_DEFAULT
    system = (
        "You are a Linux vulnerability triage assistant. Use only the supplied vendor security JSON and "
        "deterministic parser result. Cross-check the selected operating system/version against package or "
        "release records. Do not invent package status. Reply as one compact JSON object only."
    )
    user = {
        "task": "Cross-check whether this CVE affects the selected OS version.",
        "selected_target": {"distro": distro, "version": version},
        "cve": cve,
        "deterministic_result": vendor_result,
        "vendor_security_json_compacted": compact_json(vendor_json),
        "required_schema": {
            "classification": "Affected | Fixed | Not affected | Deferred | Out of support | Not found | Not listed | Unknown | Lookup failed",
            "confidence": "high | medium | low",
            "plain_language_summary": "one short sentence for a non-technical reader",
            "evidence": "one short sentence naming the package/release evidence used",
            "next_action": "one practical action",
        },
    }
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": 700,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
        ],
    }
    started = time.perf_counter()
    try:
        data = groq_chat_completion(payload)
        content = str(data.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
        parsed = parse_json_object(content)
        if not parsed:
            LOG.warning("groq_analysis parse_failed cve=%s model=%s content=%r elapsed_ms=%.1f", cve, model, content[:300], elapsed_ms(started))
            return {
                "enabled": True,
                "status": "parse_failed",
                "model": model,
                "message": "Groq returned text that could not be parsed as JSON.",
                "raw": content[:1200],
            }
        review = {
            "enabled": True,
            "status": "ok",
            "model": model,
            "classification": valid_ai_classification(parsed.get("classification")),
            "confidence": str(parsed.get("confidence") or "medium"),
            "plain_language_summary": str(parsed.get("plain_language_summary") or "").strip(),
            "evidence": str(parsed.get("evidence") or "").strip(),
            "next_action": str(parsed.get("next_action") or "").strip(),
        }
        LOG.info(
            "groq_analysis ok cve=%s distro=%s version=%s model=%s class=%s confidence=%s elapsed_ms=%.1f",
            cve,
            distro,
            version,
            model,
            review["classification"],
            review["confidence"],
            elapsed_ms(started),
        )
        return review
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        LOG.warning("groq_analysis http_error cve=%s code=%s reason=%s body=%s elapsed_ms=%.1f", cve, exc.code, exc.reason, detail, elapsed_ms(started))
        return {"enabled": True, "status": "http_error", "model": model, "message": f"Groq HTTP Error {exc.code}: {exc.reason}", "detail": detail}
    except Exception as exc:
        LOG.exception("groq_analysis failed cve=%s distro=%s version=%s elapsed_ms=%.1f", cve, distro, version, elapsed_ms(started))
        return {"enabled": True, "status": "failed", "model": model, "message": str(exc)}


def groq_analyze_report(report: dict[str, Any]) -> dict[str, Any]:
    if not groq_enabled():
        return {
            "enabled": False,
            "status": "disabled",
            "model": os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT),
            "message": "Set GROQ_API_KEY in .env to enable AI report summaries.",
        }

    workspace = report.get("workspace") if isinstance(report.get("workspace"), dict) else {}
    summary = workspace.get("summary", {}) if isinstance(workspace.get("summary"), dict) else {}
    hosts = workspace.get("hosts", []) if isinstance(workspace.get("hosts"), list) else []
    check_results = report.get("check_results") if isinstance(report.get("check_results"), list) else []
    cves = report.get("cves") if isinstance(report.get("cves"), list) else extract_cves(workspace)
    attention_results = []
    for item in check_results:
        if not isinstance(item, dict):
            continue
        classification = classify_status(item.get("classification") or item.get("status"))
        if classification in {"Fixed", "Not affected", "Not found"}:
            continue
        attention_results.append({
            "cve": item.get("cve"),
            "classification": classification,
            "severity": item.get("severity"),
            "summary": item.get("summary"),
            "records": item.get("records", [])[:4] if isinstance(item.get("records"), list) else [],
            "ai_review": item.get("ai_review") if isinstance(item.get("ai_review"), dict) else {},
        })
    host_snapshot = []
    for host in hosts[:12]:
        if not isinstance(host, dict):
            continue
        ports = []
        for port in host.get("ports", [])[:12] if isinstance(host.get("ports"), list) else []:
            if isinstance(port, dict):
                service = port.get("service", {}) if isinstance(port.get("service"), dict) else {}
                ports.append({
                    "port": f"{port.get('portid')}/{port.get('protocol', 'tcp')}",
                    "state": (port.get("state") or {}).get("state") if isinstance(port.get("state"), dict) else port.get("state"),
                    "service": service.get("name"),
                    "product": service.get("product"),
                    "version": service.get("version"),
                    "script_count": len(port.get("scripts", [])) if isinstance(port.get("scripts"), list) else 0,
                })
        host_snapshot.append({"address": host.get("address"), "ports": ports})

    model = os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT).strip() or GROQ_MODEL_DEFAULT
    system = (
        "You write executive security summaries for scan reports. Use only the supplied structured evidence. "
        "Be clear for non-technical readers, but do not downplay uncertainty. Return one compact JSON object only."
    )
    user = {
        "task": "Create a non-technical report summary focused only on attention-needed security work.",
        "workspace_name": report.get("workspace_name"),
        "created_at": report.get("created_at"),
        "plain_summary": report.get("plain_summary"),
        "scan_summary": summary,
        "cve_count": len(cves),
        "attention_cves": attention_results[:18],
        "host_snapshot": host_snapshot,
        "required_schema": {
            "headline": "short report headline",
            "executive_summary": "2-3 short sentences, plain language",
            "business_impact": "one short sentence",
            "top_priorities": ["3-5 short action-focused bullets"],
            "recommended_next_steps": ["3-5 practical next steps"],
            "confidence": "high | medium | low",
        },
    }
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": 900,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user, ensure_ascii=False)},
        ],
    }
    started = time.perf_counter()
    try:
        data = groq_chat_completion(payload)
        content = str(data.get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
        parsed = parse_json_object(content)
        if not parsed:
            LOG.warning("groq_report parse_failed report=%s model=%s content=%r elapsed_ms=%.1f", report.get("report_id"), model, content[:300], elapsed_ms(started))
            return {"enabled": True, "status": "parse_failed", "model": model, "message": "Groq returned text that could not be parsed as JSON.", "raw": content[:1200]}
        review = {
            "enabled": True,
            "status": "ok",
            "model": model,
            "headline": str(parsed.get("headline") or "Security report summary").strip(),
            "executive_summary": str(parsed.get("executive_summary") or "").strip(),
            "business_impact": str(parsed.get("business_impact") or "").strip(),
            "top_priorities": [str(item).strip() for item in parsed.get("top_priorities", []) if str(item).strip()][:5] if isinstance(parsed.get("top_priorities"), list) else [],
            "recommended_next_steps": [str(item).strip() for item in parsed.get("recommended_next_steps", []) if str(item).strip()][:5] if isinstance(parsed.get("recommended_next_steps"), list) else [],
            "confidence": str(parsed.get("confidence") or "medium"),
        }
        LOG.info("groq_report ok report=%s model=%s confidence=%s elapsed_ms=%.1f", report.get("report_id"), model, review["confidence"], elapsed_ms(started))
        return review
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        LOG.warning("groq_report http_error report=%s code=%s reason=%s body=%s elapsed_ms=%.1f", report.get("report_id"), exc.code, exc.reason, detail, elapsed_ms(started))
        return {"enabled": True, "status": "http_error", "model": model, "message": f"Groq HTTP Error {exc.code}: {exc.reason}", "detail": detail}
    except Exception as exc:
        LOG.exception("groq_report failed report=%s elapsed_ms=%.1f", report.get("report_id"), elapsed_ms(started))
        return {"enabled": True, "status": "failed", "model": model, "message": str(exc)}


def product_matches_rhel(name: object, version: str) -> bool:
    text = str(name or "").lower()
    return f"red hat enterprise linux {version}" in text or f"rhel {version}" in text


def clean_summary(value: object) -> str:
    if isinstance(value, list):
        return "\n\n".join(str(item).strip() for item in value if str(item).strip())
    if isinstance(value, dict):
        return "; ".join(f"{key}: {nested}" for key, nested in value.items())
    return str(value or "").strip()


def rollup_status(records: list[dict[str, Any]]) -> str:
    if not records:
        return "Not listed"
    statuses = [str(record.get("status", "")).lower() for record in records]
    if any("out of support" in status for status in statuses):
        return "Out of support scope"
    if any(status in {"affected", "new", "needed", "vulnerable", "needs evaluation", "needs-triage", "needs triage"} or "work in progress" in status for status in statuses):
        return "Affected"
    if any("deferred" in status or "will not fix" in status or "ignored" in status for status in statuses):
        return "Deferred"
    if any("fixed" in status or "released" in status or "resolved" in status for status in statuses):
        return "Fixed"
    if all("not affected" in status or "not in release" in status or status == "dne" for status in statuses):
        return "Not affected"
    return records[0].get("status") or "Unknown"


def dedupe_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    out = []
    for record in records:
        key = tuple(sorted((field, str(value)) for field, value in record.items()))
        if key not in seen:
            seen.add(key)
            out.append(record)
    return out


def summarize_redhat(cve: str, version: str, data: dict[str, Any], url: str) -> dict[str, Any]:
    records = []
    for item in data.get("affected_release") or []:
        if product_matches_rhel(item.get("product_name"), version):
            records.append({
                "package": item.get("package") or item.get("package_name") or "",
                "product": item.get("product_name", ""),
                "status": "Fixed",
                "detail": item.get("advisory") or item.get("release_date") or "",
            })
    for item in data.get("package_state") or []:
        if product_matches_rhel(item.get("product_name"), version):
            records.append({
                "package": item.get("package_name") or item.get("package") or "",
                "product": item.get("product_name", ""),
                "status": item.get("fix_state") or "Unknown",
                "detail": item.get("cpe") or "",
            })
    return enrich({
        "cve": cve,
        "status": rollup_status(records),
        "severity": data.get("threat_severity") or "",
        "score": data.get("cvss3_score") or data.get("cvss_score") or "",
        "summary": clean_summary(data.get("bugzilla_description") or data.get("details") or ""),
        "url": url,
        "records": dedupe_records(records),
    })


def release_matches(value: object, version: str) -> bool:
    text = str(value or "").lower()
    return any(alias.lower() in text for alias in UBUNTU_RELEASES.get(version, [version]))


def summarize_ubuntu(cve: str, version: str, data: dict[str, Any], url: str) -> dict[str, Any]:
    records = []

    def add(package: str, release: object, status: object, detail: object = "") -> None:
        if release_matches(release, version) and status:
            records.append({"package": package, "product": f"Ubuntu {version}", "status": str(status), "detail": str(detail or "")})

    def walk(item: object, package: str = "") -> None:
        if isinstance(item, dict):
            package_name = str(item.get("name") or item.get("package") or item.get("source") or item.get("source_package") or package)
            release = item.get("release") or item.get("release_codename") or item.get("series") or item.get("codename") or item.get("ubuntu_release")
            status = item.get("status") or item.get("state")
            if release and status:
                add(package_name, release, status, item.get("description") or item.get("note"))
            for key, value in item.items():
                if release_matches(key, version):
                    if isinstance(value, str):
                        add(package_name, key, value)
                    elif isinstance(value, dict):
                        add(package_name, key, value.get("status") or value.get("state"), value.get("note") or value.get("description"))
                walk(value, package_name)
        elif isinstance(item, list):
            for nested in item:
                walk(nested, package)

    walk(data.get("packages", data))
    return enrich({
        "cve": cve,
        "status": rollup_status(records),
        "severity": data.get("priority") or data.get("severity") or "",
        "score": data.get("cvss3") or data.get("cvss_score") or "",
        "summary": clean_summary(data.get("description") or data.get("notes") or ""),
        "url": url,
        "records": dedupe_records(records),
    })


def check_cve(cve: str, distro: str, version: str) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        if distro == "rhel":
            url = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve}.json"
            vendor_json = fetch_json(url)
            result = summarize_redhat(cve, version, vendor_json, url)
        else:
            url = f"https://ubuntu.com/security/cves/{cve}.json"
            vendor_json = fetch_json(url)
            result = summarize_ubuntu(cve, version, vendor_json, url)
        result["ai_review"] = groq_analyze_cve(cve, distro, version, result, vendor_json)
        LOG.info(
            "cve_lookup ok cve=%s distro=%s version=%s classification=%s ai_status=%s records=%s elapsed_ms=%.1f",
            cve,
            distro,
            version,
            result["classification"],
            result.get("ai_review", {}).get("status"),
            len(result["records"]),
            elapsed_ms(started),
        )
        return result
    except HTTPError as exc:
        status = "Not found" if exc.code == 404 else "Lookup failed"
        LOG.warning("cve_lookup http_error cve=%s distro=%s version=%s code=%s elapsed_ms=%.1f", cve, distro, version, exc.code, elapsed_ms(started))
        result = enrich({"cve": cve, "status": status, "severity": "", "score": "", "summary": f"HTTP Error {exc.code}: {exc.reason}", "url": url if "url" in locals() else "", "records": []})
        result["ai_review"] = {"enabled": groq_enabled(), "status": "skipped", "model": os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT), "message": "Vendor endpoint did not return CVE JSON to cross-check."}
        return result
    except Exception as exc:
        LOG.exception("cve_lookup failed cve=%s distro=%s version=%s elapsed_ms=%.1f", cve, distro, version, elapsed_ms(started))
        result = enrich({"cve": cve, "status": "Lookup failed", "severity": "", "score": "", "summary": str(exc), "url": url if "url" in locals() else "", "records": []})
        result["ai_review"] = {"enabled": groq_enabled(), "status": "skipped", "model": os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT), "message": "Vendor lookup failed before AI cross-checking could run."}
        return result


def parse_multipart_files(content_type: str, body: bytes) -> list[tuple[str, bytes]]:
    if "multipart/form-data" not in content_type:
        raise ValueError("Expected multipart/form-data upload.")
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
    )
    files = []
    for part in message.iter_parts():
        field_name = part.get_param("name", header="content-disposition")
        if field_name not in {"scan_file", "scan_files"}:
            continue
        filename = part.get_filename() or "uploaded-scan"
        payload = part.get_payload(decode=True) or b""
        files.append((filename, payload))
    if not files:
        raise ValueError("No file field named scan_file or scan_files was found.")
    return files


def parse_multipart_file(content_type: str, body: bytes) -> tuple[str, bytes]:
    return parse_multipart_files(content_type, body)[0]


def persist_session_uploads(session_id: str, uploads: list[tuple[str, bytes]]) -> list[dict[str, Any]]:
    stored = []
    for index, (filename, payload) in enumerate(uploads, start=1):
        path = unique_session_file(session_id, filename, index)
        path.write_bytes(payload)
        item = {
            "filename": filename,
            "stored_path": session_relative(path),
            "size": len(payload),
            "stored_at": utc_stamp(),
        }
        stored.append(item)
        LOG.debug("session_file stored session=%s file=%s bytes=%s path=%s", session_id, filename, len(payload), item["stored_path"])
    return stored


def persist_report(session_id: str, workspace: dict[str, Any], cves: list[str], check_results: list[dict[str, Any]], workspace_name: str) -> dict[str, Any]:
    report_id = new_report_id()
    report = {
        "report_id": report_id,
        "created_at": utc_stamp(),
        "session_id": session_id,
        "workspace_name": workspace_name,
        "workspace": workspace,
        "cves": sorted({str(item).upper() for item in cves if normalize_cve(item)}),
        "check_results": check_results,
    }
    if not report["cves"]:
        report["cves"] = extract_cves(workspace)
    report["plain_summary"] = summarize_report_for_people(report)
    report["ai_report"] = groq_analyze_report(report)
    path = report_path(session_id, report_id)
    write_json_file(path, report)
    update_session_manifest(session_id, [], {
        "kind": "report",
        "id": report_id,
        "name": workspace_name,
        "stored_path": session_relative(path),
        "url": f"/{report_id}",
        "summary": report["plain_summary"],
        "stored_at": utc_stamp(),
    })
    return {"report": report, "path": path}


HTML = r"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanLens</title>
<style>
:root{color-scheme:light;--bg:#f4f7fb;--panel:#ffffff;--panel2:#f8fafc;--text:#122033;--muted:#66758a;--line:#dbe4ef;--accent:#0f766e;--accent2:#2563eb;--bad:#b42318;--warn:#b7791f;--ok:#0f766e;--violet:#6d28d9;--shadow:0 18px 50px rgba(18,32,51,.08)}
[data-theme=dark]{color-scheme:dark;--bg:#0b1120;--panel:#111827;--panel2:#172033;--text:#e5edf8;--muted:#94a3b8;--line:#263348;--accent:#2dd4bf;--accent2:#60a5fa;--bad:#fb7185;--warn:#fbbf24;--ok:#34d399;--violet:#a78bfa;--shadow:0 20px 60px rgba(0,0,0,.28)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,rgba(37,99,235,.12),transparent 32rem),var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer}a{color:var(--accent2);overflow-wrap:anywhere}.shell{min-height:100vh}.top{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:18px 24px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--panel) 92%,transparent);backdrop-filter:blur(18px)}.brand{display:flex;gap:14px;align-items:center}.mark{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:var(--shadow)}h1{font-size:22px;margin:0;letter-spacing:0}.sub{margin:2px 0 0;color:var(--muted);font-size:13px}.top-actions{display:flex;gap:10px;align-items:center}.btn,.select,.search{border:1px solid var(--line);border-radius:10px;background:var(--panel2);color:var(--text);min-height:40px;padding:0 12px}.btn{font-weight:750}.btn.primary{background:var(--accent);border-color:var(--accent);color:#06201d}.btn.ghost{background:transparent}.btn:disabled,.select:disabled{opacity:.5;cursor:not-allowed}.grid{display:grid;grid-template-columns:360px minmax(0,1fr);gap:18px;max-width:1560px;margin:0 auto;padding:18px}.side{display:grid;align-content:start;gap:14px;position:sticky;top:92px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.pad{padding:16px}.title{font-size:13px;font-weight:850;text-transform:uppercase;letter-spacing:.04em}.drop{display:grid;gap:8px;align-content:center;min-height:138px;margin-top:14px;padding:18px;border:1px dashed color-mix(in srgb,var(--muted) 70%,transparent);border-radius:14px;background:var(--panel2)}.drop:hover,.drop.drag{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--panel2))}.drop input{display:none}.drop strong{font-size:18px}.muted{color:var(--muted);font-size:13px;line-height:1.45}.stack{display:grid;gap:10px}.message{min-height:20px;margin-top:10px;color:var(--muted);font-size:13px}.message.error{color:var(--bad)}.workspace-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.workspace-list{display:grid;gap:8px;margin-top:12px;max-height:260px;overflow:auto}.workspace-item{width:100%;display:grid;gap:4px;text-align:left;padding:10px 12px;border:1px solid var(--line);border-radius:12px;background:var(--panel2);color:var(--text)}.workspace-item.active{border-color:var(--accent);box-shadow:inset 3px 0 0 var(--accent)}.workspace-name{font-weight:850;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.file-list{display:grid;gap:6px;margin-top:12px;max-height:170px;overflow:auto}.file-item{display:flex;justify-content:space-between;gap:8px;padding:8px 10px;border:1px solid var(--line);border-radius:10px;background:var(--panel2);font-size:12px}.metrics{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:10px}.metric{padding:14px;border-top:3px solid color-mix(in srgb,var(--accent2) 35%,var(--line))}.metric b{font-size:26px}.metric span{display:block;margin-top:6px;color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase}.main{display:grid;gap:14px;min-width:0}.toolbar{display:grid;grid-template-columns:1fr minmax(240px,460px);gap:12px;align-items:center;padding:16px;border-bottom:1px solid var(--line)}.tabs{display:flex;gap:6px;padding:10px 16px 0}.tab{min-height:36px;padding:0 14px;border:0;border-radius:10px;background:transparent;color:var(--muted);font-weight:800}.tab.active{background:var(--panel2);color:var(--text)}.panel{display:none;padding:16px}.panel.active{display:block}.empty{display:grid;min-height:330px;place-items:center;border:1px dashed var(--line);border-radius:14px;background:var(--panel2);color:var(--muted);text-align:center}.hosts,.cves{display:grid;gap:12px}.host{overflow:hidden}.host-head{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:15px;background:var(--panel2);border-bottom:1px solid var(--line)}.mono{font-family:"Cascadia Mono",Consolas,monospace}.host-ip{font-size:18px;font-weight:850;overflow-wrap:anywhere}.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:8px}.chip,.status{display:inline-flex;align-items:center;min-height:25px;padding:0 9px;border-radius:999px;font-size:11px;font-weight:850;text-transform:uppercase}.chip{background:color-mix(in srgb,var(--muted) 16%,transparent);color:var(--muted)}.status{background:var(--muted);color:white}.status-open,.status-up,.status-fixed{background:var(--ok)}.status-affected,.status-lookup-failed{background:var(--bad)}.status-deferred{background:var(--warn);color:#1f1600}.status-out-of-support{background:var(--violet)}.status-not-affected,.status-not-found,.status-not-listed,.status-pending,.status-checking,.status-unknown{background:#64748b}.ports{display:grid}.port-head,.port{display:grid;grid-template-columns:105px 96px minmax(120px,190px) minmax(0,1fr) auto;gap:12px}.port-head{padding:10px 14px;background:var(--panel2);border-bottom:1px solid var(--line);color:var(--muted);font-size:11px;font-weight:850;text-transform:uppercase}.port{align-items:center;padding:12px 14px;border-bottom:1px solid var(--line)}.port:last-child{border-bottom:0}.detail{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:13px}details.scripts{grid-column:1/-1}details.scripts summary{display:inline-flex;min-height:30px;align-items:center;padding:0 10px;border-radius:10px;background:color-mix(in srgb,var(--accent2) 14%,transparent);color:var(--accent2);font-size:12px;font-weight:850;list-style:none}details.scripts summary::-webkit-details-marker{display:none}.script{max-height:220px;overflow:auto;margin:10px 0 0;padding:12px;border-radius:12px;background:#0f1724;color:#dbeafe;font-size:12px;line-height:1.5;white-space:pre-wrap}.cve-top{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--panel2)}.count-row{display:flex;flex-basis:100%;flex-wrap:wrap;gap:7px}.count{display:inline-flex;min-height:26px;align-items:center;padding:0 9px;border-radius:999px;color:#fff;font-size:11px;font-weight:850;text-transform:uppercase}.cve-card{overflow:hidden}.cve-head{display:grid;grid-template-columns:150px 130px minmax(0,1fr) 96px;gap:12px;align-items:center;padding:12px;background:var(--panel2);border-bottom:1px solid var(--line)}.cve-body{display:grid;gap:10px;padding:12px}.ai-review{display:grid;gap:6px;padding:12px;border:1px solid color-mix(in srgb,var(--accent2) 25%,var(--line));border-radius:12px;background:color-mix(in srgb,var(--accent2) 8%,var(--panel2))}.ai-review strong{font-size:12px;text-transform:uppercase;letter-spacing:.04em}.record{display:grid;grid-template-columns:minmax(110px,180px) minmax(0,1fr) minmax(95px,140px) minmax(0,1fr);gap:10px;padding-top:9px;border-top:1px solid var(--line);font-size:13px}pre.json{max-height:calc(100vh - 230px);min-height:420px;overflow:auto;margin:0;padding:14px;border-radius:12px;background:#0f1724;color:#dbeafe;font-size:12px;line-height:1.55}
@media(max-width:1050px){.grid{grid-template-columns:1fr}.side{position:static;grid-template-columns:1fr 1fr}.metrics{grid-template-columns:repeat(3,1fr)}}@media(max-width:760px){.top,.toolbar,.host-head{display:grid;grid-template-columns:1fr}.side,.metrics{grid-template-columns:1fr}.port-head{display:none}.port{grid-template-columns:90px 92px 1fr}.detail,details.scripts{grid-column:1/-1;white-space:normal}.cve-head,.record{grid-template-columns:1fr}.top-actions{display:grid}}
</style>
</head>
<body>
<div class="shell">
  <header class="top">
    <div class="brand"><div class="mark"></div><div><h1>ScanLens</h1><p class="sub">Self-contained scan parser, CVE extractor, and Linux advisory cross-checker.</p></div></div>
    <div class="top-actions"><button class="btn ghost" id="themeBtn">Light</button><button class="btn" id="downloadBtn" disabled>Export Report</button><a id="reportLink" class="btn ghost" href="#" target="_blank" rel="noreferrer" style="display:none">Open Report</a></div>
  </header>
  <main class="grid">
    <aside class="side">
      <section class="card pad">
        <div class="workspace-head"><div class="title">Workspaces</div><button class="btn ghost" id="newWorkspaceBtn" type="button">New Workspace</button></div>
        <div id="workspaceList" class="workspace-list"></div>
      </section>
      <section class="card pad">
        <div class="title">Workspace Inputs</div>
        <form id="uploadForm" class="stack">
          <label class="drop" id="dropZone"><input id="fileInput" name="scan_files" type="file" multiple><strong>Drop or choose files</strong><span id="fileName" class="muted">XML, TXT, NMAP, JSON, logs, or raw text.</span></label>
          <button class="btn primary" id="parseBtn" type="submit">Bulk Parse Workspace</button>
        </form>
        <div id="fileList" class="file-list"></div>
        <div id="parseMessage" class="message">Create a workspace, then upload one or more files.</div>
      </section>
      <section class="card pad">
        <div class="title">CVE Workflow</div>
        <div class="stack" style="margin-top:14px">
          <button class="btn" id="extractBtn" disabled>Extract CVEs</button>
          <select class="select" id="distroSelect" disabled><option value="rhel">RHEL</option><option value="ubuntu">Ubuntu</option></select>
          <select class="select" id="versionSelect" disabled></select>
          <button class="btn primary" id="checkBtn" disabled>Check Advisory Status</button>
        </div>
        <div id="cveMessage" class="message">Parse a file first.</div>
      </section>
      <section class="card pad">
        <div class="title">Services</div>
        <div id="serviceChart" class="stack" style="margin-top:14px"><p class="muted">Services appear after parsing.</p></div>
      </section>
    </aside>
    <section class="main">
      <section id="metrics" class="metrics"></section>
      <section class="card">
        <div class="toolbar"><div><div class="title">Analysis Workspace</div><div class="muted" id="resultCount">No data loaded</div></div><input class="search" id="filterInput" type="search" placeholder="Filter host, port, service, CVE, script"></div>
        <nav class="tabs"><button class="tab active" data-tab="hostsPanel">Hosts</button><button class="tab" data-tab="cvesPanel">CVEs</button><button class="tab" data-tab="jsonPanel">JSON</button></nav>
        <section class="panel active" id="hostsPanel"><div id="hosts" class="hosts empty">Upload a scan artifact to begin.</div></section>
        <section class="panel" id="cvesPanel"><div id="cves" class="cves empty">Extract CVEs after parsing.</div></section>
        <section class="panel" id="jsonPanel"><pre id="jsonOut" class="json">{}</pre></section>
      </section>
    </section>
  </main>
</div>
<script>
const $=s=>document.querySelector(s), $$=s=>[...document.querySelectorAll(s)];
const versions={rhel:["6","7","8","9","10"],ubuntu:["18.04","20.04","22.04","24.04","26.04"]};
const cveRe=/\bCVE-\d{4}-\d{4,7}\b/gi;
let workspaces=[],activeWorkspaceId=null,parsed=null,cves=[],checkResults=[];
function msg(el,text,bad=false){el.textContent=text;el.classList.toggle("error",bad)}
function fmt(v){return typeof v==="string"?v:new Intl.NumberFormat().format(v||0)}
function cls(v){return "status-"+String(v||"unknown").toLowerCase().replace(/[^a-z0-9]+/g,"-")}
function current(){return workspaces.find(w=>w.id===activeWorkspaceId)||null}
function workspaceName(){return current()?.name||"Workspace"}
function syncFromWorkspace(){let ws=current();parsed=ws?.data||null;cves=ws?.cves||[];checkResults=ws?.checkResults||[]}
function syncToWorkspace(){let ws=current();if(ws){ws.data=parsed;ws.cves=cves;ws.checkResults=checkResults}}
function createWorkspace(){let id=crypto.randomUUID?crypto.randomUUID():String(Date.now());let ws={id,name:`Workspace ${workspaces.length+1}`,data:null,cves:[],checkResults:[],files:[]};workspaces.unshift(ws);activeWorkspaceId=id;renderWorkspaceList();renderActive();return ws}
function setWorkspace(id){if(activeWorkspaceId&&activeWorkspaceId!==id)syncToWorkspace();activeWorkspaceId=id;renderWorkspaceList();renderActive()}
function renderWorkspaceList(){let root=$("#workspaceList");root.replaceChildren();workspaces.forEach(ws=>{let b=document.createElement("button");b.type="button";b.className=`workspace-item ${ws.id===activeWorkspaceId?"active":""}`;let s=ws.data?.summary||{};b.innerHTML=`<span class="workspace-name">${ws.name}</span><span class="muted">${fmt(s.file_count||ws.files.length)} files · ${fmt(s.host_count)} hosts · ${fmt(s.cve_count)} CVEs</span>`;b.addEventListener("click",()=>setWorkspace(ws.id));root.append(b)})}
function renderFileList(files=[]){let root=$("#fileList");root.replaceChildren();files.forEach(file=>{let row=document.createElement("div");row.className="file-item";let name=file.name||file;let meta=file.input_type?`${file.input_type} · ${fmt(file.open_port_count)} open ports`:`${fmt(file.size)} bytes`;row.append(Object.assign(document.createElement("span"),{className:"mono",textContent:name}),Object.assign(document.createElement("span"),{className:"muted",textContent:meta}));root.append(row)})}
function renderActive(){syncFromWorkspace();let ws=current();let summary=parsed?.summary||{};renderMetrics(summary);serviceChart(summary.service_counts||{});$("#jsonOut").textContent=parsed?JSON.stringify(parsed,null,2):"{}";$("#downloadBtn").disabled=!parsed;$("#extractBtn").disabled=!parsed;$("#distroSelect").disabled=!cves.length;$("#versionSelect").disabled=!cves.length;$("#checkBtn").disabled=!cves.length;if(ws?.reportUrl){$("#reportLink").href=ws.reportUrl;$("#reportLink").style.display="inline-flex"}else{$("#reportLink").style.display="none"}renderFileList(ws?.files||parsed?.files||[]);renderHosts();if(checkResults.length){renderCheckedCves()}else if(cves.length){renderCveExtracted()}else{let r=$("#cves");r.className="cves empty";r.textContent=parsed?"Extract CVEs for this workspace.":"Bulk parse files to extract CVEs."}msg($("#parseMessage"),parsed?`${workspaceName()} contains ${fmt(summary.file_count||0)} files.`:"Upload one or more files into this workspace.");msg($("#cveMessage"),parsed?"Ready to extract CVEs.":"Parse a workspace first.");renderWorkspaceList()}
function classify(s){let t=String(s||"").toLowerCase().replace(/_/g," ");if(t.includes("lookup failed"))return"Lookup failed";if(t.includes("not found")||t.includes("404"))return"Not found";if(t.includes("out of support")||t.includes("end of life"))return"Out of support";if(t.includes("deferred")||t.includes("will not fix")||t.includes("ignored"))return"Deferred";if(["affected","new","needed","vulnerable","needs evaluation","needs-triage","needs triage"].includes(t)||t.includes("work in progress"))return"Affected";if(t.includes("not affected")||t.includes("not in release")||t==="dne")return"Not affected";if(t.includes("fixed")||t.includes("released")||t.includes("resolved"))return"Fixed";if(t.includes("not listed"))return"Not listed";if(t.includes("pending"))return"Pending";if(t.includes("checking"))return"Checking";return"Unknown"}
function pill(text,type="chip"){let e=document.createElement("span");e.className=type==="status"?`status ${cls(text)}`:"chip";e.textContent=text;return e}
function metric(label,value){let d=document.createElement("div");d.className="card metric";d.innerHTML=`<b>${fmt(value)}</b><span>${label}</span>`;return d}
function renderMetrics(s={}){$("#metrics").replaceChildren(metric("Files",s.file_count),metric("Hosts",s.host_count),metric("Open Ports",s.open_port_count),metric("CVEs",s.cve_count),metric("Runs",s.run_count),metric("Scripts",s.script_count))}
function serviceChart(counts={}){let box=$("#serviceChart");box.replaceChildren();let entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]);if(!entries.length){box.innerHTML='<p class="muted">Services appear after parsing.</p>';return}for(let [name,count] of entries){let row=document.createElement("div");row.className="muted";row.innerHTML=`<span class="mono">${name}</span><b style="float:right;color:var(--text)">${count}</b>`;box.append(row)}}
function activate(id){$$(".tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===id));$$(".panel").forEach(p=>p.classList.toggle("active",p.id===id))}
function scriptText(s){return `${s.id?`${s.id}: `:""}${s.output||JSON.stringify(s.data||"",null,2)}`.trim()}
function searchText(host,port){return [host.address,port.protocol,port.portid,port.state?.state,port.service?.name,port.service?.details,port.source_file,...(port.scripts||[]).map(scriptText)].filter(Boolean).join(" ").toLowerCase()}
function renderHosts(){let root=$("#hosts");root.classList.remove("empty");root.replaceChildren();if(!parsed){root.classList.add("empty");root.textContent="Bulk parse files to build this workspace.";$("#resultCount").textContent="No data loaded";return}let q=$("#filterInput").value.trim().toLowerCase(),shown=0;for(let host of parsed.hosts||[]){let ports=(host.ports||[]).filter(p=>!q||searchText(host,p).includes(q)||String(host.address).toLowerCase().includes(q));if(!ports.length&&!String(host.address).toLowerCase().includes(q))continue;shown++;let card=document.createElement("article");card.className="card host";let meta=document.createElement("div");meta.className="chips";meta.append(pill(`${ports.length} ports`),pill(`runs ${(host.seen_in_runs||[]).join(",")||"1"}`));card.innerHTML=`<div class="host-head"><div><div class="host-ip mono">${host.address||"Unknown host"}</div></div></div>`;card.querySelector(".host-head>div").append(meta);card.querySelector(".host-head").append(pill(host.status?.state||"unknown","status"));let list=document.createElement("div");list.className="ports";let head=document.createElement("div");head.className="port-head";["Port","State","Service","Details","Scripts"].forEach(x=>{let c=document.createElement("div");c.textContent=x;head.append(c)});list.append(head);for(let p of ports){let row=document.createElement("div");row.className="port";let details=[p.service?.product,p.service?.version,p.service?.extrainfo,p.service?.details,`runs ${(p.seen_in_runs||[]).join(",")}`].filter(Boolean).join(" ")||"No service details";row.append(Object.assign(document.createElement("div"),{className:"mono",textContent:`${p.portid}/${p.protocol}`}),pill(p.state?.state||"unknown","status"),Object.assign(document.createElement("div"),{className:"mono",textContent:p.service?.name||"unknown"}),Object.assign(document.createElement("div"),{className:"detail",textContent:details,title:details}));if((p.scripts||[]).length){let d=document.createElement("details");d.className="scripts";let s=document.createElement("summary");s.textContent=`${p.scripts.length} scripts`;d.append(s);for(let sc of p.scripts){let pre=document.createElement("pre");pre.className="script mono";pre.textContent=scriptText(sc);d.append(pre)}row.append(d)}else row.append(pill("No scripts"));list.append(row)}card.append(list);root.append(card)}$("#resultCount").textContent=`${workspaceName()} · ${shown} hosts shown · ${fmt(parsed.summary?.file_count)} files combined`;if(!shown){root.classList.add("empty");root.textContent="No hosts match the current filter."}}
function extractLocal(v){let out=new Set();function walk(x){if(Array.isArray(x))x.forEach(walk);else if(x&&typeof x==="object")Object.entries(x).forEach(([k,val])=>{walk(k);walk(val)});else if(x!==undefined&&x!==null){for(let m of String(x).match(cveRe)||[])out.add(m.toUpperCase())}}walk(v);return [...out].sort()}
function renderCveExtracted(){let root=$("#cves");root.classList.remove("empty");root.replaceChildren();if(!cves.length){root.classList.add("empty");root.textContent="No CVEs found.";return}let top=document.createElement("div");top.className="cve-top";top.innerHTML=`<b>${cves.length} CVEs extracted</b><span class="muted">${workspaceName()} · ${$("#distroSelect").value.toUpperCase()} ${$("#versionSelect").value}</span>`;let chips=document.createElement("div");chips.className="chips";cves.forEach(c=>chips.append(pill(c)));root.append(top,chips)}
function countBadges(){let row=$("#countRow");if(!row)return;let order=["Affected","Fixed","Not affected","Deferred","Out of support","Not found","Lookup failed","Not listed","Unknown"];let counts={};checkResults.forEach(r=>counts[r.classification||classify(r.status)]=(counts[r.classification||classify(r.status)]||0)+1);row.replaceChildren();order.filter(k=>counts[k]).forEach(k=>{let e=document.createElement("span");e.className=`count ${cls(k)}`;e.textContent=`${k}: ${counts[k]}`;row.append(e)})}
function cveId(c){return "row-"+c.replace(/[^a-z0-9]/gi,"-")}
function cveCard(r){let classification=r.classification||classify(r.status);let card=document.createElement("article");card.className="card cve-card";card.id=cveId(r.cve);let head=document.createElement("div");head.className="cve-head";head.append(Object.assign(document.createElement("b"),{className:"mono",textContent:r.cve}),pill(classification,"status"),Object.assign(document.createElement("span"),{className:"muted",textContent:r.severity||"Severity unavailable"}),Object.assign(document.createElement("span"),{className:"muted",textContent:r.score?`CVSS ${r.score}`:""}));let body=document.createElement("div");body.className="cve-body";body.append(Object.assign(document.createElement("div"),{className:"muted",textContent:r.summary||"No vendor summary."}));if(r.status&&r.status!==classification)body.append(Object.assign(document.createElement("div"),{className:"muted",textContent:`Vendor status: ${r.status}`}));let ai=r.ai_review;if(ai&&ai.enabled&&ai.status==="ok"){let box=document.createElement("div");box.className="ai-review";box.append(Object.assign(document.createElement("strong"),{textContent:`Groq cross-check · ${ai.classification||"Unknown"} · ${ai.confidence||"medium"} confidence`}));[ai.plain_language_summary,ai.evidence,ai.next_action?`Next: ${ai.next_action}`:""].filter(Boolean).forEach(v=>box.append(Object.assign(document.createElement("div"),{className:"muted",textContent:v})));body.append(box)}else if(ai&&ai.enabled&&ai.message){body.append(Object.assign(document.createElement("div"),{className:"muted",textContent:`Groq cross-check unavailable: ${ai.message}`}))}if(r.url){let a=document.createElement("a");a.href=r.url;a.target="_blank";a.rel="noreferrer";a.textContent=r.url;body.append(a)}(r.records||[]).forEach(rec=>{let rr=document.createElement("div");rr.className="record";[rec.package||"package unavailable",rec.product||"product unavailable",rec.status||"status unavailable",rec.detail||""].forEach(v=>rr.append(Object.assign(document.createElement("div"),{textContent:v})));body.append(rr)});card.append(head,body);return card}
function startChecks(){let root=$("#cves");root.classList.remove("empty");root.replaceChildren();let top=document.createElement("div");top.className="cve-top";top.innerHTML=`<b>${cves.length} CVEs queued</b><span id="progress" class="muted">0 / ${cves.length} checked</span><div id="countRow" class="count-row"></div>`;root.append(top);let list=document.createElement("div");list.className="cves";cves.forEach(c=>list.append(cveCard({cve:c,status:"Pending",summary:"Waiting to check vendor endpoint...",records:[]})));root.append(list);checkResults=[];syncToWorkspace();countBadges()}
function renderCheckedCves(){let root=$("#cves");root.classList.remove("empty");root.replaceChildren();let top=document.createElement("div");top.className="cve-top";top.innerHTML=`<b>${checkResults.length} CVEs checked</b><span class="muted">${workspaceName()}</span><div id="countRow" class="count-row"></div>`;root.append(top);let list=document.createElement("div");list.className="cves";checkResults.forEach(r=>list.append(cveCard(r)));root.append(list);countBadges()}
function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms))}
async function checkOne(cve,distro,version){let res=await fetch("/api/check-cve",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cve,distro,version})});let body=await res.json();if(!res.ok)throw new Error(body.error||"Lookup failed");return body.result}
function populateVersions(){let sel=$("#versionSelect");sel.replaceChildren();(versions[$("#distroSelect").value]||[]).forEach(v=>{let o=document.createElement("option");o.value=v;o.textContent=v;sel.append(o)})}
$("#newWorkspaceBtn").addEventListener("click",()=>createWorkspace());
$("#uploadForm").addEventListener("submit",async e=>{e.preventDefault();let ws=current()||createWorkspace(),files=[...$("#fileInput").files];if(!files.length){msg($("#parseMessage"),"Choose one or more files first.",true);return}$("#parseBtn").disabled=true;msg($("#parseMessage"),`Parsing ${files.length} files into ${ws.name}...`);let fd=new FormData();files.forEach(file=>fd.append("scan_files",file));try{let res=await fetch("/api/parse-workspace",{method:"POST",headers:{"X-Workspace-Name":ws.name},body:fd});let body=await res.json();if(!res.ok)throw new Error(body.error||"Workspace parse failed");ws.data=body;ws.files=body.files||files.map(f=>({name:f.name,size:f.size}));ws.cves=[];ws.checkResults=[];setWorkspace(ws.id);msg($("#parseMessage"),`Parsed ${files.length} files into ${ws.name}.`);msg($("#cveMessage"),"Ready to extract workspace CVEs.");activate("hostsPanel")}catch(err){msg($("#parseMessage"),err.message,true)}finally{$("#parseBtn").disabled=false}});
$("#extractBtn").addEventListener("click",async()=>{if(!parsed)return;let ws=current();$("#extractBtn").disabled=true;msg($("#cveMessage"),"Extracting CVEs from combined workspace...");try{let res=await fetch("/api/extract-cves",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scan_data:parsed})});let body=await res.json();if(!res.ok)throw new Error(body.error||"Extraction failed");cves=body.cves||[]}catch{cves=extractLocal(parsed)}finally{checkResults=[];if(ws){ws.cves=cves;ws.checkResults=[]}$("#extractBtn").disabled=false;$("#distroSelect").disabled=!cves.length;$("#versionSelect").disabled=!cves.length;$("#checkBtn").disabled=!cves.length;msg($("#cveMessage"),cves.length?`${cves.length} unique CVEs extracted from ${workspaceName()}.`:"No CVEs found.",!cves.length);renderCveExtracted();renderWorkspaceList();activate("cvesPanel")}});
$("#checkBtn").addEventListener("click",async()=>{if(!cves.length)return;let ws=current(),distro=$("#distroSelect").value,version=$("#versionSelect").value;$("#checkBtn").disabled=true;startChecks();activate("cvesPanel");msg($("#cveMessage"),`Checking ${cves.length} CVEs for ${workspaceName()}...`);let done=0;for(let c of cves){document.getElementById(cveId(c))?.replaceWith(cveCard({cve:c,status:"Checking",summary:"Requesting vendor API...",records:[]}));try{let r=await checkOne(c,distro,version);checkResults.push(r);document.getElementById(cveId(c))?.replaceWith(cveCard(r))}catch(err){let r={cve:c,status:"Lookup failed",classification:"Lookup failed",summary:err.message,records:[]};checkResults.push(r);document.getElementById(cveId(c))?.replaceWith(cveCard(r))}if(ws)ws.checkResults=checkResults;done++;$("#progress").textContent=`${done} / ${cves.length} checked`;countBadges();if(done<cves.length){msg($("#cveMessage"),`Checked ${done} / ${cves.length}. Waiting 2 seconds before the next request...`);await sleep(2000)}}msg($("#cveMessage"),`Complete: ${done} CVEs checked.`);$("#checkBtn").disabled=false;renderWorkspaceList()});
$("#fileInput").addEventListener("change",()=>{let files=[...$("#fileInput").files];$("#fileName").textContent=files.length?`${files.length} files selected`:"XML, TXT, NMAP, JSON, logs, or raw text.";renderFileList(files)});
$("#dropZone").addEventListener("dragover",e=>{e.preventDefault();$("#dropZone").classList.add("drag")});$("#dropZone").addEventListener("dragleave",()=>$("#dropZone").classList.remove("drag"));$("#dropZone").addEventListener("drop",e=>{e.preventDefault();$("#dropZone").classList.remove("drag");if(e.dataTransfer.files.length){$("#fileInput").files=e.dataTransfer.files;$("#fileInput").dispatchEvent(new Event("change"))}});
$("#filterInput").addEventListener("input",renderHosts);$$(".tab").forEach(b=>b.addEventListener("click",()=>activate(b.dataset.tab)));$("#downloadBtn").addEventListener("click",async()=>{if(!parsed)return;let ws=current();$("#downloadBtn").disabled=true;msg($("#parseMessage"),"Exporting shareable report...");try{let res=await fetch("/api/export-workspace",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({workspace:parsed,workspace_name:workspaceName(),cves,check_results:checkResults})});let body=await res.json();if(!res.ok)throw new Error(body.error||"Export failed");if(ws){ws.reportUrl=body.url;ws.reportId=body.report_id}$("#reportLink").href=body.url;$("#reportLink").style.display="inline-flex";msg($("#parseMessage"),`Report exported: ${body.url}`);window.open(body.url,"_blank","noopener")}catch(err){msg($("#parseMessage"),err.message,true)}finally{$("#downloadBtn").disabled=!parsed;renderWorkspaceList()}});
$("#themeBtn").addEventListener("click",()=>{let html=document.documentElement,next=html.dataset.theme==="dark"?"light":"dark";html.dataset.theme=next;localStorage.setItem("theme",next);$("#themeBtn").textContent=next==="dark"?"Dark":"Light"});let saved=localStorage.getItem("theme")||"light";document.documentElement.dataset.theme=saved;$("#themeBtn").textContent=saved==="dark"?"Dark":"Light";populateVersions();$("#distroSelect").addEventListener("change",()=>{populateVersions();if(cves.length)renderCveExtracted()});createWorkspace();
</script>
</body>
</html>"""


class AppHandler(BaseHTTPRequestHandler):
    server_version = "ScanLens/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        LOG.info("client=%s %s", self.address_string(), fmt % args)

    def get_session_id(self) -> str:
        existing = getattr(self, "session_id", None)
        if existing:
            return existing
        cookie_header = self.headers.get("Cookie", "")
        cookie = SimpleCookie()
        if cookie_header:
            cookie.load(cookie_header)
        morsel = cookie.get(SESSION_COOKIE)
        session_id = morsel.value if morsel and SESSION_ID_RE.fullmatch(morsel.value) else new_session_id()
        self.session_id = session_id
        session_directory(session_id)
        return session_id

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        LOG.debug("GET path=%s", path)
        report_id = path.strip("/")
        if REPORT_ID_RE.fullmatch(report_id):
            self.handle_public_report(report_id)
            return
        if path in {"/", "/index.html"}:
            self.get_session_id()
            self.send_bytes(HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/health":
            self.send_json({"ok": True, "app": APP_NAME})
            return
        if path == "/api/session":
            session_id = self.get_session_id()
            self.send_json({
                "session_id": session_id,
                "path": session_relative(session_directory(session_id)),
                "groq": {
                    "enabled": groq_enabled(),
                    "model": os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT),
                    "base_url": os.environ.get("GROQ_BASE_URL", GROQ_BASE_URL_DEFAULT),
                },
            })
            return
        self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        LOG.debug("POST path=%s content_length=%s", path, self.headers.get("Content-Length", "0"))
        if path == "/api/parse":
            self.handle_parse()
        elif path == "/api/parse-workspace":
            self.handle_parse_workspace()
        elif path == "/api/extract-cves":
            self.handle_extract()
        elif path == "/api/check-cve":
            self.handle_check_cve()
        elif path == "/api/check-cves":
            self.handle_check_cves()
        elif path == "/api/export-workspace":
            self.handle_export_workspace()
        else:
            self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            raise ValueError("Empty request body.")
        if length > MAX_UPLOAD_BYTES:
            raise ValueError(f"Request body exceeds {MAX_UPLOAD_BYTES} bytes.")
        return self.rfile.read(length)

    def read_json(self) -> dict[str, Any]:
        try:
            return json.loads(self.read_body().decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid JSON payload.") from exc

    def handle_public_report(self, report_id: str) -> None:
        started = time.perf_counter()
        try:
            path = find_report(report_id)
            if not path:
                self.send_json({"error": "Report not found"}, HTTPStatus.NOT_FOUND)
                return
            report = json.loads(path.read_text(encoding="utf-8"))
            LOG.info("report_view id=%s path=%s elapsed_ms=%.1f", report_id, session_relative(path), elapsed_ms(started))
            self.send_bytes(render_public_report(report).encode("utf-8"), "text/html; charset=utf-8")
        except Exception as exc:
            LOG.exception("report_view failed id=%s elapsed_ms=%.1f", report_id, elapsed_ms(started))
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_parse(self) -> None:
        started = time.perf_counter()
        try:
            session_id = self.get_session_id()
            filename, payload = parse_multipart_file(self.headers.get("Content-Type", ""), self.read_body())
            stored = persist_session_uploads(session_id, [(filename, payload)])
            update_session_manifest(session_id, stored)
            text = payload.decode("utf-8-sig", errors="replace")
            data = convert_content(text, filename)
            data["session"] = {"id": session_id, "path": session_relative(session_directory(session_id)), "files": stored}
            LOG.info("parse ok session=%s file=%s type=%s hosts=%s runs=%s cves=%s elapsed_ms=%.1f", session_id, filename, data["summary"]["input_type"], data["summary"]["host_count"], data["summary"]["run_count"], data["summary"]["cve_count"], elapsed_ms(started))
            self.send_json(data)
        except Exception as exc:
            LOG.exception("parse failed elapsed_ms=%.1f", elapsed_ms(started))
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_parse_workspace(self) -> None:
        started = time.perf_counter()
        try:
            session_id = self.get_session_id()
            uploads = parse_multipart_files(self.headers.get("Content-Type", ""), self.read_body())
            stored = persist_session_uploads(session_id, uploads)
            documents = []
            for index, (filename, payload) in enumerate(uploads):
                text = payload.decode("utf-8-sig", errors="replace")
                document = convert_content(text, filename)
                documents.append(document)
                if index < len(stored):
                    document.setdefault("session_file", stored[index])
                LOG.debug(
                    "workspace_file parsed session=%s file=%s type=%s hosts=%s runs=%s cves=%s",
                    session_id,
                    filename,
                    document["summary"]["input_type"],
                    document["summary"]["host_count"],
                    document["summary"]["run_count"],
                    document["summary"]["cve_count"],
                )
            workspace_name = self.headers.get("X-Workspace-Name", "Workspace")
            data = merge_parsed_documents(documents, workspace_name)
            for index, item in enumerate(data.get("files", [])):
                if index < len(stored):
                    item.update({"stored_path": stored[index]["stored_path"], "size": stored[index]["size"]})
            workspace_path = session_directory(session_id) / f"{utc_stamp()}_workspace_{sanitize_filename(workspace_name)}.json"
            data["session"] = {
                "id": session_id,
                "path": session_relative(session_directory(session_id)),
                "files": stored,
                "workspace_path": session_relative(workspace_path),
            }
            write_json_file(workspace_path, data)
            update_session_manifest(session_id, stored, {
                "name": workspace_name,
                "stored_path": session_relative(workspace_path),
                "summary": data.get("summary", {}),
                "stored_at": utc_stamp(),
            })
            LOG.info(
                "parse_workspace ok session=%s workspace=%s files=%s hosts=%s runs=%s cves=%s stored=%s elapsed_ms=%.1f",
                session_id,
                workspace_name,
                len(uploads),
                data["summary"]["host_count"],
                data["summary"]["run_count"],
                data["summary"]["cve_count"],
                session_relative(workspace_path),
                elapsed_ms(started),
            )
            self.send_json(data)
        except Exception as exc:
            LOG.exception("parse_workspace failed elapsed_ms=%.1f", elapsed_ms(started))
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_extract(self) -> None:
        started = time.perf_counter()
        try:
            payload = self.read_json()
            found = extract_cves(payload.get("scan_data", payload))
            LOG.info("extract_cves ok count=%s elapsed_ms=%.1f values=%s", len(found), elapsed_ms(started), found)
            self.send_json({"cves": found, "count": len(found)})
        except Exception as exc:
            LOG.exception("extract_cves failed")
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def validate_target(self, payload: dict[str, Any]) -> tuple[str, str]:
        distro = str(payload.get("distro", "")).lower()
        version = str(payload.get("version", ""))
        if distro not in {"rhel", "ubuntu"}:
            raise ValueError("Choose rhel or ubuntu.")
        if distro == "rhel" and version not in RHEL_VERSIONS:
            raise ValueError("Unsupported RHEL version.")
        if distro == "ubuntu" and version not in UBUNTU_RELEASES:
            raise ValueError("Unsupported Ubuntu version.")
        return distro, version

    def handle_check_cve(self) -> None:
        started = time.perf_counter()
        try:
            payload = self.read_json()
            distro, version = self.validate_target(payload)
            cve = normalize_cve(payload.get("cve", ""))
            if not cve:
                raise ValueError("No valid CVE provided.")
            result = check_cve(cve, distro, version)
            LOG.info("check_cve response cve=%s class=%s elapsed_ms=%.1f", cve, result.get("classification"), elapsed_ms(started))
            self.send_json({"distro": distro, "version": version, "result": result})
        except Exception as exc:
            LOG.exception("check_cve failed")
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_check_cves(self) -> None:
        started = time.perf_counter()
        try:
            payload = self.read_json()
            distro, version = self.validate_target(payload)
            items = sorted({cve for cve in (normalize_cve(item) for item in payload.get("cves", [])) if cve})
            if not items:
                raise ValueError("No CVEs provided.")
            results = [check_cve(cve, distro, version) for cve in items]
            LOG.info("check_cves response count=%s elapsed_ms=%.1f", len(results), elapsed_ms(started))
            self.send_json({"distro": distro, "version": version, "results": results})
        except Exception as exc:
            LOG.exception("check_cves failed")
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def handle_export_workspace(self) -> None:
        started = time.perf_counter()
        try:
            session_id = self.get_session_id()
            payload = self.read_json()
            workspace = payload.get("workspace")
            if not isinstance(workspace, dict):
                raise ValueError("No workspace object provided.")
            workspace_name = str(payload.get("workspace_name") or workspace.get("summary", {}).get("source_file") or "Workspace")
            cves = payload.get("cves") if isinstance(payload.get("cves"), list) else extract_cves(workspace)
            check_results = payload.get("check_results") if isinstance(payload.get("check_results"), list) else []
            stored = persist_report(session_id, workspace, cves, check_results, workspace_name)
            report = stored["report"]
            url = f"/{report['report_id']}"
            LOG.info("export_workspace ok session=%s report=%s workspace=%s path=%s elapsed_ms=%.1f", session_id, report["report_id"], workspace_name, session_relative(stored["path"]), elapsed_ms(started))
            self.send_json({
                "report_id": report["report_id"],
                "url": url,
                "path": session_relative(stored["path"]),
                "plain_summary": report.get("plain_summary", {}),
            })
        except Exception as exc:
            LOG.exception("export_workspace failed elapsed_ms=%.1f", elapsed_ms(started))
            self.send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def send_json(self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def send_bytes(self, payload: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'")
        self.send_header("Content-Length", str(len(payload)))
        session_id = getattr(self, "session_id", None)
        if session_id:
            self.send_header("Set-Cookie", f"{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(payload)


def configure_logging() -> None:
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s %(levelname)s %(name)s %(message)s", handlers=[logging.StreamHandler()])
    LOG.debug("logging configured level=DEBUG output=terminal")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the self-contained ScanLens web app.")
    parser.add_argument("--host", default="0.0.0.0", help="Host/interface to bind. Defaults to 0.0.0.0 for Linux hosting.")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    configure_logging()
    load_env_file()
    LOG.info(
        "groq_config enabled=%s model=%s base_url=%s",
        groq_enabled(),
        os.environ.get("GROQ_MODEL", GROQ_MODEL_DEFAULT),
        os.environ.get("GROQ_BASE_URL", GROQ_BASE_URL_DEFAULT),
    )
    SESSIONS_ROOT.mkdir(parents=True, exist_ok=True)
    LOG.info("sessions_root path=%s", session_relative(SESSIONS_ROOT))
    server = ThreadingHTTPServer((args.host, args.port), AppHandler)
    LOG.info("server_start url=http://%s:%s", args.host, args.port)
    print(f"{APP_NAME} running at http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("server_stop reason=keyboard_interrupt")
    finally:
        server.server_close()
        LOG.info("server_closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
