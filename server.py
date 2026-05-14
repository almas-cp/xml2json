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
import json
import logging
import re
import sys
import time
from collections import Counter
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
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

RHEL_VERSIONS = ["6", "7", "8", "9", "10"]
UBUNTU_RELEASES = {
    "18.04": ["18.04", "bionic"],
    "20.04": ["20.04", "focal"],
    "22.04": ["22.04", "jammy"],
    "24.04": ["24.04", "noble"],
    "26.04": ["26.04", "resolute"],
}


def elapsed_ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


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
                stored["service"] = {**stored.get("service", {}), **port.get("service", {})}
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


def normalize_existing_json(data: Any, source_name: str) -> dict[str, Any]:
    if isinstance(data, dict) and {"summary", "hosts", "runs"}.issubset(data):
        out = data
        out.setdefault("summary", {})
        out["summary"].setdefault("source_file", source_name)
        out["summary"].setdefault("input_type", "json")
        out["summary"]["cve_count"] = len(extract_cves(out))
        return out
    runs = [{"run_index": 1, "source_format": "json", "scanner": "unknown", "scaninfo": [], "hosts": [], "raw_json": data}]
    hosts: list[dict[str, Any]] = []
    return {"summary": build_summary(source_name, "json", runs, hosts, data), "hosts": hosts, "runs": runs, "raw": data}


def convert_content(scan_text: str, source_name: str = "uploaded file") -> dict[str, Any]:
    if not scan_text.strip():
        raise ValueError(f"Input file is empty: {source_name}")

    stripped = scan_text.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            return normalize_existing_json(json.loads(scan_text), source_name)
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
            result = summarize_redhat(cve, version, fetch_json(url), url)
        else:
            url = f"https://ubuntu.com/security/cves/{cve}.json"
            result = summarize_ubuntu(cve, version, fetch_json(url), url)
        LOG.info("cve_lookup ok cve=%s distro=%s version=%s classification=%s records=%s elapsed_ms=%.1f", cve, distro, version, result["classification"], len(result["records"]), elapsed_ms(started))
        return result
    except HTTPError as exc:
        status = "Not found" if exc.code == 404 else "Lookup failed"
        LOG.warning("cve_lookup http_error cve=%s distro=%s version=%s code=%s elapsed_ms=%.1f", cve, distro, version, exc.code, elapsed_ms(started))
        return enrich({"cve": cve, "status": status, "severity": "", "score": "", "summary": f"HTTP Error {exc.code}: {exc.reason}", "url": url if "url" in locals() else "", "records": []})
    except Exception as exc:
        LOG.exception("cve_lookup failed cve=%s distro=%s version=%s elapsed_ms=%.1f", cve, distro, version, elapsed_ms(started))
        return enrich({"cve": cve, "status": "Lookup failed", "severity": "", "score": "", "summary": str(exc), "url": url if "url" in locals() else "", "records": []})


def parse_multipart_file(content_type: str, body: bytes) -> tuple[str, bytes]:
    if "multipart/form-data" not in content_type:
        raise ValueError("Expected multipart/form-data upload.")
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
    )
    for part in message.iter_parts():
        if part.get_param("name", header="content-disposition") != "scan_file":
            continue
        filename = part.get_filename() or "uploaded-scan"
        payload = part.get_payload(decode=True) or b""
        if not payload.strip():
            raise ValueError(f"Input file is empty: {filename}")
        return filename, payload
    raise ValueError("No file field named scan_file was found.")


HTML = r"""<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScanLens</title>
<style>
:root{color-scheme:light;--bg:#f4f7fb;--panel:#ffffff;--panel2:#f8fafc;--text:#122033;--muted:#66758a;--line:#dbe4ef;--accent:#0f766e;--accent2:#2563eb;--bad:#b42318;--warn:#b7791f;--ok:#0f766e;--violet:#6d28d9;--shadow:0 18px 50px rgba(18,32,51,.08)}
[data-theme=dark]{color-scheme:dark;--bg:#0b1120;--panel:#111827;--panel2:#172033;--text:#e5edf8;--muted:#94a3b8;--line:#263348;--accent:#2dd4bf;--accent2:#60a5fa;--bad:#fb7185;--warn:#fbbf24;--ok:#34d399;--violet:#a78bfa;--shadow:0 20px 60px rgba(0,0,0,.28)}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top left,rgba(37,99,235,.12),transparent 32rem),var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer}a{color:var(--accent2);overflow-wrap:anywhere}.shell{min-height:100vh}.top{position:sticky;top:0;z-index:10;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:18px 24px;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--panel) 92%,transparent);backdrop-filter:blur(18px)}.brand{display:flex;gap:14px;align-items:center}.mark{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:var(--shadow)}h1{font-size:22px;margin:0;letter-spacing:0}.sub{margin:2px 0 0;color:var(--muted);font-size:13px}.top-actions{display:flex;gap:10px;align-items:center}.btn,.select,.search{border:1px solid var(--line);border-radius:10px;background:var(--panel2);color:var(--text);min-height:40px;padding:0 12px}.btn{font-weight:750}.btn.primary{background:var(--accent);border-color:var(--accent);color:#06201d}.btn.ghost{background:transparent}.btn:disabled,.select:disabled{opacity:.5;cursor:not-allowed}.grid{display:grid;grid-template-columns:340px minmax(0,1fr);gap:18px;max-width:1500px;margin:0 auto;padding:18px}.side{display:grid;align-content:start;gap:14px;position:sticky;top:92px}.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}.pad{padding:16px}.title{font-size:13px;font-weight:850;text-transform:uppercase;letter-spacing:.04em}.drop{display:grid;gap:8px;align-content:center;min-height:138px;margin-top:14px;padding:18px;border:1px dashed color-mix(in srgb,var(--muted) 70%,transparent);border-radius:14px;background:var(--panel2)}.drop:hover,.drop.drag{border-color:var(--accent);background:color-mix(in srgb,var(--accent) 10%,var(--panel2))}.drop input{display:none}.drop strong{font-size:18px}.muted{color:var(--muted);font-size:13px;line-height:1.45}.stack{display:grid;gap:10px}.message{min-height:20px;margin-top:10px;color:var(--muted);font-size:13px}.message.error{color:var(--bad)}.metrics{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:10px}.metric{padding:14px;border-top:3px solid color-mix(in srgb,var(--accent2) 35%,var(--line))}.metric b{font-size:26px}.metric span{display:block;margin-top:6px;color:var(--muted);font-size:11px;font-weight:800;text-transform:uppercase}.main{display:grid;gap:14px;min-width:0}.toolbar{display:grid;grid-template-columns:1fr minmax(240px,460px);gap:12px;align-items:center;padding:16px;border-bottom:1px solid var(--line)}.tabs{display:flex;gap:6px;padding:10px 16px 0}.tab{min-height:36px;padding:0 14px;border:0;border-radius:10px;background:transparent;color:var(--muted);font-weight:800}.tab.active{background:var(--panel2);color:var(--text)}.panel{display:none;padding:16px}.panel.active{display:block}.empty{display:grid;min-height:330px;place-items:center;border:1px dashed var(--line);border-radius:14px;background:var(--panel2);color:var(--muted);text-align:center}.hosts,.cves{display:grid;gap:12px}.host{overflow:hidden}.host-head{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:15px;background:var(--panel2);border-bottom:1px solid var(--line)}.mono{font-family:"Cascadia Mono",Consolas,monospace}.host-ip{font-size:18px;font-weight:850;overflow-wrap:anywhere}.chips{display:flex;flex-wrap:wrap;gap:7px;margin-top:8px}.chip,.status{display:inline-flex;align-items:center;min-height:25px;padding:0 9px;border-radius:999px;font-size:11px;font-weight:850;text-transform:uppercase}.chip{background:color-mix(in srgb,var(--muted) 16%,transparent);color:var(--muted)}.status{background:var(--muted);color:white}.status-open,.status-up,.status-fixed{background:var(--ok)}.status-affected,.status-lookup-failed{background:var(--bad)}.status-deferred{background:var(--warn);color:#1f1600}.status-out-of-support{background:var(--violet)}.status-not-affected,.status-not-found,.status-not-listed,.status-pending,.status-checking,.status-unknown{background:#64748b}.ports{display:grid}.port-head,.port{display:grid;grid-template-columns:105px 96px minmax(120px,190px) minmax(0,1fr) auto;gap:12px}.port-head{padding:10px 14px;background:var(--panel2);border-bottom:1px solid var(--line);color:var(--muted);font-size:11px;font-weight:850;text-transform:uppercase}.port{align-items:center;padding:12px 14px;border-bottom:1px solid var(--line)}.port:last-child{border-bottom:0}.detail{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:13px}details.scripts{grid-column:1/-1}details.scripts summary{display:inline-flex;min-height:30px;align-items:center;padding:0 10px;border-radius:10px;background:color-mix(in srgb,var(--accent2) 14%,transparent);color:var(--accent2);font-size:12px;font-weight:850;list-style:none}details.scripts summary::-webkit-details-marker{display:none}.script{max-height:220px;overflow:auto;margin:10px 0 0;padding:12px;border-radius:12px;background:#0f1724;color:#dbeafe;font-size:12px;line-height:1.5;white-space:pre-wrap}.cve-top{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:space-between;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--panel2)}.count-row{display:flex;flex-basis:100%;flex-wrap:wrap;gap:7px}.count{display:inline-flex;min-height:26px;align-items:center;padding:0 9px;border-radius:999px;color:#fff;font-size:11px;font-weight:850;text-transform:uppercase}.cve-card{overflow:hidden}.cve-head{display:grid;grid-template-columns:150px 130px minmax(0,1fr) 96px;gap:12px;align-items:center;padding:12px;background:var(--panel2);border-bottom:1px solid var(--line)}.cve-body{display:grid;gap:10px;padding:12px}.record{display:grid;grid-template-columns:minmax(110px,180px) minmax(0,1fr) minmax(95px,140px) minmax(0,1fr);gap:10px;padding-top:9px;border-top:1px solid var(--line);font-size:13px}pre.json{max-height:calc(100vh - 230px);min-height:420px;overflow:auto;margin:0;padding:14px;border-radius:12px;background:#0f1724;color:#dbeafe;font-size:12px;line-height:1.55}
@media(max-width:1050px){.grid{grid-template-columns:1fr}.side{position:static;grid-template-columns:1fr 1fr}.metrics{grid-template-columns:repeat(3,1fr)}}@media(max-width:760px){.top,.toolbar,.host-head{display:grid;grid-template-columns:1fr}.side,.metrics{grid-template-columns:1fr}.port-head{display:none}.port{grid-template-columns:90px 92px 1fr}.detail,details.scripts{grid-column:1/-1;white-space:normal}.cve-head,.record{grid-template-columns:1fr}.top-actions{display:grid}}
</style>
</head>
<body>
<div class="shell">
  <header class="top">
    <div class="brand"><div class="mark"></div><div><h1>ScanLens</h1><p class="sub">Self-contained scan parser, CVE extractor, and Linux advisory cross-checker.</p></div></div>
    <div class="top-actions"><button class="btn ghost" id="themeBtn">Light</button><button class="btn" id="downloadBtn" disabled>Download JSON</button></div>
  </header>
  <main class="grid">
    <aside class="side">
      <section class="card pad">
        <div class="title">Input Artifact</div>
        <form id="uploadForm" class="stack">
          <label class="drop" id="dropZone"><input id="fileInput" name="scan_file" type="file"><strong>Drop or choose a file</strong><span id="fileName" class="muted">XML, TXT, NMAP, JSON, logs, or raw text.</span></label>
          <button class="btn primary" id="parseBtn" type="submit">Parse File</button>
        </form>
        <div id="parseMessage" class="message">Waiting for an upload.</div>
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
const $=s=>document.querySelector(s);const $$=s=>[...document.querySelectorAll(s)];
const versions={rhel:["6","7","8","9","10"],ubuntu:["18.04","20.04","22.04","24.04","26.04"]};
const cveRe=/\bCVE-\d{4}-\d{4,7}\b/gi;let parsed=null,cves=[],checkResults=[];
function msg(el,text,bad=false){el.textContent=text;el.classList.toggle("error",bad)}
function fmt(v){return typeof v==="string"?v:new Intl.NumberFormat().format(v||0)}
function cls(v){return "status-"+String(v||"unknown").toLowerCase().replace(/[^a-z0-9]+/g,"-")}
function classify(s){let t=String(s||"").toLowerCase().replace(/_/g," ");if(t.includes("lookup failed"))return"Lookup failed";if(t.includes("not found")||t.includes("404"))return"Not found";if(t.includes("out of support")||t.includes("end of life"))return"Out of support";if(t.includes("deferred")||t.includes("will not fix")||t.includes("ignored"))return"Deferred";if(["affected","new","needed","vulnerable","needs evaluation","needs-triage","needs triage"].includes(t)||t.includes("work in progress"))return"Affected";if(t.includes("not affected")||t.includes("not in release")||t==="dne")return"Not affected";if(t.includes("fixed")||t.includes("released")||t.includes("resolved"))return"Fixed";if(t.includes("not listed"))return"Not listed";if(t.includes("pending"))return"Pending";if(t.includes("checking"))return"Checking";return"Unknown"}
function pill(text,type="chip"){let e=document.createElement("span");e.className=type==="status"?`status ${cls(text)}`:"chip";e.textContent=text;return e}
function metric(label,value){let d=document.createElement("div");d.className="card metric";d.innerHTML=`<b>${fmt(value)}</b><span>${label}</span>`;return d}
function renderMetrics(s={}){$("#metrics").replaceChildren(metric("Runs",s.run_count),metric("Hosts",s.host_count),metric("Open Ports",s.open_port_count),metric("Scripts",s.script_count),metric("CVEs",s.cve_count),metric("Format",s.input_type?String(s.input_type).toUpperCase():"--"))}
function serviceChart(counts={}){let box=$("#serviceChart");box.replaceChildren();let entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]);if(!entries.length){box.innerHTML='<p class="muted">Services appear after parsing.</p>';return}for(let [name,count] of entries){let row=document.createElement("div");row.className="muted";row.innerHTML=`<span class="mono">${name}</span><b style="float:right;color:var(--text)">${count}</b>`;box.append(row)}}
function activate(id){$$(".tab").forEach(b=>b.classList.toggle("active",b.dataset.tab===id));$$(".panel").forEach(p=>p.classList.toggle("active",p.id===id))}
function scriptText(s){return `${s.id?`${s.id}: `:""}${s.output||JSON.stringify(s.data||"",null,2)}`.trim()}
function searchText(host,port){return [host.address,port.protocol,port.portid,port.state?.state,port.service?.name,port.service?.details,...(port.scripts||[]).map(scriptText)].filter(Boolean).join(" ").toLowerCase()}
function renderHosts(){let root=$("#hosts");root.classList.remove("empty");root.replaceChildren();if(!parsed){root.classList.add("empty");root.textContent="Upload a scan artifact to begin.";return}let q=$("#filterInput").value.trim().toLowerCase(),shown=0;for(let host of parsed.hosts||[]){let ports=(host.ports||[]).filter(p=>!q||searchText(host,p).includes(q)||String(host.address).toLowerCase().includes(q));if(!ports.length&&!String(host.address).toLowerCase().includes(q))continue;shown++;let card=document.createElement("article");card.className="card host";let meta=document.createElement("div");meta.className="chips";meta.append(pill(`${ports.length} ports`),pill(`runs ${(host.seen_in_runs||[]).join(",")||"1"}`));card.innerHTML=`<div class="host-head"><div><div class="host-ip mono">${host.address||"Unknown host"}</div></div></div>`;card.querySelector(".host-head>div").append(meta);card.querySelector(".host-head").append(pill(host.status?.state||"unknown","status"));let list=document.createElement("div");list.className="ports";let head=document.createElement("div");head.className="port-head";["Port","State","Service","Details","Scripts"].forEach(x=>{let c=document.createElement("div");c.textContent=x;head.append(c)});list.append(head);for(let p of ports){let row=document.createElement("div");row.className="port";let details=[p.service?.product,p.service?.version,p.service?.extrainfo,p.service?.details].filter(Boolean).join(" ")||"No service details";row.append(Object.assign(document.createElement("div"),{className:"mono",textContent:`${p.portid}/${p.protocol}`}),pill(p.state?.state||"unknown","status"),Object.assign(document.createElement("div"),{className:"mono",textContent:p.service?.name||"unknown"}),Object.assign(document.createElement("div"),{className:"detail",textContent:details,title:details}));if((p.scripts||[]).length){let d=document.createElement("details");d.className="scripts";let s=document.createElement("summary");s.textContent=`${p.scripts.length} scripts`;d.append(s);for(let sc of p.scripts){let pre=document.createElement("pre");pre.className="script mono";pre.textContent=scriptText(sc);d.append(pre)}row.append(d)}else row.append(pill("No scripts"));list.append(row)}card.append(list);root.append(card)}$("#resultCount").textContent=`${shown} hosts shown`;if(!shown){root.classList.add("empty");root.textContent="No hosts match the current filter."}}
function extractLocal(v){let out=new Set();function walk(x){if(Array.isArray(x))x.forEach(walk);else if(x&&typeof x==="object")Object.entries(x).forEach(([k,val])=>{walk(k);walk(val)});else if(x!==undefined&&x!==null){for(let m of String(x).match(cveRe)||[])out.add(m.toUpperCase())}}walk(v);return [...out].sort()}
function renderCveExtracted(){let root=$("#cves");root.classList.remove("empty");root.replaceChildren();if(!cves.length){root.classList.add("empty");root.textContent="No CVEs found.";return}let top=document.createElement("div");top.className="cve-top";top.innerHTML=`<b>${cves.length} CVEs extracted</b><span class="muted">${$("#distroSelect").value.toUpperCase()} ${$("#versionSelect").value}</span>`;let chips=document.createElement("div");chips.className="chips";cves.forEach(c=>chips.append(pill(c)));root.append(top,chips)}
function countBadges(){let row=$("#countRow");if(!row)return;let order=["Affected","Fixed","Not affected","Deferred","Out of support","Not found","Lookup failed","Not listed","Unknown"];let counts={};checkResults.forEach(r=>counts[r.classification||classify(r.status)]=(counts[r.classification||classify(r.status)]||0)+1);row.replaceChildren();order.filter(k=>counts[k]).forEach(k=>{let e=document.createElement("span");e.className=`count ${cls(k)}`;e.textContent=`${k}: ${counts[k]}`;row.append(e)})}
function cveId(c){return "row-"+c.replace(/[^a-z0-9]/gi,"-")}
function cveCard(r){let classification=r.classification||classify(r.status);let card=document.createElement("article");card.className="card cve-card";card.id=cveId(r.cve);let head=document.createElement("div");head.className="cve-head";head.append(Object.assign(document.createElement("b"),{className:"mono",textContent:r.cve}),pill(classification,"status"),Object.assign(document.createElement("span"),{className:"muted",textContent:r.severity||"Severity unavailable"}),Object.assign(document.createElement("span"),{className:"muted",textContent:r.score?`CVSS ${r.score}`:""}));let body=document.createElement("div");body.className="cve-body";body.append(Object.assign(document.createElement("div"),{className:"muted",textContent:r.summary||"No vendor summary."}));if(r.status&&r.status!==classification)body.append(Object.assign(document.createElement("div"),{className:"muted",textContent:`Vendor status: ${r.status}`}));if(r.url){let a=document.createElement("a");a.href=r.url;a.target="_blank";a.rel="noreferrer";a.textContent=r.url;body.append(a)}(r.records||[]).forEach(rec=>{let rr=document.createElement("div");rr.className="record";[rec.package||"package unavailable",rec.product||"product unavailable",rec.status||"status unavailable",rec.detail||""].forEach(v=>rr.append(Object.assign(document.createElement("div"),{textContent:v})));body.append(rr)});card.append(head,body);return card}
function startChecks(){let root=$("#cves");root.classList.remove("empty");root.replaceChildren();let top=document.createElement("div");top.className="cve-top";top.innerHTML=`<b>${cves.length} CVEs queued</b><span id="progress" class="muted">0 / ${cves.length} checked</span><div id="countRow" class="count-row"></div>`;root.append(top);let list=document.createElement("div");list.className="cves";cves.forEach(c=>list.append(cveCard({cve:c,status:"Pending",summary:"Waiting to check vendor endpoint...",records:[]})));root.append(list);checkResults=[];countBadges()}
async function checkOne(cve,distro,version){let res=await fetch("/api/check-cve",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({cve,distro,version})});let body=await res.json();if(!res.ok)throw new Error(body.error||"Lookup failed");return body.result}
function populateVersions(){let sel=$("#versionSelect");sel.replaceChildren();(versions[$("#distroSelect").value]||[]).forEach(v=>{let o=document.createElement("option");o.value=v;o.textContent=v;sel.append(o)})}
$("#uploadForm").addEventListener("submit",async e=>{e.preventDefault();let file=$("#fileInput").files[0];if(!file){msg($("#parseMessage"),"Choose a file first.",true);return}$("#parseBtn").disabled=true;msg($("#parseMessage"),"Parsing...");let fd=new FormData();fd.append("scan_file",file);try{let res=await fetch("/api/parse",{method:"POST",body:fd});let body=await res.json();if(!res.ok)throw new Error(body.error||"Parse failed");parsed=body;cves=[];checkResults=[];renderMetrics(body.summary);serviceChart(body.summary.service_counts);$("#jsonOut").textContent=JSON.stringify(body,null,2);$("#downloadBtn").disabled=false;$("#extractBtn").disabled=false;$("#checkBtn").disabled=true;$("#distroSelect").disabled=true;$("#versionSelect").disabled=true;msg($("#parseMessage"),`Parsed ${file.name}`);msg($("#cveMessage"),"Ready to extract CVEs.");renderHosts();activate("hostsPanel")}catch(err){msg($("#parseMessage"),err.message,true)}finally{$("#parseBtn").disabled=false}});
$("#extractBtn").addEventListener("click",async()=>{if(!parsed)return;$("#extractBtn").disabled=true;msg($("#cveMessage"),"Extracting CVEs...");try{let res=await fetch("/api/extract-cves",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({scan_data:parsed})});let body=await res.json();if(!res.ok)throw new Error(body.error||"Extraction failed");cves=body.cves||[]}catch{cves=extractLocal(parsed)}finally{$("#extractBtn").disabled=false;$("#distroSelect").disabled=!cves.length;$("#versionSelect").disabled=!cves.length;$("#checkBtn").disabled=!cves.length;msg($("#cveMessage"),cves.length?`${cves.length} CVEs extracted.`:"No CVEs found.",!cves.length);renderCveExtracted();activate("cvesPanel")}});
$("#checkBtn").addEventListener("click",async()=>{if(!cves.length)return;let distro=$("#distroSelect").value,version=$("#versionSelect").value;$("#checkBtn").disabled=true;startChecks();activate("cvesPanel");msg($("#cveMessage"),`Checking ${cves.length} CVEs individually...`);let done=0;for(let c of cves){document.getElementById(cveId(c))?.replaceWith(cveCard({cve:c,status:"Checking",summary:"Requesting vendor API...",records:[]}));try{let r=await checkOne(c,distro,version);checkResults.push(r);document.getElementById(cveId(c))?.replaceWith(cveCard(r))}catch(err){let r={cve:c,status:"Lookup failed",classification:"Lookup failed",summary:err.message,records:[]};checkResults.push(r);document.getElementById(cveId(c))?.replaceWith(cveCard(r))}done++;$("#progress").textContent=`${done} / ${cves.length} checked`;countBadges()}msg($("#cveMessage"),`Complete: ${done} CVEs checked.`);$("#checkBtn").disabled=false});
$("#fileInput").addEventListener("change",()=>{let f=$("#fileInput").files[0];$("#fileName").textContent=f?`${f.name} (${fmt(f.size)} bytes)`:"XML, TXT, NMAP, JSON, logs, or raw text."});
$("#dropZone").addEventListener("dragover",e=>{e.preventDefault();$("#dropZone").classList.add("drag")});$("#dropZone").addEventListener("dragleave",()=>$("#dropZone").classList.remove("drag"));$("#dropZone").addEventListener("drop",e=>{e.preventDefault();$("#dropZone").classList.remove("drag");if(e.dataTransfer.files.length){$("#fileInput").files=e.dataTransfer.files;$("#fileInput").dispatchEvent(new Event("change"))}});
$("#filterInput").addEventListener("input",renderHosts);$$(".tab").forEach(b=>b.addEventListener("click",()=>activate(b.dataset.tab)));$("#downloadBtn").addEventListener("click",()=>{if(!parsed)return;let blob=new Blob([JSON.stringify(parsed,null,2)],{type:"application/json"}),url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download="scanlens-output.json";a.click();URL.revokeObjectURL(url)});
$("#themeBtn").addEventListener("click",()=>{let html=document.documentElement,next=html.dataset.theme==="dark"?"light":"dark";html.dataset.theme=next;localStorage.setItem("theme",next);$("#themeBtn").textContent=next==="dark"?"Dark":"Light"});let saved=localStorage.getItem("theme")||"light";document.documentElement.dataset.theme=saved;$("#themeBtn").textContent=saved==="dark"?"Dark":"Light";populateVersions();$("#distroSelect").addEventListener("change",()=>{populateVersions();if(cves.length)renderCveExtracted()});renderMetrics();
</script>
</body>
</html>"""


class AppHandler(BaseHTTPRequestHandler):
    server_version = "ScanLens/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        LOG.info("client=%s %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        LOG.debug("GET path=%s", path)
        if path in {"/", "/index.html"}:
            self.send_bytes(HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/health":
            self.send_json({"ok": True, "app": APP_NAME})
            return
        self.send_json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        LOG.debug("POST path=%s content_length=%s", path, self.headers.get("Content-Length", "0"))
        if path == "/api/parse":
            self.handle_parse()
        elif path == "/api/extract-cves":
            self.handle_extract()
        elif path == "/api/check-cve":
            self.handle_check_cve()
        elif path == "/api/check-cves":
            self.handle_check_cves()
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

    def handle_parse(self) -> None:
        started = time.perf_counter()
        try:
            filename, payload = parse_multipart_file(self.headers.get("Content-Type", ""), self.read_body())
            text = payload.decode("utf-8-sig", errors="replace")
            data = convert_content(text, filename)
            LOG.info("parse ok file=%s type=%s hosts=%s runs=%s cves=%s elapsed_ms=%.1f", filename, data["summary"]["input_type"], data["summary"]["host_count"], data["summary"]["run_count"], data["summary"]["cve_count"], elapsed_ms(started))
            self.send_json(data)
        except Exception as exc:
            LOG.exception("parse failed elapsed_ms=%.1f", elapsed_ms(started))
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

    def send_json(self, data: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def send_bytes(self, payload: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
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
