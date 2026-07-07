#!/usr/bin/env python3
"""Upload Trivy and Semgrep results to Faraday workspace."""

import json, sys, os, requests, hashlib
from datetime import datetime

FARADAY_URL  = os.environ.get("FARADAY_URL", "http://faraday:5985")
FARADAY_USER = os.environ.get("FARADAY_USER", "faraday")
FARADAY_PASS = os.environ.get("FARADAY_PASS", "Faraday2024")
WORKSPACE    = os.environ.get("FARADAY_WORKSPACE", "devsecops")


def login():
    r = requests.post(f"{FARADAY_URL}/_api/login",
                      json={"email": FARADAY_USER, "password": FARADAY_PASS})
    r.raise_for_status()
    d = r.json()
    return r.cookies, d["response"]["csrf_token"]


def target_to_ip(target):
    """Convert arbitrary target string to a deterministic fake IP."""
    h = int(hashlib.md5(target.encode()).hexdigest()[:8], 16)
    return f"10.{(h>>16)&255}.{(h>>8)&255}.{h&255}"


def bulk_create(cookies, csrf, tool_name, hosts_payload):
    if not hosts_payload:
        print(f"[{tool_name}] No findings.")
        return
    total = 0
    for host in hosts_payload:
        payload = {
            "command": {
                "tool": tool_name,
                "command": f"{tool_name} scan",
                "duration": 1,
                "start_date": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            "hosts": [host]
        }
        r = requests.post(
            f"{FARADAY_URL}/_api/v3/ws/{WORKSPACE}/bulk_create",
            json=payload, cookies=cookies,
            headers={"X-CSRF-Token": csrf, "Content-Type": "application/json"}
        )
        r.raise_for_status()
        total += len(host["vulnerabilities"])
    print(f"[{tool_name}] Uploaded {total} vulns across {len(hosts_payload)} hosts")


def parse_trivy(path):
    sev_map = {"critical":"critical","high":"high","medium":"medium","low":"low"}
    hosts = {}
    with open(path) as f:
        data = json.load(f)
    for result in data.get("Results", []):
        target = result.get("Target", "unknown")
        ip = target_to_ip(target)
        for v in result.get("Vulnerabilities") or []:
            hosts.setdefault(ip, {"ip": ip, "description": target, "vulnerabilities": []})
            hosts[ip]["vulnerabilities"].append({
                "name": f"{v.get('VulnerabilityID', 'unknown')} [{target}]",
                "desc": f"{v.get('Title','')}\n{v.get('Description','')}",
                "severity": sev_map.get(v.get("Severity","").lower(), "info"),
                "type": "Vulnerability",
                "resolution": f"Fixed in: {v.get('FixedVersion','N/A')}",
                "refs": [{"name": r, "type": "other"} for r in v.get("References",[])[:3]],
            })
    return list(hosts.values())


def parse_semgrep(path):
    sev_map = {"error":"high","warning":"medium","info":"low"}
    hosts = {}
    with open(path) as f:
        data = json.load(f)
    for r in data.get("results", []):
        extra = r.get("extra", {})
        fpath  = r.get("path", "unknown")
        ip = target_to_ip(fpath)
        hosts.setdefault(ip, {"ip": ip, "description": fpath, "vulnerabilities": []})
        hosts[ip]["vulnerabilities"].append({
            "name": r.get("check_id", "semgrep-finding"),
            "desc": extra.get("message", ""),
            "severity": sev_map.get(extra.get("severity","").lower(), "info"),
            "type": "Vulnerability",
            "resolution": extra.get("metadata",{}).get("fix","See semgrep rule."),
        })
    return list(hosts.values())


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: upload_to_faraday.py <trivy.json> <semgrep.json>")
        sys.exit(1)

    cookies, csrf = login()
    print("Logged in to Faraday.")

    trivy_hosts = parse_trivy(sys.argv[1])
    total_trivy = sum(len(h["vulnerabilities"]) for h in trivy_hosts)
    print(f"Trivy: {total_trivy} vulns across {len(trivy_hosts)} hosts")
    bulk_create(cookies, csrf, "Trivy", trivy_hosts)

    cookies, csrf = login()
    semgrep_hosts = parse_semgrep(sys.argv[2])
    total_semgrep = sum(len(h["vulnerabilities"]) for h in semgrep_hosts)
    print(f"Semgrep: {total_semgrep} vulns across {len(semgrep_hosts)} hosts")
    bulk_create(cookies, csrf, "Semgrep", semgrep_hosts)

    print(f"Total uploaded: {total_trivy + total_semgrep} findings → workspace '{WORKSPACE}'")
