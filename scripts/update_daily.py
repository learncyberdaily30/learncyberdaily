#!/usr/bin/env python3
"""Fetch daily cybersecurity data and write data/daily.json.

Sources (both free, no API key needed):
  - CISA Known Exploited Vulnerabilities (KEV) catalog
  - NIST NVD API 2.0 (recent CRITICAL CVEs)

If a source fails, the previous values for that section are kept so the
site never goes blank.
"""
import datetime as dt
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "daily.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = {"User-Agent": "learncyberdaily-bot/1.0 (+https://github.com/learncyberdaily30/learncyberdaily)"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

TIPS = [
    "Turn on multi-factor authentication everywhere. A stolen password alone should never be enough.",
    "Use a password manager and give every account a unique, long passphrase.",
    "Patch quickly: most breaches exploit vulnerabilities that already have fixes.",
    "Hover over links before clicking. Phishing relies on looking legitimate.",
    "Back up important data using the 3-2-1 rule: 3 copies, 2 media types, 1 offsite.",
    "Check logs, not just alerts. Context turns a noisy alert into an investigation.",
    "In Wireshark, start with display filters like ip.addr == x.x.x.x to cut the noise.",
    "Least privilege: give users and services only the access they need.",
    "Never test systems you don't own or have written permission to test.",
    "Verify AI answers against official docs. LLMs can sound confident and still be wrong.",
    "Learn the MITRE ATT&CK matrix. It is the common language of blue and red teams.",
    "Triage by impact: what asset, what data, what blast radius?",
    "DNS logs often reveal malware beaconing long before an antivirus does.",
    "Disable unused services and ports. Every open door is attack surface.",
    "Treat unexpected urgency in an email or call as a red flag for social engineering.",
    "Hash a file (SHA-256) before and after transfer to confirm integrity.",
    "Segment your network so one compromised device can't reach everything.",
    "Read the CVSS vector, not just the score. It explains how an attack works.",
    "Keep an asset inventory. You can't protect what you don't know you have.",
    "Document every incident step. Good notes make post-incident reviews valuable.",
    "Use HTTPS everywhere and check certificate warnings instead of clicking through.",
    "Rotate and revoke leaked secrets immediately; deleting the commit isn't enough.",
    "Practice in safe labs: TryHackMe, Hack The Box, or your own VMs.",
    "Email headers (SPF, DKIM, DMARC) help you spot spoofed senders.",
    "Learn Linux command line basics. Most security tooling lives there.",
    "Threat intel is only useful if it is acted on: block, detect, or hunt.",
    "Encrypt laptops and phones so a lost device is not a data breach.",
    "Review third-party app permissions regularly and remove what you don't use.",
    "Know your baseline. Anomaly detection starts with knowing what normal looks like.",
    "Stay curious and learn a little every day. Consistency beats cramming.",
]


def get_json(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def clip(text, n=230):
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def fetch_kev(limit=6):
    data = get_json(KEV_URL)
    vulns = [v for v in data.get("vulnerabilities", []) if CVE_RE.match(v.get("cveID", ""))]
    vulns.sort(key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)
    out = []
    for v in vulns[:limit]:
        out.append({
            "cve": v["cveID"],
            "vendor": clip(v.get("vendorProject"), 60),
            "product": clip(v.get("product"), 60),
            "name": clip(v.get("vulnerabilityName"), 120),
            "added": v.get("dateAdded", ""),
            "due": v.get("dueDate", ""),
            "ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "summary": clip(v.get("shortDescription")),
        })
    return out


def fetch_nvd(limit=5, days=7):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0, tzinfo=None)
    start = now - dt.timedelta(days=days)
    params = {
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": "50",
    }
    data = get_json(NVD_URL + "?" + urllib.parse.urlencode(params))
    items = []
    for entry in data.get("vulnerabilities", []):
        c = entry.get("cve", {})
        cid = c.get("id", "")
        if not CVE_RE.match(cid):
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score = None
        for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            m = c.get("metrics", {}).get(key)
            if m:
                score = m[0].get("cvssData", {}).get("baseScore")
                break
        items.append({
            "cve": cid,
            "published": c.get("published", "")[:10],
            "score": score,
            "summary": clip(desc),
        })
    items.sort(key=lambda i: (i["score"] or 0, i["published"]), reverse=True)
    return items[:limit]


def main():
    prev = {}
    if OUT.exists():
        try:
            prev = json.loads(OUT.read_text(encoding="utf-8"))
        except Exception:
            prev = {}

    today = dt.datetime.now(dt.timezone.utc).date()
    result = {
        "updated": today.isoformat(),
        "tip": TIPS[today.timetuple().tm_yday % len(TIPS)],
        "kev": prev.get("kev", []),
        "critical_cves": prev.get("critical_cves", []),
        "sources": {
            "kev": "CISA Known Exploited Vulnerabilities Catalog",
            "nvd": "NIST National Vulnerability Database",
        },
    }

    failures = 0
    for key, fn in (("kev", fetch_kev), ("critical_cves", fetch_nvd)):
        try:
            fresh = fn()
            if fresh:
                result[key] = fresh
            else:
                print(f"[warn] {key}: empty result, keeping previous data", file=sys.stderr)
        except Exception as exc:  # network errors, rate limits, schema changes
            failures += 1
            print(f"[warn] {key}: {exc!r}, keeping previous data", file=sys.stderr)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUT} (kev={len(result['kev'])}, cves={len(result['critical_cves'])})")
    # Only fail the workflow if BOTH sources failed.
    return 1 if failures == 2 else 0


if __name__ == "__main__":
    sys.exit(main())
