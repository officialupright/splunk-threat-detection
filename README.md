<h1 align="center">🔎 Splunk Threat Detection Playbook</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Splunk-SPL-000000?style=for-the-badge&logo=splunk&logoColor=white" />
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK-C8102E?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Data-Windows%20Security%20%2B%20Sysmon-0078D6?style=for-the-badge&logo=windows&logoColor=white" />
</p>

<p align="center"><b>Copy-paste-ready SPL detections for real attacker behavior, each one explained in plain English,<br/>with the triage questions to ask and how to cut false positives.</b></p>

---

## 🤔 Who is this for?

- **New SOC analysts** who want to understand *why* a detection works, not just paste it
- **Students** preparing for Splunk Core / SOC analyst interviews
- **Blue teamers** looking for a clean starting point to tune for their own environment

Every detection in this repo follows the same structure:

> **What it catches → Why attackers do it → The SPL → How to read the results → How to tune it**

---

## 🎯 Detection Library

| # | Detection | Data source | MITRE ATT&CK | File |
|---|---|---|---|---|
| 1 | Brute force → successful login | Windows Security 4625 / 4624 | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | [`brute-force-then-success.spl`](detections/brute-force-then-success.spl) |
| 2 | Encoded PowerShell execution | Sysmon EID 1 | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) · [T1027](https://attack.mitre.org/techniques/T1027/) | [`encoded-powershell.spl`](detections/encoded-powershell.spl) |
| 3 | Office app spawning a shell (malicious macro) | Sysmon EID 1 | [T1566.001](https://attack.mitre.org/techniques/T1566/001/) · [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | [`office-spawning-shell.spl`](detections/office-spawning-shell.spl) |
| 4 | User added to local Administrators | Windows Security 4732 | [T1098](https://attack.mitre.org/techniques/T1098/) · [T1136.001](https://attack.mitre.org/techniques/T1136/001/) | [`new-local-admin.spl`](detections/new-local-admin.spl) |

📘 New to SPL? Start with the **[SPL Cheat Sheet for SOC Analysts](spl-cheatsheet.md)**.

---

## 🔬 Deep Dive: Brute Force That *Succeeded*

Failed logins on their own are noise; every SOC sees thousands per day. The interesting question is: **did any source that failed many times eventually get in?**

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) Logon_Type IN (3, 10)
| eval outcome=if(EventCode=4624, "success", "failure")
| stats count(eval(outcome="failure")) AS failures
        count(eval(outcome="success")) AS successes
        values(TargetUserName)        AS accounts
        min(_time) AS first_seen max(_time) AS last_seen
        BY IpAddress
| where failures >= 10 AND successes >= 1
| convert ctime(first_seen) ctime(last_seen)
| sort - failures
```

**How to read it:** each row is a source IP that failed at least 10 times and then logged in successfully. Logon Type 3 = network (SMB, etc.), 10 = RDP.

**Triage questions**
1. Is the source IP internal or external? External + RDP success = escalate immediately.
2. Was it one account (password guessing) or many accounts (password spraying)?
3. What did the account do *after* the successful login? Pivot to process creation on that host.

**Tuning:** exclude known vulnerability scanners and service accounts with expired passwords (a common source of benign failures).

---

## 🧱 Field Names & Data Sources

These searches assume:
- Windows Security logs in `index=wineventlog` (via the Splunk Add-on for Microsoft Windows)
- Sysmon logs in `index=sysmon` with the Splunk Add-on for Sysmon

Field names differ slightly between add-ons and XML vs. classic rendering (e.g. `TargetUserName` vs `user`, `IpAddress` vs `src_ip`). **Run `| fieldsummary` on your data first** and adjust.

---

## 🧪 How I Test These

1. Generate the behavior in a lab (see my **[SOC Home Lab](https://github.com/officialupright/soc-home-lab)**, which uses Atomic Red Team).
2. Confirm the raw event exists: `index=sysmon EventCode=1 | head 10`
3. Run the detection and check it returns the test activity, and **only** that.
4. Run it across 7 days of normal data to measure the false-positive rate before turning it into an alert.

---

## 🤝 Contributing

Have a detection idea or a tuning tip? Open an issue or PR. Detection engineering gets better when analysts share what works.

<p align="center">Built by <a href="https://github.com/officialupright">Ifeanyi Solomon Uneze</a> · SOC Analyst · <a href="https://www.linkedin.com/in/ifeanyi-solomon-uneze-6536b8450/">LinkedIn</a><br/>⭐ Star the repo if it helped you write a better search!</p>
