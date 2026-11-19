# 📘 SPL Cheat Sheet for SOC Analysts

The 20% of Splunk commands you'll use for 80% of investigations.

## 🧱 The anatomy of a good search

```spl
index=<where> sourcetype=<what> <filters>     ← 1. narrow the data FIRST (fast)
| eval / rex / where                          ← 2. shape & filter fields
| stats ... BY ...                            ← 3. summarize
| sort / table                                ← 4. present
```

> ⚡ **Golden rule:** filter as early as possible. `index=sysmon EventCode=1 Image="*\\powershell.exe"` is much faster than searching everything and filtering later with `| where`.

## 🔧 Commands you'll use daily

| Command | What it does | Example |
|---|---|---|
| `stats` | Count / aggregate | `\| stats count BY src_ip` |
| `table` | Choose columns | `\| table _time host user CommandLine` |
| `where` | Filter on calculated values | `\| where count > 10` |
| `eval` | Create / transform fields | `\| eval is_admin=if(match(user,"adm"),1,0)` |
| `rex` | Extract with regex | `\| rex field=_raw "user=(?<user>\\S+)"` |
| `dedup` | Remove duplicates | `\| dedup host user` |
| `timechart` | Trend over time | `\| timechart span=1h count BY EventCode` |
| `transaction` | Group related events | `\| transaction user maxspan=10m` |
| `lookup` | Enrich with a CSV | `\| lookup threat_intel.csv ip AS src_ip` |
| `iplocation` | Geo-locate IPs | `\| iplocation src_ip` |
| `rare` | Least common values (find outliers!) | `\| rare limit=10 process_name` |

## 🪟 Windows Event IDs every analyst should know

| Event ID | Meaning | Why you care |
|---|---|---|
| **4624** | Successful logon | Who logged in, from where, and how (Logon Type) |
| **4625** | Failed logon | Brute force / password spraying |
| **4672** | Special privileges assigned | Admin-level logon |
| **4688** | Process created | Command-line auditing (if enabled) |
| **4720** | User account created | Backdoor accounts |
| **4732** | Added to local group | Privilege escalation |
| **1102** | Security log cleared | Anti-forensics 🚨 |
| **7045** | New service installed | Persistence / lateral movement (PsExec) |

## 🔭 Sysmon Event IDs

| EID | Event | Classic use |
|---|---|---|
| 1 | Process create | Command lines, parent/child chains |
| 3 | Network connection | Beaconing, C2 |
| 10 | Process access | LSASS credential dumping |
| 11 | File create | Dropped payloads |
| 13 | Registry value set | Run-key persistence |
| 22 | DNS query | Suspicious domains |

## 🎯 Logon Types (EventCode 4624/4625)

`2` Interactive (keyboard) · `3` Network (SMB) · `4` Batch · `5` Service · `7` Unlock · `10` RemoteInteractive (**RDP**) · `11` Cached credentials

## 🧠 Investigation pivots

~~~spl
``` Everything a host did around the time of an alert ```
index=* host="WIN-LAB-01" earliest=-15m@m latest=+15m@m
| table _time sourcetype EventCode Image CommandLine DestinationIp

``` Where else has this hash been seen? ```
index=sysmon Hashes="*<SHA256>*" | stats count BY host User Image

``` Rare parent -> child process pairs (hunting) ```
index=sysmon EventCode=1 | rare limit=20 ParentImage Image
~~~

---
⬅️ Back to the [detection library](README.md)
