# [pOSINT™]  
##### Gather Open-Source Intelligence using PowerShell.  

### Usage  
Save the parent project directory, `pOSINT`, to `C:\Users\$env:username\Documents\WindowsPowerShell\Modules\`.  

List available modules:  
```powershell
Get-Module -ListAvailable
```

Import the module:  
```powershell
Import-Module pOSINT
```

Or, just import the manifest file manually:  
```powershell
Import-Module pOSINT.psd1
```

View module details:  
```powershell
Get-Module pOSINT
```

Review module help page:  
```powershell
Get-Help Search-<OSINT_SOURCE>
```

Show Cmdlet examples:  
```powershell
Get-Help Search-<OSINT_SOURCE> -Examples
```

Check the following sources' help page to see special mappings:  
- AlienVault  
- Censys  
- Hybrid-Analysis  
- ThreatMiner  

Remove the module:  
```powershell
Remove-Module pOSINT
```

### Examples:    
```powershell
Search-AlienVault -Endpoint IPv4 -Section general -Query 187.233.152.78 | Format-List
Search-Censys -Uid <UID> -Secret <SECRET> -Endpoint search -Index certificates -Query pandorasong.com | Format-List
Search-Crtsh -Query jotugaedorm.com -Wildcard | Format-List
Search-Cymon -Endpoint ip -Query 195.123.237.120 | Format-List
Search-EmailRep -Query bill@microsoft.com | Format-List
Search-GreyNoise -Endpoint list | Format-List
Search-GreyNoise -Endpoint tag -Query ADB_WORM | Format-List
Search-GreyNoise -Endpoint ip -Query 123.193.145.85 | Format-List
Search-HybridAnalysis -ApiKey <APIKEY> -Secret <SECRET> -Endpoint hash -Name hash -Query 116858001ed50d8dd02b353473a139b98820dcf620c9e70e8a51c49f62cc6581 | Format-List
Search-Malshare -ApiKey <APIKEY> -Query 4cc96f0003b6c0429f29013a8d9e3e3c | Format-List
Search-PhishingKitTracker | Format-List
Search-PulseDive -Endpoint threat -Query Zeus | Format-List
Search-PulseDive -Endpoint indicator -Query pulsedive.com | Format-List
Search-PulseDive -Endpoint feed_list | Format-List
Search-PulseDive -Endpoint feed -Query "Zeus Bad Domains" -organization abuse.ch | Format-List
Search-ThreatCrowd -Endpoint ip -Query 188.40.75.132 | Format-List
Search-ThreatMiner -Endpoint host -Query 216.58.192.174 -QueryType report_tagging | Format-List
Search-Urlhaus -Endpoint payload -Query 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11 | Format-List
Search-Urlscan -Query 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11 | Format-List
Search-VirusTotal -ApiKey <APIKEY> -Endpoint ip-address -Query 99.84.254.97 | Format-List
```
![pOSINT](https://raw.githubusercontent.com/ecstatic-nobel/pOSINT/master/static/assets/pOSINT.gif)  

### Things to Know  
- Do not use Format-List when accessing properties  

Please fork, create merge requests, and help make this better.  
