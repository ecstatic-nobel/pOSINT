# [pOSINT™]  
##### Request Open-Source Intelligence using PowerShell.  

### Usage  
Import the module:  
```powershell
Import-Module pOSINT.psm1
```

View module details:  
```powershell
Get-Module pOSINT
```

Review module help page:  
```powershell
Get-Help Request-OSINT
```

Module Help Page:  

    NAME  
        Request-Osint  
        
    SYNOPSIS
        Request Open-Source Intelligence using PowerShell.  
        
        
    SYNTAX  
        Request-Osint -Crtsh [-Wildcard] -QueryString <String> [<CommonParameters>]  
        
        Request-Osint -Cymon -QueryString <String> -CyQueryType <Object> [<CommonParameters>]  
        
        Request-Osint -GreyNoise [-QueryString <String>] -GnQueryType <Object> [<CommonParameters>]  
        
        Request-Osint -PhishingKitTracker [<CommonParameters>]  
        
        Request-Osint -Threatcrowd -QueryString <String> -TcQueryType <Object> [<CommonParameters>]  
        
        Request-Osint -Urlhaus -QueryString <String> -UhQueryType <Object> [<CommonParameters>]  
        
        Request-Osint -Urlscan -QueryString <String> [<CommonParameters>]  
        
        
    DESCRIPTION  
        Request Open-Source Intelligence using PowerShell. The response is a  
        PowerShell object which can be formatted in many different ways.  
        

    RELATED LINKS  
        https://github.com/ecstatic-nobel/pOSINT/  

    REMARKS  
        To see the examples, type: "get-help Request-Osint -examples".  
        For more information, type: "get-help Request-Osint -detailed".  
        For technical information, type: "get-help Request-Osint -full".  
        For online help, type: "get-help Request-Osint -online"  

Show Cmd-let examples:  
```powershell
Get-Help Request-OSINT -Examples
```

EXAMPLE:  
```powershell
Request-Osint -GreyNoise -QueryString adb_worm -GnQueryType tag | Select-Object -ExpandProperty records
```
![pOSINT](https://raw.githubusercontent.com/ecstatic-nobel/pOSINT/master/static/assets/pOSINT.gif)  

Remove the module:  
```powershell
Remove-Module pOSINT
```

### Coming Soon  
- Alienvault  
- Censys  
- Hybrid-Analysis  
- Malshare  
- PulseDive  