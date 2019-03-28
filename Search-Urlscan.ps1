<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from urlscan.io using PowerShell.

    .EXAMPLE
    Search-Urlscan -Query 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11 | Format-List

    task           : @{visibility=public; method=automatic; time=3/1/19 5:03:35 PM; source=urlhaus; url=http://195.123.237.120/tin.png}
    stats          : @{uniqIPs=1; consoleMsgs=0; dataLength=339968; encodedDataLength=340210; requests=1}
    page           : @{country=UA; server=nginx/1.6.2; city=; domain=195.123.237.120; ip=195.123.237.120; asnname=LAYER6, UA; asn=AS204957; url=http://195.123.237.120/tin.png; ptr=sweetdrem.biz}
    uniq_countries : 1
    _id            : 5524d559-9d34-4147-8c05-e434756d6a41
    result         : https://urlscan.io/api/v1/result/5524d559-9d34-4147-8c05-e434756d6a41
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-Urlscan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $ReponseType = "OBJ"
        $Uri = "https://urlscan.io/api/v1/search/`?q=$Query&size=10000"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

