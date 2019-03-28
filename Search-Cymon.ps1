<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from Cymon using PowerShell.

    .EXAMPLE
    Search-Cymon -Endpoint ip -Query 195.123.237.120 | Format-List

    total : 1
    from  : 0
    size  : 10
    hits  : {@{title=Malware email submission; link=http://www.senderbase.org/lookup/?search_string=195.123.237.120;
            reported_by=cymon; feed=senderbase.org; feed_id=AVsGXxCjVjrVcoBZyoh-; timestamp=12/10/18 6:00:02 AM; 
            tags=System.Object[]; ioc=; id=7d33126e4f3e1acb8ea770cda0452fb641617f798aa6302b025dc2d148ec84f8}}
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-Cymon {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("ip", "domain", "hostname", "md5", "sha256", "ssdeep", "term")]
        [string]$Endpoint,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $Uri = "https://api.cymon.io/v2/ioc/search/$Endpoint/$Query".ToLower()
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

