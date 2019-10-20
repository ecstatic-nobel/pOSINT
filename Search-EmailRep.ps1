<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from EmailRep.io using PowerShell.

    .EXAMPLE
    Search-EmailRep -Query bill@microsoft.com -ApiKey APIKEY | Format-List

    email      : bill@microsoft.com
    reputation : high
    suspicious : False
    references : 79
    details    : @{blacklisted=False; malicious_activity=False; malicious_activity_recent=False; credentials_leaked=True; credentials_leaked_recent=False; data_breach=True; first_seen=07/01/2008; last_seen=05/24/2019; domain_exists=True; 
                 domain_reputation=high; new_domain=False; days_since_domain_creation=10362; suspicious_tld=False; spam=False; free_provider=False; disposable=False; deliverable=True; accept_all=True; valid_mx=True; spoofable=False; spf_strict=True; 
                 dmarc_enforced=True; profiles=System.Object[]}
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-EmailRep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $UserAgent = "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.15063; en-US) PowerShell/6.0.0"
        $Uri = "https://emailrep.io/$Query".ToLower()
        $Body = "@{Key='$ApiKey'}"
        $ExtraRequestParams = "-Body $Body"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}
