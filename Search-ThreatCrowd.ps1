<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from ThreatCrowd using PowerShell.

    .EXAMPLE
    Search-ThreatCrowd -Endpoint ip -Query 188.40.75.132 | Format-List

    response_code : 1
    resolutions   : {@{last_resolved=2015-02-17; domain=tvgate.rocks}, @{last_resolved=2015-02-17; domain=nice-mobiles.com}, @{last_resolved=2015-02-17; domain=nauss-lab.com}, @{last_resolved=2015-02-17; 
                    domain=iwork-sys.com}...}
    hashes        : {003f0ed24b5f70ddc7c6e80f9c4dac73, 027fc90c13f6d87e1f68d25b0d0ec4a7, 088420b7e56c73d3d495230d42e0cb95, 1e52a293838464e4cd6c1c6d94a55793...}
    references    : {}
    votes         : -1
    permalink     : https://www.threatcrowd.org/ip.php?ip=188.40.75.132
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-ThreatCrowd {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("email", "domain", "ip", "resource")]
        [string]$Endpoint,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $Endpoint = "$Endpoint".ToLower()
        $BaseUri = "https://www.threatcrowd.org/searchApi/v2/$Endpoint"

        if ($Endpoint -eq "resource") {
            $BaseUri = "https://www.threatcrowd.org/searchApi/v2/file"
        }

        $Uri = "$BaseUri/report/`?$Endpoint=$Query"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}
