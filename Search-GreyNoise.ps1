<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from GreyNoise using PowerShell.

    .EXAMPLE
    Search-GreyNoise -Endpoint list | Format-List

    status : ok
    tags   : {VNC_SCANNER_HIGH, PING_SCANNER_LOW, BINGBOT, IIS_WEBDAV_REMOTE_CODE_EXECUTION_CVE_2017_7269...}

    .EXAMPLE
    Search-GreyNoise -Endpoint tag -Query ADB_WORM | Format-List

    tag            : ADB_WORM
    status         : ok
    returned_count : 500
    records        : {@{ip=185.25.196.139; name=ADB_WORM; first_seen=3/22/19 8:55:39 PM; last_updated=3/22/19 8:55:39 PM; confidence=high; intention=malicious; category=worm; metadata=}, @{ip=188.59.135.65; 
                     name=ADB_WORM; first_seen=3/22/19 7:45:27 PM; last_updated=3/22/19 7:45:27 PM; confidence=high; intention=malicious; category=worm; metadata=}, @{ip=203.91.113.41; name=ADB_WORM; 
                     first_seen=3/22/19 11:28:16 AM; last_updated=3/22/19 8:56:34 PM; confidence=high; intention=malicious; category=worm; metadata=}, @{ip=125.59.141.46; name=ADB_WORM; first_seen=3/22/19 
                     9:02:25 AM; last_updated=3/22/19 9:02:25 AM; confidence=high; intention=malicious; category=worm; metadata=}...}

    .EXAMPLE
    Search-GreyNoise -Endpoint ip -Query 123.193.145.85 | Format-List

    ip             : 123.193.145.85
    status         : ok
    returned_count : 55
    records        : {@{name=ADB_WORM; first_seen=3/21/19 7:24:20 PM; last_updated=3/21/19 7:24:20 PM; confidence=high; intention=malicious; category=worm; metadata=}, @{name=MIRAI; first_seen=3/14/19 
                     10:52:10 AM; last_updated=3/14/19 10:52:10 AM; confidence=high; intention=malicious; category=worm; metadata=}, @{name=MIRAI; first_seen=3/11/19 1:20:56 AM; last_updated=3/11/19 1:20:56 
                     AM; confidence=high; intention=malicious; category=worm; metadata=}, @{name=MIRAI; first_seen=3/11/19 1:20:56 AM; last_updated=3/14/19 10:52:10 AM; confidence=high; intention=malicious; 
                     category=worm; metadata=}...}
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-GreyNoise {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Key,

        [Parameter(Mandatory=$true)]
        [ValidateSet("list", "ip", "tag")]
        [string]$EndPoint,
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            if ($EndPoint -ne "list") {
                $true
            } else {
                Throw "Value Mismatch Detected: list (Query not needed)."
            }
        })]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $Uri = "https://api.greynoise.io/v1/query/$EndPoint".ToLower()

        if ($EndPoint -ne "list") {
            $Query = $Query.ToUpper()
            $Body = "@{$EndPoint='$Query';key='$Key'}"
            $Method = "POST"
            $Uri = "https://api.greynoise.io/v1/query/$EndPoint".ToLower()
            $ExtraRequestParams = "-Body $Body"
        }
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

