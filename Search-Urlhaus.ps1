<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from URLhaus using PowerShell.

    .EXAMPLE
    Search-Urlhaus -Endpoint payload -Query 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11 | Format-List

    query_status     : ok
    md5_hash         : fbd9ea8ffe773b85a603665c44a86502
    sha256_hash      : 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11
    content_type     : exe
    file_size        : 339968
    signature        : TrickBot
    firstseen        : 2019-03-01 16:50:06
    lastseen         : 2019-03-01 20:40:07
    url_count        : 1
    urlhaus_download : https://api.urlhaus.abuse.ch/v1/download/4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11/
    virustotal       : 
    urls             : {@{url_id=149696; url=http://195.123.237.120/tin.png; url_status=offline; urlhaus_reference=https://urlhaus.abuse.ch/url/149696/; filename=; firstseen=2019-03-01; lastseen=2019-03-01}}
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-Urlhaus {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("url", "host", "payload")]
        [string]$Endpoint,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $Body = "@{$Endpoint='$Query'}"
        $Method = "POST"

        if ($Endpoint -eq "payload") {
            if ($Query.Length -eq 32) {
                $Body = "@{md5_hash='$Query'}"
            } elseif ($Query.Length -eq 64) {
                $Body = "@{sha256_hash='$Query'}"
            }
        }

        $Uri = "https://urlhaus-api.abuse.ch/v1/$Endpoint/".ToLower()
        $ExtraRequestParams = "-Body $Body"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

