<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from Malshare using PowerShell.

    .EXAMPLE
    Search-Malshare -ApiKey <APIKEY> -Query 4cc96f0003b6c0429f29013a8d9e3e3c | Format-List

    md5         : 4cc96f0003b6c0429f29013a8d9e3e3c
    sha1        : eff0fc5a16e132a5fcaceedb95609cbdecdfdd04
    sha256      : 02786fc9baf3ccdb3286dc7001997edcb010c187d8a6a7bf6ec85d48fdb80554
    type        : ASCII
    added       : 1520369674
    source      : http://94.130.104.170/Android.Spy.49_iBanking_Feb2014//Android.Spy.49_iBanking_Feb2014.pass
    yarahits    : @{yara=System.Object[]}
    parentfiles : {}
    subfiles    : {}
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-Malshare {
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
        
        $Uri = "https://malshare.com/api.php?api_key=$ApiKey&action=search&query=$Query".ToLower()
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

