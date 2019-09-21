<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from Censys using PowerShell.

    .EXAMPLE
    Search-Censys -Uid <UID> -Secret <SECRET> -Endpoint search -Index certificates -Query pandorasong.com | Format-List

    status   : ok
    results  : {@{parsed.fingerprint_sha256=ff081d0526721b9217295e809e30fcea66e31f2ab0e0fc6699af222a24f5f6cc; parsed.issuer_dn=C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA 
               Domain Validation Secure Server CA; parsed.subject_dn=OU=Domain Control Validated, OU=PositiveSSL, CN=pandorasong.com}, 
               @{parsed.fingerprint_sha256=216fda88168f10f19d5b217d5d718b90c950176224d24a97fcb2eea71a153f39; parsed.issuer_dn=C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO RSA 
               Domain Validation Secure Server CA; parsed.subject_dn=OU=Domain Control Validated, OU=PositiveSSL, CN=pandorasong.com}}
    metadata : @{count=2; query=pandorasong.com; backend_time=824; page=1; pages=1}


    ######################################################################
    Available options not found in 'Get-Help Search-Censys' SYNTAX section
    ######################################################################

    Endpoint: search
    Index   : [ipv4,websites,certificates]
    Query   : <STRING>

    Endpoint: view
    Index   : [ipv4,websites,certificates]
    Id      : <STRING>

    ENDPOINT: account

    ######################################################################
    Available options not found in 'Get-Help Search-Censys' SYNTAX section
    ######################################################################
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-Censys {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Uid,
        [Parameter(Mandatory=$true)]
        [string]$Secret,

        [Parameter(Mandatory=$true)]
        [ValidateSet('search','view','account')]
        [string]$Endpoint,

        [Parameter(Mandatory=$false)]
        [ValidateSet('ipv4', 'websites', 'certificates')]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-Censys -Examples' to see available options.
            #
            if ($Endpoint -in @('search', 'view')) {$True}
        })]
        [string]$Index,
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-Censys -Examples' to see available options.
            #
            if ($Endpoint -eq 'search') {$True}
        })]
        [string]$Query,
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-Censys -Examples' to see available options.
            #
            if ($Endpoint -eq 'view') {$True}
        })]
        [string]$Id,

        [Parameter(Mandatory=$false)]
        [int]$Page = 1
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $BaseUri = "https://censys.io/api/v1/$Endpoint"
        $Credentials = "${Uid}:${Secret}"
        $Base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($Credentials))
        $Headers = "@{Authorization = 'Basic $Base64'}"
        $Uri = $BaseUri
        $ExtraRequestParams = "-Headers $Headers"

        if ($Endpoint -in @('search', 'view')) {
            $Uri = "$BaseUri/$Index"

            if ($Id) {
                $Uri = "$BaseUri/$Index/$Id"
            } else {
                $Body = [PSCustomObject]@{
                    query = $Query
                    page = $Page
                }
                #$Body = "@{query='$Query', page = '$Page'}"
                $Method = 'POST'
            }
        }

        if ($Body) {
            $b = (ConvertTo-Json $Body)
            $ExtraRequestParams = "-Body '$b' -Headers $Headers"
        }
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose 'Complete'}
}
