<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from Certificate Search using PowerShell.

    .EXAMPLE
    Search-Crtsh -Query jotugaedorm.com -Wildcard | Format-List

    issuer_ca_id        : 12922
    issuer_name         : C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    name_value          : cpanel.jotugaedorm.com
    min_cert_id         : 1179646010
    min_entry_timestamp : 2/6/19 9:46:22 PM
    not_before          : 2/6/19 12:00:00 AM
    not_after           : 5/7/19 11:59:59 PM

    ...
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-Crtsh {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Query,
        [Parameter(Mandatory=$false)]
        [switch]$Wildcard
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        if ($Wildcard) {
            $Query = "%25.$Query"
        }

        $Uri = "https://crt.sh/`?q=$Query&output=json"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

