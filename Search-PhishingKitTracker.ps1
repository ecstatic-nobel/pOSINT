<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from neonprimetime's PhishingKitTracker using PowerShell.

    .EXAMPLE
    Search-PhishingKitTracker | Format-List

    DateFound        : 2/26/2019
    ReferenceLink    : https://twitter.com/covertshell/status/1100574595902451712
    ThreatActorEmail : vioilla86@gmail.com
    EmailType        : gmail
    KitMailer        : auth.php
    Target           : 
    PhishingDomain   : jotugaedorm.com
    KitName          : order_pdf2019.zip
    ThreatActor      : 
    KitHash          : 04ae2a48f6d55e63d8ca9f3784d4fe8e
    KitUrl           : http://jotugaedorm.com/import/order_pdf2019.zip

    ...
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-PhishingKitTracker {
    [CmdletBinding()]
    param()
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $ReponseType = 'CSV'
        $Uri = 'https://raw.githubusercontent.com/neonprimetime/PhishingKitTracker/master/PhishingKitTracker.csv'
        $ExtraRequestParams = ''
    }
    Process {Search-Api }
    End {Reset-SslDefaults; Write-Verbose 'Complete'}
}

