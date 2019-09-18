<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from ThreatMiner using PowerShell.

    .EXAMPLE
    Search-ThreatMiner -Endpoint host -Query 216.58.192.174 -QueryType report_tagging | Format-List

    status_code    : 200
    status_message : Results found.
    results        : {@{filename=DarkHydrus delivers new Trojan that can use Google Drive for C2 communications.pdf; year=2019; URL=https://www.threatminer.org/report.php?q=DarkHydrus delivers new Trojan 
                     that can use Google Drive for C2 communications.pdf&y=2019}}

    ###########################################################################
    Available options not found in 'Get-Help Search-ThreatMiner' SYNTAX section
    ###########################################################################

    Endpoint : domain
    Query    : <STRING>
    QueryType: [whois,passive_dns,uris,samples,subdomains,report_tagging]
    
    Endpoint : host
    Query    : <STRING>
    QueryType: [whois,passive_dns,uris,samples,ssl_hashes,report_tagging]

    Endpoint : sample
    Query    : <STRING>
    QueryType: [metadata,http_traffic,hosts,mutants,registry_keys,av,report_tagging]

    Endpoint : imphash
    Query    : <STRING>
    QueryType: [samples,report_tagging]

    Endpoint : ssdeep
    Query    : <STRING>
    QueryType: [samples,report_tagging]

    Endpoint : ssl
    Query    : <STRING>
    QueryType: [hosts,report_tagging]

    Endpoint : email
    Query    : <STRING>
    QueryType: [domains]

    Endpoint : av
    Query    : <STRING>
    QueryType: [samples,report_tagging]

    Endpoint : reports
    Query    : <STRING>
    QueryType: [report_names,reports_by_year]

    ###########################################################################
    Available options not found in 'Get-Help Search-ThreatMiner' SYNTAX section
    ###########################################################################
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-ThreatMiner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("domain", "host", "sample", "imphash", "ssdeep", "ssl", "email", "av", "reports")]
        [string]$Endpoint,
        [Parameter(Mandatory=$true)]
        [string]$Query,
        [Parameter(Mandatory=$true)]
        [ValidateSet("av_detection", "domains", "hosts", "http_traffic", "metadata", "mutants", "passive_dns", "registry_keys", "report_names", "report_tagging", "reports_by_year", "samples", "ssl_hashes", "subdomains", "uris", "whois")]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-ThreatMiner -Examples' to see available options.
            #
            if ($Endpoint -eq "domain") {
                if ($_ -in @("whois","passive_dns","uris","samples","subdomains","report_tagging")) {$True}
            } elseif ($Endpoint -eq "host") {
                if ($_ -in @("whois","passive_dns","uris","samples","ssl_hashes","report_tagging")) {$True}
            } elseif ($Endpoint -eq "sample") {
                if ($_ -in @("metadata","http_traffic","hosts","mutants","registry_keys","av", "report_tagging")) {$True}
            } elseif ($Endpoint -eq "imphash") {
                if ($_ -in @("samples","report_tagging")) {$True}
            } elseif ($Endpoint -eq "ssdeep") {
                if ($_ -in @("samples","report_tagging")) {$True}
            } elseif ($Endpoint -eq "ssl") {
                if ($_ -in @("hosts","report_tagging")) {$True}
            } elseif ($Endpoint -eq "email") {
                if ($_ -in @("domains")) {$True}
            } elseif ($Endpoint -eq "av") {
                if ($_ -in @("samples","report_tagging")) {$True}
            } elseif ($Endpoint -eq "reports") {
                if ($_ -in @("report_names","reports_by_year")) {$True}
            }
        })]
        [string]$QueryType
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        Switch ($Endpoint) {
            "domain"   {
                Switch ($QueryType) {
                    "whois"          {$Flag = 1;Break}
                    "passive_dns"    {$Flag = 2;Break}
                    "uris"           {$Flag = 3;Break}
                    "samples"        {$Flag = 4;Break}
                    "subdomains"     {$Flag = 5;Break}
                    "report_tagging" {$Flag = 6;Break}
                }
                Break
            }
            "host"     {
                Switch ($QueryType) {
                    "whois"          {$Flag = 1;Break}
                    "passive_dns"    {$Flag = 2;Break}
                    "uris"           {$Flag = 3;Break}
                    "samples"        {$Flag = 4;Break}
                    "ssl_hashes"     {$Flag = 5;Break}
                    "report_tagging" {$Flag = 6;Break}
                }
                Break
            }
            "sample"   {
                Switch ($QueryType) {
                    "metadata"       {$Flag = 1;Break}
                    "http_traffic"   {$Flag = 2;Break}
                    "hosts"          {$Flag = 3;Break}
                    "mutants"        {$Flag = 4;Break}
                    "registry_keys"  {$Flag = 5;Break}
                    "av_detection"   {$Flag = 6;Break}
                    "report_tagging" {$Flag = 7;Break}
                }
                Break
            }
            "imphash"  {
                Switch ($QueryType) {
                    "samples"        {$Flag = 1;Break}
                    "report_tagging" {$Flag = 2;Break}
                }
            }
            "ssdeep"   {
                Switch ($QueryType) {
                    "samples"        {$Flag = 1;Break}
                    "report_tagging" {$Flag = 2;Break}
                }
                Break
            }
            "ssl"      {
                Switch ($QueryType) {
                    "hosts"          {$Flag = 1;Break}
                    "report_tagging" {$Flag = 2;Break}
                }
                Break
            }
            "email"    {
                Switch ($QueryType) {
                    "domains" {$Flag = 1;Break}
                }
                Break
            }
            "av"       {
                Switch ($QueryType) {
                    "samples"        {$Flag = 1;Break}
                    "report_tagging" {$Flag = 2;Break}
                }
                Break
            }
            "aptnotes" {
                Switch ($QueryType) {
                    "report_names"    {$Flag = 1;Break}
                    "reports_by_year" {$Flag = 2;Break}
                }
                Break
            }
        }

        $BaseUri = "https://api.threatminer.org/v2/$Endpoint.php".ToLower()
        $Uri = "$BaseUri`?q=$Query&rt=$Flag"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}
