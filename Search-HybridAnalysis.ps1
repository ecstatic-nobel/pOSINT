<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from HybridAnalysis using PowerShell.

    .EXAMPLE
    Search-HybridAnalysis -ApiKey <APIKEY> -Endpoint hash -Name hash -Query 116858001ed50d8dd02b353473a139b98820dcf620c9e70e8a51c49f62cc6581 | Format-List

    job_id                    : 5c8c08950288388746c6f986
    environment_id            : 110
    environment_description   : Windows 7 32 bit (HWP Support)
    size                      : 413556
    type                      : PDF document, version 1.3
    type_short                : {pdf}
    target_url                : 
    state                     : SUCCESS
    error_type                : 
    error_origin              : 
    submit_name               : Citigroup Acc OR 86236564.pdf
    md5                       : e1a1da63a973ff780cf0415d2cfddcc8
    sha1                      : 0a3c1770f0a0c998a31f6b55dec2b592ba7890e7
    sha256                    : 116858001ed50d8dd02b353473a139b98820dcf620c9e70e8a51c49f62cc6581
    sha512                    : 9379207951778666369d2190ffa4797650d41f312858b2b807c960b9889fbef21c961c16c1fe3c6baef2362a0ef9df42672d312d
                                c085c0761851e4434adc6251
    ssdeep                    : 6144:65I9D6nuGeCeqy8dvq0eNOFIyxT8di6dggXg9DeJbDtz04BO34mRkehkuINPCFsz:65I97OZJZsZiV/pl45HuO4sKBLZ9mTFj
    imphash                   : Unknown
    av_detect                 : 
    vx_family                 : 
    url_analysis              : False
    analysis_start_time       : 3/15/19 8:09:37 PM
    threat_score              : 100
    interesting               : False
    threat_level              : 2
    verdict                   : malicious
    certificates              : {}
    domains                   : {a1089.dscd.akamai.net, cs9.wac.phicdn.net, d1zkz3k4cclnv6.cloudfront.net, 
                                dcky6u1m8u6el.cloudfront.net...}
    classification_tags       : {banker, emotet, evasive}
    compromised_hosts         : {99.84.254.97, 172.217.9.35, 54.201.6.28, 99.84.254.15...}
    hosts                     : {54.149.115.79, 99.84.254.97, 172.217.9.42, 172.217.9.35...}
    total_network_connections : 7
    total_processes           : 8
    total_signatures          : 48
    extracted_files           : {}
    processes                 : {}
    file_metadata             : 
    tags                      : {banker, emotet, evasive}
    mitre_attcks              : {@{tactic=Execution; technique=Windows Management Instrumentation; attck_id=T1047; 
                                attck_id_wiki=https://attack.mitre.org/wiki/Technique/T1047; malicious_identifiers_count=0; 
                                malicious_identifiers=System.Object[]; suspicious_identifiers_count=1; 
                                suspicious_identifiers=System.Object[]; informative_identifiers_count=0; 
                                informative_identifiers=System.Object[]}, @{tactic=Execution; technique=Service Execution; 
                                attck_id=T1035; attck_id_wiki=https://attack.mitre.org/wiki/Technique/T1035; 
                                malicious_identifiers_count=0; malicious_identifiers=System.Object[]; suspicious_identifiers_count=2; 
                                suspicious_identifiers=System.Object[]; informative_identifiers_count=0; 
                                informative_identifiers=System.Object[]}, @{tactic=Persistence; technique=Hooking; attck_id=T1179; 
                                attck_id_wiki=https://attack.mitre.org/wiki/Technique/T1179; malicious_identifiers_count=0; 
                                malicious_identifiers=System.Object[]; suspicious_identifiers_count=0; 
                                suspicious_identifiers=System.Object[]; informative_identifiers_count=1; 
                                informative_identifiers=System.Object[]}, @{tactic=Persistence; technique=New Service; attck_id=T1050; 
                                attck_id_wiki=https://attack.mitre.org/wiki/Technique/T1050; malicious_identifiers_count=1; 
                                malicious_identifiers=System.Object[]; suspicious_identifiers_count=0; 
                                suspicious_identifiers=System.Object[]; informative_identifiers_count=0; 
                                informative_identifiers=System.Object[]}...}


    ##############################################################################
    Available options not found in 'Get-Help Search-HybridAnalysis' SYNTAX section
    ##############################################################################
    
    Endpoint: hash
    Name    : [hash]
    Query   : <STRING>

    Endpoint: terms
    Name    : [authentihash,av_detect,context,country,domain,env_id,filename,filetype_desc,filetype,host,imp_hash,port,similar_to,ssdeep,tag,url,verdict,vx_family]
    Document: <STRING>
    
    ##############################################################################
    Available options not found in 'Get-Help Search-HybridAnalysis' SYNTAX section
    ##############################################################################
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-HybridAnalysis {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,

        [Parameter(Mandatory=$true)]
        [ValidateSet('hash', 'terms')]
        [string]$Endpoint,
        [Parameter(Mandatory=$true)]
        [ValidateSet('authentihash', 'av_detect', 'context', 'country', 'domain', 'env_id', 'filename', 'filetype_desc', 'filetype', 'hash', 'host', 'imp_hash', 'port', 'similar_to', 'ssdeep', 'tag', 'url', 'verdict', 'vx_family')]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-HybridAnalysis -Examples' to see available options.
            #
            if ($Endpoint -eq 'hash') {
                if ($_ -in @('hash')) {$True}
            } elseif ($Endpoint -eq 'terms') {
                if ($_ -notin @('hash')) {$True}
            }
        })]
        [string]$Name,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $Body = "@{$Name='$Query'}"
        $Headers = "@{'Accept'='application/json';'api-key'='$ApiKey'}"
        $Method = 'POST'
        $UserAgent = 'Falcon Sandbox'
        $Uri = "https://www.hybrid-analysis.com/api/v2/search/$Endpoint".ToLower()
        $ExtraRequestParams = "-Body $($Body) -Headers $Headers"
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose 'Complete'}
}

