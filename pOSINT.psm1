<#
    .SYNOPSIS
    Request Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Request Open-Source Intelligence using PowerShell. The response is a 
    PowerShell object which can be formatted in many different ways.
                                 
    .EXAMPLE
    Request-Osint -Crtsh -QueryString jotugaedorm.com -Wildcard | Format-List

    issuer_ca_id        : 12922
    issuer_name         : C=US, ST=TX, L=Houston, O="cPanel, Inc.", CN="cPanel, Inc. Certification Authority"
    name_value          : cpanel.jotugaedorm.com
    min_cert_id         : 1179646010
    min_entry_timestamp : 2/6/19 9:46:22 PM
    not_before          : 2/6/19 12:00:00 AM
    not_after           : 5/7/19 11:59:59 PM

    ...

    .EXAMPLE
    Request-Osint -Cymon -QueryString 195.123.237.120 -CyQueryType ip | Format-List

    total : 1
    from  : 0
    size  : 10
    hits  : {@{title=Malware email submission; link=http://www.senderbase.org/lookup/?search_string=195.123.237.120; reported_by=cymon; feed=senderbase.org; feed_id=AVsGXxCjVjrVcoBZyoh-; timestamp=12/10/18 6:00:02 AM; tags=System.Object[]; ioc=; id=7d33126e4f3e1acb8ea770cda0452fb641617f798aa6302b025dc2d148ec84f8}}

    .EXAMPLE
    Request-Osint -GreyNoise -GnQueryType list | Format-List

    status : ok
    tags   : {VNC_SCANNER_HIGH, PING_SCANNER_LOW, BINGBOT, IIS_WEBDAV_REMOTE_CODE_EXECUTION_CVE_2017_7269...}

    .EXAMPLE
    Request-Osint -GreyNoise -QueryString shodan -GnQueryType tag | Format-List

    tag            : SHODAN
    status         : ok
    returned_count : 297
    records        : {@{ip=107.6.151.194; name=SHODAN; first_seen=2/24/19 12:53:40 PM; last_updated...}...}

    .EXAMPLE
    Request-Osint -PhishingKitTracker | Format-List

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

    .EXAMPLE
    Request-Osint -Threatcrowd -QueryString 188.40.75.132 -TcQueryType ip | Format-List

    response_code : 1
    resolutions   : {@{last_resolved=2015-02-17; domain=tvgate.rocks}, @{last_resolved=2015-02-17; domain=nice-mobiles.com}, @{last_resolved=2015-02-17; domain=nauss-lab.com}, @{last_resolved=2015-02-17; 
                    domain=iwork-sys.com}...}
    hashes        : {003f0ed24b5f70ddc7c6e80f9c4dac73, 027fc90c13f6d87e1f68d25b0d0ec4a7, 088420b7e56c73d3d495230d42e0cb95, 1e52a293838464e4cd6c1c6d94a55793...}
    references    : {}
    votes         : -1
    permalink     : https://www.threatcrowd.org/ip.php?ip=188.40.75.132

    .EXAMPLE
    Request-Osint -Urlhaus -QueryString 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11 -UhQueryType payload | Format-List

    query_status     : ok
    md5_hash         : fbd9ea8ffe773b85a603665c44a86502
    sha256_hash      : 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11
    content_type     : exe
    file_size        : 339968
    signature        : 
    firstseen        : 2019-03-01 16:50:06
    lastseen         : 2019-03-01 20:40:07
    url_count        : 1
    urlhaus_download : https://api.urlhaus.abuse.ch/v1/download/4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11/
    virustotal       : 
    urls             : {@{url_id=149696; url=http://195.123.237.120/tin.png; url_status=offline; urlhaus_reference=https://urlhaus.abuse.ch/url/149696/; filename=; firstseen=2019-03-01; lastseen=2019-03-01}}

    .EXAMPLE
    Request-Osint -Urlscan -QueryString 4ef1c08fe44a8d1e1c8ef214e7ed63a318663e926860702076bc6234fd3b1d11 | Format-List

    task           : @{visibility=public; method=automatic; time=3/1/19 5:03:35 PM; source=urlhaus; url=http://195.123.237.120/tin.png}
    stats          : @{uniqIPs=1; consoleMsgs=0; dataLength=339968; encodedDataLength=340210; requests=1}
    page           : @{country=UA; server=nginx/1.6.2; city=; domain=195.123.237.120; ip=195.123.237.120; asnname=LAYER6, UA; asn=AS204957; url=http://195.123.237.120/tin.png; ptr=sweetdrem.biz}
    uniq_countries : 1
    _id            : 5524d559-9d34-4147-8c05-e434756d6a41
    result         : https://urlscan.io/api/v1/result/5524d559-9d34-4147-8c05-e434756d6a41
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Request-Osint {
    [CmdletBinding()]
    param(
        [parameter(ParameterSetName="crtsh",
        Mandatory=$true)]
        [Switch]$Crtsh,
        [parameter(ParameterSetName="cymon",
        Mandatory=$true)]
        [Switch]$Cymon,
        [parameter(ParameterSetName="greynoise",
        Mandatory=$true)]
        [Switch]$GreyNoise,
        [parameter(ParameterSetName="phishingkittracker",
        Mandatory=$true)]
        [Switch]$PhishingKitTracker,
        [parameter(ParameterSetName="threatcrowd",
        Mandatory=$true)]
        [Switch]$Threatcrowd,
        [parameter(ParameterSetName="urlhaus",
        Mandatory=$true)]
        [Switch]$Urlhaus,
        [parameter(ParameterSetName="urlscan.io",
        Mandatory=$true)]
        [Switch]$Urlscan,

        [parameter(ParameterSetName="crtsh",
        Mandatory=$false)]
        [Switch]$Wildcard,

        [parameter(ParameterSetName="crtsh",
        Mandatory=$true)]
        [parameter(ParameterSetName="cymon",
        Mandatory=$true)]
        [parameter(ParameterSetName="greynoise",
        Mandatory=$false)]
        [parameter(ParameterSetName="threatcrowd",
        Mandatory=$true)]
        [parameter(ParameterSetName="urlhaus",
        Mandatory=$true)]
        [parameter(ParameterSetName="urlscan.io",
        Mandatory=$true)]
        [String]$QueryString,

        [parameter(ParameterSetName="cymon",
        Mandatory=$true)]
        [ValidateSet("ip", "domain", "hostname", "md5", "sha256", "ssdeep", "term")]
        $CyQueryType,
        [parameter(ParameterSetName="greynoise",
        Mandatory=$true)]
        [ValidateSet("list", "ip", "tag")]
        $GnQueryType,
        [parameter(ParameterSetName="threatcrowd",
        Mandatory=$true)]
        [ValidateSet("email", "domain", "ip", "resource")]
        $TcQueryType,
        [parameter(ParameterSetName="urlhaus",
        Mandatory=$true)]
        [ValidateSet("url", "host", "payload")]
        $UhQueryType
    )
    
    Begin {
        $CurrentSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

        $Method  = "GET"
        $Body    = $Null
        $Timeout = 30

        Switch ($PSCmdlet.ParameterSetName) {
            "crtsh" {
                if ($Wildcard) {
                    $QueryString = "%25.$QueryString"
                }

                [String]$Uri = "https://crt.sh/?q=$QueryString&output=json"
                Break
            }
            "cymon" {
                $QueryType   = $CyQueryType.ToLower()
                [String]$Uri = "https://api.cymon.io/v2/ioc/search/$QueryType/$QueryString"
                Break
            }
            "greynoise" {
                $QueryType = $GnQueryType.ToLower()

                if ($QueryType -in @("ip", "tag")) {
                    $Method = "POST"
                    $Body   = "$QueryType=$($QueryString.ToUpper())"
                }

                [String]$Uri = "https://api.greynoise.io/v1/query/$QueryType"
                Break
            }
            "phishingkittracker" {
                [String]$Uri = "https://raw.githubusercontent.com/neonprimetime/PhishingKitTracker/master/PhishingKitTracker.csv"
                $ReponseType = "CSV"
                Break
            }
            "threatcrowd" {
                $QueryType = $TcQueryType.ToLower()
                [String]$BaseUri = "https://www.threatcrowd.org/searchApi/v2/$QueryType"

                if ($TcQueryType -eq "resource") {
                    [String]$BaseUri = "https://www.threatcrowd.org/searchApi/v2/file"
                }

                [String]$Uri = "$BaseUri/report/?$QueryType=$QueryString"
                Break
            }
            "urlhaus" {
                $QueryType = $UhQueryType.ToLower()
                $Method    = "POST"
                $Body      = "$QueryType=$QueryString"

                Switch($QueryType) {
                    "payload" {
                        if ($QueryString.Length -eq 32) {
                            $Body = "md5_hash=$QueryString"
                        } elseif ($QueryString.Length -eq 64) {
                            $Body = "sha256_hash=$QueryString"
                        }
                    }
                }

                [String]$Uri = "https://urlhaus-api.abuse.ch/v1/$QueryType/"
                Break
            }
            "urlscan.io" {
                [String]$Uri = "https://urlscan.io/api/v1/search/?q=$QueryString&size=10000"
                $ReponseType = "OBJ"
                Break
            }
        }
    }

    Process {
        Write-Verbose "`nMethod : $Method"
        Write-Verbose "Body   : $Body"
        Write-Verbose "URI    : $Uri"
        Write-Verbose "Timeout: $Timeout"
        $Response = Invoke-RestMethod -Method $Method -Body $Body -Uri $Uri -TimeoutSec $Timeout
        
        if ($ReponseType -eq "CSV") {
            $Response |  
                ConvertFrom-Csv
        } elseif ($ReponseType -eq "JSON") {
            $Response | 
                Select-Object -ExpandProperty Content | 
                ConvertFrom-Json
        } elseif ($ReponseType -eq "OBJ") {
            $Response | 
                Select-Object -ExpandProperty Results
        } else {
            $Response
        }
    }

    End {
        [Net.ServicePointManager]::SecurityProtocol = $CurrentSecurityProtocol
        Write-Verbose "`nComplete"
    }
}
