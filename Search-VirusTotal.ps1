<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from VirusTotal using PowerShell.

    .EXAMPLE
    Search-VirusTotal -ApiKey <APIKEY> -Endpoint ip-address -Query 99.84.254.97 | Format-List

    asn                           : 7018
    undetected_urls               : {http://oasjs.kataweb.it/ 0cefd68381b426c7666dc2a7845bc9389280c1b73f190315b94ef311fdf4283e 0 69 2019-03-21 13:46:29, 
                                    http://de5zarwna0j2q.cloudfront.net/native/placements/ansa.it/pconfig?r=7d426347 64a3a1e4d68ce4d2802b5889ff0b35db5ff57717a6b6193447d0d1f0368ff4b7 0 69 2019-03-21 
                                    03:38:15, https://cdn.picrew.me/app/share/201903/41329_Xvt6EbMM.png 7a819c225e844e5840c91238298feee7e1edcf3f013fd13ce6ab9c00c7ee2f35 0 69 2019-03-20 18:00:14, 
                                    http://myconnection.cox.com/?ptrxcz_oflwddupzxsmmerwsfppkfbgoxj4df 9084deb41029914a85fa3bb6a1ea7f67b82926d55ec5635ef9d1d56f6316eaea 0 69 2019-03-20 12:07:36...}
    undetected_downloaded_samples : {@{date=2019-03-18 20:27:36; positives=0; total=67; sha256=0eeb00ea3dd08f15c0afa1bd8d4fdc0d1e0a11f97f097f1f0fed9df3fe77ccc0}, @{date=2018-08-17 01:58:40; positives=0; 
                                    total=70; sha256=92e8f8c0b1cba7ad83c7376808958507e04c5bf6c659a304d551a29d59ede1fc}, @{date=2019-03-20 18:00:14; positives=0; total=0; 
                                    sha256=ca9b692f10ea88c9204548918066cd28f8564e29a36bfa42f595aa2708c35969}, @{date=2019-03-20 15:20:33; positives=0; total=59; 
                                    sha256=6d3d7cd53add6e68a60a27238b7b8ade1385da4ef460aeb4e37079c458f4ab92}...}
    whois                         : NetHandle: NET-99-83-64-0-1
                                    NetType: Direct Allocation
                                    Organization: Amazon.com, Inc. (AMAZO-4)
                                    Updated: 2018-01-11
                                    OrgName: Amazon.com, Inc.
                                    OrgId: AMAZO-4
                                    City: Seattle
                                    PostalCode: 98108-1226
                                    Country: US
                                    Updated: 2018-09-19
                                    OrgNOCHandle: AANO1-ARIN
                                    OrgNOCName: Amazon AWS Network Operations
                                    OrgNOCPhone: +1-206-266-4064
                                    OrgNOCEmail: amzn-noc-contact@amazon.com
                                    OrgNOCRef: https://rdap.arin.net/registry/entity/AANO1-ARIN
                                    OrgTechHandle: ANO24-ARIN
                                    OrgTechName: Amazon EC2 Network Operations
                                    OrgTechPhone: +1-206-266-4064
                                    OrgTechEmail: amzn-noc-contact@amazon.com
                                    OrgTechRef: https://rdap.arin.net/registry/entity/ANO24-ARIN
                                    OrgAbuseHandle: AEA8-ARIN
                                    OrgAbuseName: Amazon EC2 Abuse
                                    OrgAbusePhone: +1-206-266-4064
                                    OrgAbuseEmail: abuse@amazonaws.com
                                    OrgAbuseRef: https://rdap.arin.net/registry/entity/AEA8-ARIN
    whois_timestamp               : 1543910560
    country                       : US
    response_code                 : 1
    as_owner                      : AT&T Services, Inc.
    verbose_msg                   : IP address in dataset
    detected_downloaded_samples   : {@{date=2019-02-17 13:16:14; positives=1; total=71; sha256=35e15ef3ac2bcea68a2e892e37c7a7fa50d869a0c95091593164227c92ba3279}, @{date=2019-03-21 03:09:14; positives=2; 
                                    total=57; sha256=f1a97c433f29d7b1aa47840fd1ecdab57c7d1a6b927823d0e4a174524ba658b2}, @{date=2019-03-20 14:28:54; positives=2; total=57; 
                                    sha256=a3052d59930a9eba9774017b49e55b2f4e9b3cfa02984f2be09b7e52c99fa2e2}, @{date=2019-03-19 15:09:32; positives=1; total=56; 
                                    sha256=da581f0d8c4a92d8a87bace76b7c57a015a338f5466e6f40eee6acdcafa79081}...}
    resolutions                   : {@{last_resolved=2018-12-04 11:08:27; hostname=0-1-39.inyourarea.co.uk}, @{last_resolved=2019-01-29 08:52:46; hostname=0-3-3.inyourarea.co.uk}, @{last_resolved=2019-01-29 
                                    06:00:25; hostname=00215-qa.eci26381.easn.morningstar.com}, @{last_resolved=2019-01-17 17:41:02; hostname=074630452374.dev.cirrus.panasonic.com}...}
    detected_urls                 : {@{url=https://api.al1cloud.com/9/sim/4J213OU4F08BPTDC; positives=2; total=69; scan_date=2019-03-22 23:11:12}, 
                                    @{url=http://apps.sfcdn.org/apk/com.applidium.nickelodeon.bce9d3577aa62447dfdf5e560c2b07df.apk; positives=4; total=69; scan_date=2019-03-21 13:12:35}, 
                                    @{url=http://apps.sfcdn.org/apk/com.wyt.iexuetang.tv.xxas.651633acfaca2b4c5d6a00b7912cfffb.apk; positives=4; total=69; scan_date=2019-03-21 13:10:54}, 
                                    @{url=http://apps.sfcdn.org/apk/com.shafa.launcher.62cd07e6111407b7371be6c23e2291c3.apk; positives=4; total=69; scan_date=2019-03-21 13:10:03}...}
    continent                     : NA
    network                       : 99.84.248.0/21
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-VirusTotal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ApiKey,
        [Parameter(Mandatory=$true)]
        [ValidateSet("file", "url", "domain", "ip-address")]
        [string]$Endpoint,
        [Parameter(Mandatory=$true)]
        [string]$Query
    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        Switch($Endpoint) {
            "file" {
                $VirusTotalParam = "resource"
                Break
            }
            "url" {
                $VirusTotalParam = "resource"
                Break
            }
            "ip-address" {
                $VirusTotalParam = "ip"
                Break
            }
        }

        $BaseUri = "https://www.virustotal.com/vtapi/v2/$Endpoint/report"
        $Uri = "$BaseUri`?apikey=$ApiKey&$VirusTotalParam=$Query".ToLower()
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose "Complete"}
}

