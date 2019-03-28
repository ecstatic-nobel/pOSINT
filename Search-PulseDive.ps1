<#
    .SYNOPSIS
    Gather Open-Source Intelligence using PowerShell.
                 
    .DESCRIPTION
    Gather Open-Source Intelligence from PulseDive using PowerShell.

    .EXAMPLE
    Search-PulseDive -Endpoint threat -Query Zeus | Format-List

    Summary : @{risk=; feeds=System.Object[]; attributes=; properties=}
    Value   : @{tid=1; threat=Zeus; category=malware; risk=high; description=; wikisummary=Zeus, ZeuS, or Zbot is a Trojan horse malware package that runs on versions of Microsoft Windows. While it can be 
              used to carry out many malicious and criminal tasks, it is often used to steal banking information by man-in-the-browser keystroke logging and form grabbing.; 
              wikireference=https://en.wikipedia.org/wiki/Zeus_(malware); retired=; stamp_added=2017-09-27 18:11:38; stamp_updated=2018-07-06 19:02:51; stamp_seen=2019-03-20 03:32:16; stamp_retired=; 
              updated_last_domain=2019-03-21 00:00:00; comments=System.Object[]; othernames=System.Object[]; techniques=System.Object[]; news=System.Object[]}
    Linked  : @{page_current=0; results=System.Object[]}

    .EXAMPLE
    Search-PulseDive -Endpoint indicator -Query pulsedive.com | Format-List

    Value      : @{iid=53929; type=domain; indicator=pulsedive.com; risk=none; risk_recommended=none; manualrisk=0; retired=No recent activity; stamp_added=2017-10-04 01:20:55; stamp_updated=2019-03-06 
                 12:25:08; stamp_seen=2019-03-26 14:59:39; stamp_probed=2019-03-06 12:25:08; stamp_retired=; recent=0; riskfactors=System.Object[]; attributes=; domain=; domainiid=; properties=}
    Linked     : @{Active DNS=System.Object[]; SSL Certificate Domains=System.Object[]; Redirects=System.Object[]; Related URLs=System.Object[]}
    Properties : @{cookies=System.Object[]; dns=System.Object[]; geo=System.Object[]; http=System.Object[]; meta=System.Object[]; ssl=System.Object[]; whois=System.Object[]}

    .EXAMPLE
    Search-PulseDive -Endpoint feed_list | Format-List
    
    results : {@{schedule=daily; fid=1; stamp_updated=2018-10-08 00:41:35; name=Zeus Bad Domains; stamp_modified=2019-03-19 09:15:40; category=malware; stamp_pulled=2019-03-28 09:16:00; 
              organization=abuse.ch; indicators=System.Collections.Hashtable; pricing=free}, @{schedule=daily; fid=2; stamp_updated=2018-10-08 00:41:28; name=Zeus Bad IPs; stamp_modified=2019-03-19 
              09:15:43; category=malware; stamp_pulled=2019-03-28 09:16:01; organization=abuse.ch; indicators=System.Collections.Hashtable; pricing=free}, @{schedule=daily; fid=3; stamp_updated=2018-12-31 
              09:59:15; name=Tor IPs; stamp_modified=2019-03-28 09:30:27; category=proxy; stamp_pulled=2019-03-28 09:30:44; organization=dan.me.uk; indicators=System.Collections.Hashtable; pricing=free}, 
              @{schedule=daily; fid=4; stamp_updated=2018-10-08 00:38:08; name=C&amp;C IPs; stamp_modified=2019-03-28 09:30:45; category=malware; stamp_pulled=2019-03-28 09:30:52; organization=Bambenek 
              Consulting; indicators=System.Collections.Hashtable; pricing=free}...}

    .EXAMPLE
    Search-PulseDive -Endpoint feed -Query "Zeus Bad Domains" -organization abuse.ch | Format-List

    Name   : @{fid=1; feed=Zeus Bad Domains; category=malware; pricing=free; organization=abuse.ch; contact=; website=https://abuse.ch/; schedule=daily; stamp_added=2017-09-27 00:00:00; 
             stamp_updated=2018-10-08 00:41:35; stamp_pulled=2019-03-28 09:16:00; stamp_modified=2019-03-19 09:15:40; indicators=}
    Linked : @{page_current=0; results=System.Object[]}
    
    .LINK
    https://github.com/ecstatic-nobel/pOSINT/
#>
function Search-PulseDive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ApiKey,
        [Parameter(Mandatory=$true)]
        [ValidateSet('indicator', 'threat', 'feed', 'feed_list')]
        [string]$Endpoint,
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-PulseDive -Examples' to see available options.
            #
            if ($Endpoint -ne 'feed_list') {$true}
        })]
        [string]$Query,
        [Parameter(Mandatory=$false)]
        [ValidateScript({
            #
            # Mismatch detected. Use 'Get-Help Search-PulseDive -Examples' to see available options.
            #
            if ($Endpoint -eq 'feed') {$true}
        })]
        [string]$Organization

    )
    
    Begin {
        Set-SslDefaults
        Set-ModuleDefaults

        $Uri = 'https://pulsedive.com/api/info.php'
        $Endpoint = $Endpoint.ToLower()
        $Body = "@{$Endpoint='$Query';pretty=1;key='$ApiKey'}"
        $ExtraRequestParams = "-Body $Body"

        Switch ($Endpoint) {
            'feed' {
                $Body = "@{$Endpoint='$Query';organization='$Organization';pretty=1;key='$ApiKey'}"
                $ExtraRequestParams = "-Body $Body"
            }
            'feed_list' {
                $Uri = 'https://pulsedive.com/api/search.php?category%5B%5D=general&category%5B%5D=abuse&category%5B%5D=apt&category%5B%5D=attack&category%5B%5D=botnet&category%5B%5D=crime&category%5B%5D=exploitkit&category%5B%5D=fraud&category%5B%5D=group&category%5B%5D=malware&category%5B%5D=proxy&category%5B%5D=pup&category%5B%5D=rat&category%5B%5D=reconnaissance&category%5B%5D=spam&category%5B%5D=phishing&category%5B%5D=terrorism&category%5B%5D=vulnerability&search=feed&splitrisk=true&sanitize=true'
                $ReponseType = 'JSON'
            }
        }
    }
    Process {Search-Api}
    End {Reset-SslDefaults; Write-Verbose 'Complete'}
}
