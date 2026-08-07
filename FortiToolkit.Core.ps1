<#
    FortiToolkit - core
    Parsing, reference analysis, duplicate detection. No UI in this file.

    Design notes
    ------------
    1. Reference analysis scans EVERY value of EVERY object. A whitelist of
       "fields that can hold a reference" is silently wrong when incomplete,
       and it fails toward deletion. Roots are derived, not listed.

    2. FortiOS omits settings sitting at factory default, so an absent key is
       not an unset value. Rules declare the default to assume.

    Performance
    -----------
    The hot path is the reachability walk: roughly one tokenise plus one index
    lookup per setting value, which on an 80k line config is several hundred
    thousand iterations. Three things matter there and are done deliberately:

      - the index is nested (vdom -> name -> objects) so no interpolated
        string key is allocated per lookup
      - tokenising is inlined for the common unquoted case, avoiding a
        function call per value
      - Join-Sorted uses Array::Sort instead of the Sort-Object cmdlet,
        because it is called several times per policy

    Collections are generic List[object]. Add() on a generic list returns
    void, unlike ArrayList, so there is no [void] cast on those calls.
#>

# =================================================================== HELPERS

$script:SpaceSep = [char[]]@(' ', "`t")
$script:QuoteRx  = New-Object System.Text.RegularExpressions.Regex '"([^"]*)"|(\S+)', 'Compiled'

function New-Set {
    param([string[]]$Items)
    $h = @{}
    foreach ($i in $Items) { $h[$i] = $true }
    return $h
}

function Strip-Quotes {
    param([string]$V)
    if ($V.Length -gt 1 -and $V[0] -eq '"' -and $V[$V.Length - 1] -eq '"') {
        return $V.Substring(1, $V.Length - 2)
    }
    return $V
}

function Split-Tokens {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return @() }
    if ($Value.IndexOf('"') -lt 0) {
        return $Value.Split($script:SpaceSep, [System.StringSplitOptions]::RemoveEmptyEntries)
    }
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $script:QuoteRx.Matches($Value)) {
        if ($m.Groups[1].Success) { $out.Add($m.Groups[1].Value) }
        else { $out.Add($m.Groups[2].Value) }
    }
    return $out.ToArray()
}

function Join-Sorted {
    param([string]$Value)
    $t = Split-Tokens $Value
    if ($t.Count -eq 0) { return '' }
    if ($t.Count -eq 1) { return [string]$t[0] }
    $a = [string[]]$t
    [System.Array]::Sort($a)
    return ($a -join ',')
}

function Get-MaskBits {
    param([string]$Mask)
    if ($Mask.Length -le 2) {
        $r = 0
        if ([int]::TryParse($Mask, [ref]$r)) { return $r }
    }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Mask, [ref]$ip)) { return $Mask }
    $count = 0
    foreach ($b in $ip.GetAddressBytes()) {
        $v = [int]$b
        while ($v -ne 0) {
            $count = $count + ($v -band 1)
            $v = $v -shr 1
        }
    }
    return $count
}

# =================================================================== SETS

# Sections whose objects are cleanup candidates.
$script:WatchSet = New-Set @(
    'firewall address','firewall address6','firewall addrgrp','firewall addrgrp6',
    'firewall service custom','firewall service group','firewall vip','firewall vip6',
    'firewall vipgrp','firewall ippool','firewall ippool6','firewall schedule recurring',
    'firewall schedule onetime','firewall schedule group','firewall ldb-monitor',
    'firewall shaper traffic-shaper','firewall shaper per-ip-shaper','firewall wildcard-fqdn custom'
)

$script:GroupSet = New-Set @(
    'firewall addrgrp','firewall addrgrp6','firewall service group','firewall vipgrp',
    'firewall vipgrp6','firewall proxy-addrgrp','firewall schedule group',
    'firewall internet-service-group','user group','firewall wildcard-fqdn group'
)

# Values that never hold an object reference.
$script:SkipKeys = New-Set @('comment','comments','description','uuid','q_origin_key')

# FortiOS ships these. They can legitimately show zero references in a config
# file yet must never be deleted. Hard stop, independent of the analysis.
$script:Builtin = New-Set @(
    'all','none','ALL','NONE','ANY','any',
    'SSLVPN_TUNNEL_ADDR1','SSLVPN_TUNNEL_IPv6_ADDR1','SSLVPN_TUNNEL_IPv6_ADDR2',
    'FABRIC_DEVICE','FIREWALL_AUTH_PORTAL_ADDRESS','login.microsoftonline.com',
    'metadata-server','gcp-metadata-server','azure-metadata-server','aws-metadata-server',
    'autoupdate.opensource.org','wildcard.dropbox.com','wildcard.google.com',
    'always','default','Deny','deny','none-schedule',
    'ALL_TCP','ALL_UDP','ALL_ICMP','ALL_ICMP6','AFS3','AH','BGP','DCE-RPC','DHCP','DHCP6',
    'DNS','ESP','FINGER','FTP','FTP_GET','FTP_PUT','GRE','GTP','H323','HTTP','HTTPS','IKE',
    'IMAP','IMAPS','Internet-Locator-Service','IRC','KERBEROS','L2TP','LDAP','LDAP_UDP',
    'MGCP','MMS','MS-SQL','MYSQL','NetMeeting','NFS','NNTP','NTP','ONC-RPC','OSPF',
    'PC-Anywhere','PING','PING6','POP3','POP3S','PPTP','QUAKE','RADIUS','RADIUS-OLD',
    'RAUDIO','RIP','RLOGIN','RSH','RTSP','SAMBA','SCCP','SIP','SIP-MSNmessenger','SMTP',
    'SMTPS','SNMP','SOCKS','SQUID','SSH','SYSLOG','TALK','TELNET','TFTP','TIMESTAMP',
    'TRACEROUTE','UUCP','VDOLIVE','VNC','WAIS','WINFRAME','WINS','X-WINDOWS','webproxy',
    'Email Access','Web Access','Windows AD','Exchange Server','G Suite',
    'Microsoft Office 365','Salesforce','DNS Resolution','Web Management'
)
$script:BuiltinPrefix = @('SSLVPN_','FABRIC_','FIREWALL_AUTH_','Fortinet_','FCTUEMS_','g-')

function Test-Builtin {
    param([string]$Name)
    if ($script:Builtin.ContainsKey($Name)) { return $true }
    foreach ($p in $script:BuiltinPrefix) { if ($Name.StartsWith($p)) { return $true } }
    return $false
}

# Duplicate rule id per section.
$script:DupSec = @{
    'firewall address'            = 1
    'firewall address6'           = 1
    'firewall addrgrp'            = 2
    'firewall addrgrp6'           = 2
    'firewall service custom'     = 3
    'firewall service group'      = 4
    'firewall vip'                = 5
    'firewall vip6'               = 5
    'firewall ippool'             = 6
    'firewall ippool6'            = 6
    'firewall schedule recurring' = 7
    'router static'               = 8
    'router static6'              = 8
    'system interface'            = 9
    'firewall policy'             = 10
    'firewall policy6'            = 10
    'firewall proxy-policy'       = 10
}

# cmdb paths for the mandatory refcnt verification step.
$script:CmdbPath = @{
    'firewall address'            = 'firewall.address.name'
    'firewall address6'           = 'firewall.address6.name'
    'firewall addrgrp'            = 'firewall.addrgrp.name'
    'firewall addrgrp6'           = 'firewall.addrgrp6.name'
    'firewall service custom'     = 'firewall.service.custom.name'
    'firewall service group'      = 'firewall.service.group.name'
    'firewall vip'                = 'firewall.vip.name'
    'firewall vip6'               = 'firewall.vip6.name'
    'firewall vipgrp'             = 'firewall.vipgrp.name'
    'firewall ippool'             = 'firewall.ippool.name'
    'firewall ippool6'            = 'firewall.ippool6.name'
    'firewall schedule recurring' = 'firewall.schedule.recurring.name'
    'firewall schedule onetime'   = 'firewall.schedule.onetime.name'
    'firewall schedule group'     = 'firewall.schedule.group.name'
    'firewall ldb-monitor'        = 'firewall.ldb-monitor.name'
    'firewall shaper traffic-shaper' = 'firewall.shaper.traffic-shaper.name'
}

# =================================================================== PARSER

function Parse-FortiConfig {
    param([string[]]$Lines)

    $objects  = [System.Collections.Generic.List[object]]::new()
    $header   = [System.Collections.Generic.List[object]]::new()
    $stack    = New-Object System.Collections.Stack
    $sectObjs = @{}

    $curVdom = 'root'
    $curSeg  = ''
    $curPath = ''
    $curObj  = $null
    $depth   = 0
    $sawVdom = $false

    $n = $Lines.Length
    for ($i = 0; $i -lt $n; $i++) {

        $line = $Lines[$i].Trim()
        if ($line.Length -eq 0) { continue }
        $c0 = $line[0]

        # 'set' is the most common line by a wide margin, so test it first
        if ($c0 -eq 's' -and $line.Length -gt 4 -and $line.StartsWith('set ')) {
            $rest = $line.Substring(4)
            $sp = $rest.IndexOf(' ')
            $sk = $rest
            $sv = ''
            if ($sp -ge 0) {
                $sk = $rest.Substring(0, $sp)
                $sv = $rest.Substring($sp + 1).Trim()
            }
            if ($null -ne $curObj) {
                $curObj.T[$sk] = $sv
            }
            elseif ($curPath -ne '') {
                # a block with no 'edit', e.g. config vpn ssl settings.
                # these hold real references and real settings.
                $sid = "$curVdom|$curPath"
                $so = $sectObjs[$sid]
                if ($null -eq $so) {
                    $so = @{ V = $curVdom; S = $curPath; N = '(settings)'; T = @{}; L = $i + 1; Sect = $true }
                    $sectObjs[$sid] = $so
                }
                $so.T[$sk] = $sv
            }
            continue
        }

        if ($c0 -eq 'n' -and $line -eq 'next') {
            if ($null -ne $curObj) {
                if ($curSeg -ne 'vdom') { $objects.Add($curObj) }
                $curObj = $null
            }
            continue
        }

        if ($c0 -eq 'e' -and $line.Length -gt 5 -and $line.StartsWith('edit ')) {
            $name = Strip-Quotes $line.Substring(5).Trim()
            if ($curSeg -eq 'vdom' -and $depth -eq 1) { $curVdom = $name }
            $curObj = @{ V = $curVdom; S = $curPath; N = $name; T = @{}; L = $i + 1; Sect = $false }
            continue
        }

        if ($c0 -eq 'e' -and $line -eq 'end') {
            if ($null -ne $curObj) {
                if ($curSeg -ne 'vdom') { $objects.Add($curObj) }
                $curObj = $null
            }
            if ($stack.Count -gt 0) {
                $f = $stack.Pop()
                $curSeg = $f[0]; $curPath = $f[1]; $curObj = $f[2]; $curVdom = $f[3]
                $depth--
            } else {
                $curSeg = ''; $curPath = ''; $curVdom = 'root'; $depth = 0
            }
            continue
        }

        if ($c0 -eq 'c' -and $line.Length -gt 7 -and $line.StartsWith('config ')) {
            $stack.Push(@($curSeg, $curPath, $curObj, $curVdom))
            $depth++
            $seg = $line.Substring(7).Trim()
            # vdom / global are scope markers, not path segments
            if ($curPath -eq '' -or $curPath -eq 'vdom' -or $curPath -eq 'global') {
                $curPath = $seg
            } else {
                $curPath = "$curPath/$seg"
            }
            $curSeg = $seg
            $curObj = $null
            if ($seg -eq 'vdom') { $sawVdom = $true }
            elseif ($seg -eq 'global') { $curVdom = 'global' }
            continue
        }

        if ($c0 -eq '#') {
            if ($depth -eq 0 -and $header.Count -lt 40) { $header.Add($line) }
            continue
        }
    }

    foreach ($so in $sectObjs.Values) { $objects.Add($so) }

    return @{ Objects = $objects; Header = $header; VdomMode = $sawVdom }
}

# =================================================================== DUP KEYS

function Get-DupKey {
    param($O, [int]$Code)
    $t = $O.T

    switch ($Code) {
        1 {
            $ty = $t['type']
            if ($ty -eq 'iprange') {
                $s = $t['start-ip']
                if ($s) { return @('Address (range)', "$s-$($t['end-ip'])") }
            }
            elseif ($ty -eq 'fqdn') {
                $q = $t['fqdn']
                if ($q) { return @('Address (FQDN)', $q.ToLower()) }
            }
            elseif ($ty -eq 'geography') {
                $c = $t['country']
                if ($c) { return @('Address (geo)', $c) }
            }
            elseif ($ty -eq 'wildcard') {
                $w = $t['wildcard']
                if (-not $w) { $w = $t['subnet'] }
                if ($w) { return @('Address (wildcard)', ($w -replace '\s+', ' ')) }
            }
            $sub = $t['subnet']
            if (-not $sub) { $sub = $t['ip6'] }
            if ($sub) {
                $sp = $sub.IndexOf(' ')
                if ($sp -gt 0) {
                    $ip = $sub.Substring(0, $sp)
                    $mk = $sub.Substring($sp + 1).Trim()
                    return @('Address (subnet)', "$ip/$(Get-MaskBits $mk)")
                }
                if ($sub.IndexOf('/') -ge 0) { return @('Address (subnet)', $sub) }
                return @('Address (subnet)', "$sub/32")
            }
            $s2 = $t['start-ip']
            if ($s2) { return @('Address (range)', "$s2-$($t['end-ip'])") }
            return $null
        }
        2 {
            $m = Join-Sorted $t['member']
            if ($m -eq '') { return $null }
            return @('Address group', $m)
        }
        3 {
            $parts = [System.Collections.Generic.List[object]]::new()
            foreach ($k in @('protocol','protocol-number','tcp-portrange','udp-portrange','sctp-portrange','icmptype','icmpcode','iprange','fqdn')) {
                $v = $t[$k]
                if ($v) { $parts.Add("$k=$(Join-Sorted $v)") }
            }
            if ($parts.Count -eq 0) { return $null }
            return @('Service', ($parts -join '; '))
        }
        4 {
            $m = Join-Sorted $t['member']
            if ($m -eq '') { return $null }
            return @('Service group', $m)
        }
        5 {
            $ext = $t['extip']
            if (-not $ext) { return $null }
            return @('VIP', "ext=$($ext):$($t['extport']) map=$($t['mappedip']):$($t['mappedport']) proto=$($t['protocol'])")
        }
        6 {
            $s = $t['startip']
            if (-not $s) { return $null }
            return @('IP pool', "$s-$($t['endip'])")
        }
        7 {
            return @('Schedule', "day=$($t['day']) $($t['start'])-$($t['end'])")
        }
        8 {
            $d = $t['dst']
            if (-not $d) { $d = '0.0.0.0 0.0.0.0' }
            return @('Static route', "dst=$d gw=$($t['gateway']) dev=$($t['device'])")
        }
        9 {
            $ip = $t['ip']
            if (-not $ip) { return $null }
            $sp = $ip.IndexOf(' ')
            $a = $ip
            if ($sp -gt 0) { $a = $ip.Substring(0, $sp) }
            if ($a -eq '0.0.0.0') { return $null }
            return @('Interface IP', $a)
        }
        10 {
            $k = "in=$(Join-Sorted $t['srcintf'])>$(Join-Sorted $t['dstintf'])  src=$(Join-Sorted $t['srcaddr'])  dst=$(Join-Sorted $t['dstaddr'])  svc=$(Join-Sorted $t['service'])  sch=$($t['schedule'])  act=$($t['action'])"
            return @('Policy', $k)
        }
    }
    return $null
}

# =================================================================== CLEANUP AUDIT

function Invoke-Cleanup {
    param($Parsed, [bool]$CrossVdom)

    $objs = $Parsed.Objects

    # Nested index: vdom -> name -> list of objects.
    # Nested rather than a single "vdom|name" key because the reachability walk
    # does hundreds of thousands of lookups, and an interpolated key would
    # allocate a string on every one of them.
    $byV = @{}
    foreach ($o in $objs) {
        $m = $byV[$o.V]
        if ($null -eq $m) { $m = @{}; $byV[$o.V] = $m }
        $lst = $m[$o.N]
        if ($null -eq $lst) { $lst = [System.Collections.Generic.List[object]]::new(); $m[$o.N] = $lst }
        $lst.Add($o)
    }
    # A VDOM can reference an object defined in the global scope. Resolving
    # names strictly inside one VDOM makes those look unreferenced, which puts
    # a live object on the delete list. Current scope first, then global.
    $gmap = $byV['global']

    # ---------- section inventory ----------
    $cnt = @{}
    foreach ($o in $objs) {
        $id = "$($o.V)|$($o.S)"
        if ($cnt.ContainsKey($id)) { $cnt[$id] = $cnt[$id] + 1 } else { $cnt[$id] = 1 }
    }
    $sections = [System.Collections.Generic.List[object]]::new()
    foreach ($k in ($cnt.Keys | Sort-Object)) {
        $p = $k.Split('|', 2)
        $sections.Add(@($p[0], $p[1], $cnt[$k]))
    }

    # ---------- reachability, full scan ----------
    $used   = @{}
    $usedBy = @{}
    $queue  = New-Object System.Collections.Queue

    foreach ($o in $objs) {
        if ($script:WatchSet.ContainsKey($o.S)) { continue }   # candidate, not a root
        $queue.Enqueue($o)
    }

    $sep = $script:SpaceSep
    $rmEmpty = [System.StringSplitOptions]::RemoveEmptyEntries

    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        $v = $cur.V
        $vmap = $byV[$v]
        $useGlobal = ($v -ne 'global' -and $null -ne $gmap)

        foreach ($kv in $cur.T.GetEnumerator()) {
            if ($script:SkipKeys.ContainsKey($kv.Key)) { continue }
            $val = $kv.Value
            if (-not $val) { continue }

            # inlined tokenise: avoids a function call per setting value
            if ($val.IndexOf('"') -lt 0) {
                $toks = $val.Split($sep, $rmEmpty)
            } else {
                $toks = Split-Tokens $val
            }

            foreach ($tok in $toks) {
                $lst = $null
                if ($null -ne $vmap) { $lst = $vmap[$tok] }
                if ($null -eq $lst -and $useGlobal) { $lst = $gmap[$tok] }
                if ($null -eq $lst) { continue }
                foreach ($tgt in $lst) {
                    if ($tgt -eq $cur) { continue }
                    if (-not $usedBy.ContainsKey($tgt)) {
                        if ($cur.Sect) { $usedBy[$tgt] = "$($cur.S)  set $($kv.Key)" }
                        else { $usedBy[$tgt] = "$($cur.S) '$($cur.N)'  set $($kv.Key)" }
                    }
                    if (-not $used.ContainsKey($tgt)) {
                        $used[$tgt] = $true
                        $queue.Enqueue($tgt)
                    }
                }
            }
        }
    }

    # ---------- SAFE ----------
    # One row per object. An empty group that is also unreferenced must not be
    # listed twice, or the generated CLI would try to delete it twice and the
    # second attempt errors.
    $safe   = [System.Collections.Generic.List[object]]::new()
    $held   = [System.Collections.Generic.List[object]]::new()
    $onList = @{}

    foreach ($o in $objs) {
        if (-not $script:WatchSet.ContainsKey($o.S)) { continue }
        if ($used.ContainsKey($o)) { continue }

        $val = ''
        $code = $script:DupSec[$o.S]
        if ($null -ne $code) {
            $k = Get-DupKey $o $code
            if ($null -ne $k) { $val = $k[1] }
        }

        if (Test-Builtin $o.N) {
            $held.Add(@{ V = $o.V; S = $o.S; N = $o.N; Val = $val })
            continue
        }

        $kind = 'Unreferenced'
        $why  = 'Name appears nowhere else in this file'
        if ($script:GroupSet.ContainsKey($o.S) -and -not $o.T['member']) {
            $kind = 'Empty group'
            $why  = 'No members, and nothing refers to it'
            if ($val -eq '') { $val = '(no members)' }
        }

        $cm = $o.T['comment']
        if (-not $cm) { $cm = $o.T['comments'] }
        $safe.Add(@{
            Kind = $kind; V = $o.V; S = $o.S; N = $o.N; Val = $val
            Why = $why; Cm = $cm; L = $o.L; O = $o
        })
        $onList[$o] = $true
    }

    # empty groups that ARE still referenced: worth reporting, but the reason
    # differs and deleting one will fail until the reference is removed
    foreach ($o in $objs) {
        if (-not $script:GroupSet.ContainsKey($o.S)) { continue }
        if ($o.T['member']) { continue }
        if ($onList.ContainsKey($o)) { continue }
        if (Test-Builtin $o.N) { continue }
        $ub = $usedBy[$o]
        $wy = 'Group has no member, it matches nothing'
        if ($ub) { $wy = "Empty, but still referenced by $ub - remove that reference first" }
        $safe.Add(@{
            Kind = 'Empty group'; V = $o.V; S = $o.S; N = $o.N; Val = '(no members)'
            Why = $wy; Cm = $o.T['comment']; L = $o.L; O = $o
        })
        $onList[$o] = $true
    }

    foreach ($o in $objs) {
        if ($o.S -ne 'firewall policy' -and $o.S -ne 'firewall policy6') { continue }
        if ($o.T['status'] -ne 'disable') { continue }
        $safe.Add(@{
            Kind = 'Disabled policy'; V = $o.V; S = $o.S; N = $o.N; Val = $o.T['name']
            Why = 'status = disable, never evaluated'
            Cm = $o.T['comments']; L = $o.L; O = $o
        })
    }

    # ---------- DECIDE ----------
    $dupGrp = @{}
    foreach ($o in $objs) {
        $code = $script:DupSec[$o.S]
        if ($null -eq $code) { continue }
        $k = Get-DupKey $o $code
        if ($null -eq $k) { continue }
        $scope = $o.V
        if ($CrossVdom) { $scope = '*' }
        $id = "$scope|$($k[0])|$($k[1])"
        $g = $dupGrp[$id]
        if ($null -eq $g) {
            $g = @{ C = $k[0]; K = $k[1]; I = [System.Collections.Generic.List[object]]::new() }
            $dupGrp[$id] = $g
        }
        $g.I.Add($o)
    }

    # single precomputed sort key beats several script blocks per item
    $dupList = [System.Collections.Generic.List[object]]::new()
    foreach ($g in $dupGrp.Values) {
        if ($g.I.Count -le 1) { continue }
        $g.SortKey = ('{0:D6}|{1}|{2}' -f (999999 - $g.I.Count), $g.C, $g.K)
        $dupList.Add($g)
    }

    $decide = [System.Collections.Generic.List[object]]::new()
    foreach ($g in ($dupList | Sort-Object -Property SortKey)) {

        $keep = $null
        foreach ($o in $g.I) { if ($used.ContainsKey($o)) { $keep = $o; break } }
        if ($null -eq $keep) { $keep = $g.I[0] }

        $others = [System.Collections.Generic.List[object]]::new()
        $vset = @{}
        $names = [System.Collections.Generic.List[object]]::new()
        $lines = [System.Collections.Generic.List[object]]::new()
        foreach ($o in $g.I) {
            $vset[$o.V] = $true
            $lines.Add($o.L)
            if ($o -ne $keep) { $others.Add($o); $names.Add($o.N) }
        }

        $decide.Add(@{
            V = (($vset.Keys | Sort-Object) -join ',')
            C = $g.C; K = $g.K; Cnt = $g.I.Count
            Keep = $keep.N
            Drop = ($names -join ' , ')
            L = ($lines -join ',')
            Items = $g.I; KeepObj = $keep; DropObjs = $others
        })
    }

    return @{
        Sections = $sections
        Safe     = $safe
        Decide   = $decide
        Held     = $held
        UsedBy   = $usedBy
    }
}

