<#
    FortiToolkit - compliance engine and rule pack

    Rules run against the PARSED OBJECT TREE, not against the config text.
    A text rule such as

        config system admin(.|\n)*edit "remoteuser"(.|\n)*set trusthost1

    reports compliant as soon as ANY later account carries a trusthost,
    because the wildcard walks straight past 'next' into the following
    object. Matching on structure removes that whole class of false pass by
    construction: a rule that says "every object in system admin must have
    trusthost1" can only ever look at one object at a time.

    Second point: FortiOS omits settings that sit at their factory default,
    so an absent key is not the same as an unset value. Every assertion may
    declare Default, and the engine substitutes it when the key is missing.
    Text matching cannot do this at all, which is why regex packs quietly
    under-report.

    Rule shape
      Id Title Sev Cat Scope Zone Mode Where Assert Fix Why
    Mode
      each     one finding per object in Scope
      section  evaluate the section's own settings block
      exists   Scope must contain at least MinCount objects
      absent   Scope must not contain any matching object
    Condition
      Key Op Val Default
      Op: exists missing eq ne in notin has nothas startswith notstartswith
          match notmatch lte gte
#>

# =================================================================== ENGINE

function Get-Val {
    param($Obj, $Cond)
    $k = $Cond.Key
    if ($Obj.T.ContainsKey($k)) { return [string]$Obj.T[$k] }
    if ($Cond.ContainsKey('Default')) { return [string]$Cond.Default }
    return $null
}

function Test-Cond {
    param($Obj, $Cond)

    $op = $Cond.Op
    $raw = Get-Val $Obj $Cond

    if ($op -eq 'exists')  { return ($null -ne $raw -and $raw -ne '') }
    if ($op -eq 'missing') { return ($null -eq $raw -or $raw -eq '') }
    if ($null -eq $raw) { return $false }

    $v = Strip-Quotes $raw
    $want = $Cond.Val

    switch ($op) {
        'eq'  { return ($v -eq [string]$want) }
        'ne'  { return ($v -ne [string]$want) }
        'in'  {
            foreach ($w in $want) { if ($v -eq [string]$w) { return $true } }
            return $false
        }
        'notin' {
            foreach ($w in $want) { if ($v -eq [string]$w) { return $false } }
            return $true
        }
        'has' {
            foreach ($t in (Split-Tokens $raw)) {
                foreach ($w in $want) { if ($t -eq [string]$w) { return $true } }
            }
            return $false
        }
        'nothas' {
            foreach ($t in (Split-Tokens $raw)) {
                foreach ($w in $want) { if ($t -eq [string]$w) { return $false } }
            }
            return $true
        }
        'startswith'    { return $v.StartsWith([string]$want) }
        'notstartswith' { return (-not $v.StartsWith([string]$want)) }
        'match'         { return ($v -match [string]$want) }
        'notmatch'      { return (-not ($v -match [string]$want)) }
        'lte' {
            $n = 0
            if (-not [int]::TryParse($v, [ref]$n)) { return $false }
            return ($n -le [int]$want)
        }
        'gte' {
            $n = 0
            if (-not [int]::TryParse($v, [ref]$n)) { return $false }
            return ($n -ge [int]$want)
        }
    }
    return $false
}

function Test-All {
    param($Obj, $Conds)
    if ($null -eq $Conds) { return $true }
    foreach ($c in $Conds) {
        if (-not (Test-Cond $Obj $c)) { return $false }
    }
    return $true
}

function Get-FailDetail {
    param($Obj, $Conds)
    foreach ($c in $Conds) {
        if (Test-Cond $Obj $c) { continue }
        $raw = Get-Val $Obj $c
        $shown = 'not set'
        if ($null -ne $raw -and $raw -ne '') {
            $shown = $raw
            if (-not $Obj.T.ContainsKey($c.Key)) { $shown = "$raw (default)" }
        }
        $want = ''
        if ($c.ContainsKey('Val')) { $want = ($c.Val -join ', ') }
        switch ($c.Op) {
            'exists'        { return "$($c.Key) is not configured" }
            'missing'       { return "$($c.Key) is set to $shown but must not be" }
            'eq'            { return "$($c.Key) = $shown, expected $want" }
            'ne'            { return "$($c.Key) = $shown, must not be $want" }
            'in'            { return "$($c.Key) = $shown, expected one of: $want" }
            'notin'         { return "$($c.Key) = $shown, must not be any of: $want" }
            'has'           { return "$($c.Key) = $shown, must include: $want" }
            'nothas'        { return "$($c.Key) = $shown, must not include: $want" }
            'startswith'    { return "$($c.Key) = $shown, must start with $want" }
            'notstartswith' { return "$($c.Key) = $shown, must not start with $want" }
            'match'         { return "$($c.Key) = $shown, does not match the required pattern" }
            'notmatch'      { return "$($c.Key) = $shown, matches a forbidden pattern" }
            'lte'           { return "$($c.Key) = $shown, must be at most $want" }
            'gte'           { return "$($c.Key) = $shown, must be at least $want" }
        }
        return "$($c.Key) = $shown"
    }
    return ''
}

function Invoke-Compliance {
    param($Objects, $Rules, [bool]$VdomMode)

    $idx = @{}
    $zones = @{}
    foreach ($o in $Objects) {
        $zones[$o.V] = $true
        $k = "$($o.V)|$($o.S)"
        $lst = $idx[$k]
        if ($null -eq $lst) { $lst = [System.Collections.Generic.List[object]]::new(); $idx[$k] = $lst }
        $lst.Add($o)
    }

    $zoneList = @($zones.Keys | Sort-Object)
    if ($zoneList.Count -eq 0) { $zoneList = @('root') }

    $results = [System.Collections.Generic.List[object]]::new()
    $empty = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $Rules) {

        $targets = $zoneList
        if ($VdomMode) {
            if ($r.Zone -eq 'global') { $targets = @('global') }
            elseif ($r.Zone -eq 'vdom') { $targets = @($zoneList | Where-Object { $_ -ne 'global' }) }
        }

        foreach ($z in $targets) {

            $objs = $idx["$z|$($r.Scope)"]
            if ($null -eq $objs) { $objs = $empty }

            switch ($r.Mode) {

                'exists' {
                    $min = 1
                    if ($r.ContainsKey('MinCount')) { $min = $r.MinCount }
                    $hit = 0
                    foreach ($o in $objs) { if (Test-All $o $r.Where) { $hit++ } }
                    $ok = ($hit -ge $min)
                    $d = "$hit entry present"
                    if (-not $ok) { $d = "expected at least $min entry in '$($r.Scope)', found $hit" }
                    $results.Add(@{
                        Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                        Zone = $z; Obj = ''; Scope = $r.Scope; Detail = $d
                        Why = $r.Why; Fix = $r.Fix; Line = 0; Pass = $ok
                    })
                }

                'absent' {
                    $bad = [System.Collections.Generic.List[object]]::new()
                    foreach ($o in $objs) { if (Test-All $o $r.Where) { $bad.Add($o) } }
                    if ($bad.Count -eq 0) {
                        $results.Add(@{
                            Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                            Zone = $z; Obj = ''; Scope = $r.Scope; Detail = 'none present'
                            Why = $r.Why; Fix = $r.Fix; Line = 0; Pass = $true
                        })
                    }
                    foreach ($o in $bad) {
                        $results.Add(@{
                            Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                            Zone = $z; Obj = $o.N; Scope = $r.Scope
                            Detail = 'exists but should not'
                            Why = $r.Why; Fix = $r.Fix; Line = $o.L; Pass = $false
                        })
                    }
                }

                'section' {
                    $so = $null
                    foreach ($o in $objs) { if ($o.Sect) { $so = $o; break } }
                    if ($null -eq $so) {
                        $so = @{ V = $z; S = $r.Scope; N = '(settings)'; T = @{}; L = 0; Sect = $true }
                    }
                    if (-not (Test-All $so $r.Where)) {
                        $results.Add(@{
                            Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                            Zone = $z; Obj = ''; Scope = $r.Scope
                            Detail = 'precondition not met'; Why = $r.Why; Fix = $r.Fix
                            Line = 0; Pass = $true; Skip = $true
                        })
                    } else {
                        $ok = Test-All $so $r.Assert
                        $d = ''
                        if (-not $ok) { $d = Get-FailDetail $so $r.Assert }
                        $results.Add(@{
                            Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                            Zone = $z; Obj = ''; Scope = $r.Scope; Detail = $d
                            Why = $r.Why; Fix = $r.Fix; Line = $so.L; Pass = $ok
                        })
                    }
                }

                default {   # each
                    $seen = 0
                    foreach ($o in $objs) {
                        if ($o.Sect) { continue }
                        if (-not (Test-All $o $r.Where)) { continue }
                        $seen++
                        $ok = Test-All $o $r.Assert
                        $d = ''
                        if (-not $ok) { $d = Get-FailDetail $o $r.Assert }
                        $results.Add(@{
                            Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                            Zone = $z; Obj = $o.N; Scope = $r.Scope; Detail = $d
                            Why = $r.Why; Fix = $r.Fix; Line = $o.L; Pass = $ok
                        })
                    }
                    if ($seen -eq 0) {
                        $results.Add(@{
                            Id = $r.Id; Sev = $r.Sev; Cat = $r.Cat; Title = $r.Title
                            Zone = $z; Obj = ''; Scope = $r.Scope
                            Detail = 'no matching object in this zone'
                            Why = $r.Why; Fix = $r.Fix; Line = 0; Pass = $true; Skip = $true
                        })
                    }
                }
            }
        }
    }
    return $results
}

# =================================================================== RULE PACK

function C {
    param([string]$Key, [string]$Op, $Val, $Default)
    $h = @{ Key = $Key; Op = $Op }
    if ($PSBoundParameters.ContainsKey('Val')) { $h.Val = $Val }
    if ($PSBoundParameters.ContainsKey('Default')) { $h.Default = $Default }
    return $h
}

$script:Pack = @(

    # ---------------- administrative access ----------------
    @{ Id='ADM-01'; Sev='critical'; Cat='Administrative access'; Zone='global'
       Title='Every admin account restricts logins to trusted hosts'
       Scope='system admin'; Mode='each'
       Assert=@( (C 'trusthost1' 'exists'), (C 'trusthost1' 'notstartswith' '0.0.0.0') )
       Fix=@('set trusthost1 10.0.0.0 255.255.255.0')
       Why='Without a trusted host an admin account can be attacked from any reachable network, and 0.0.0.0/0 counts as unrestricted. Checked per account: a trusted host on one account does not protect the others. A regex that anchors on one account and then searches forward will pass as soon as any later account has the setting.' }

    @{ Id='ADM-02'; Sev='high'; Cat='Administrative access'; Zone='global'
       Title='Super admin accounts use two-factor authentication'
       Scope='system admin'; Mode='each'
       Where=@( (C 'accprofile' 'eq' 'super_admin') )
       Assert=@( (C 'two-factor' 'ne' 'disable' 'disable') )
       Fix=@('set two-factor fortitoken','# set fortitoken <serial>')
       Why='A stolen password alone should not grant full device control.' }

    @{ Id='ADM-03'; Sev='medium'; Cat='Administrative access'; Zone='global'
       Title='Idle admin sessions time out within 10 minutes'
       Scope='system global'; Mode='section'
       Assert=@( (C 'admintimeout' 'lte' 10 '5') )
       Fix=@('set admintimeout 5')
       Why='An unattended session left open is an unauthenticated console. FortiOS omits this key when it equals the factory default of 5, so an absent key is compliant here.' }

    @{ Id='ADM-04'; Sev='high'; Cat='Administrative access'; Zone='global'
       Title='Admin lockout is enforced after repeated failures'
       Scope='system global'; Mode='section'
       Assert=@( (C 'admin-lockout-threshold' 'lte' 5 '3'), (C 'admin-lockout-duration' 'gte' 60 '60') )
       Fix=@('set admin-lockout-threshold 3','set admin-lockout-duration 60')
       Why='Slows password guessing against the management interface.' }

    @{ Id='ADM-05'; Sev='medium'; Cat='Administrative access'; Zone='global'
       Title='Management uses a non-default HTTPS port'
       Scope='system global'; Mode='section'
       Assert=@( (C 'admin-sport' 'ne' '443' '443') )
       Fix=@('set admin-sport 8443')
       Why='Reduces noise from untargeted scanning. Low value alone, useful alongside trusted hosts.' }

    @{ Id='ADM-06'; Sev='critical'; Cat='Administrative access'; Zone='global'
       Title='Plain HTTP administration redirects to HTTPS'
       Scope='system global'; Mode='section'
       Assert=@( (C 'admin-https-redirect' 'ne' 'disable' 'enable') )
       Fix=@('set admin-https-redirect enable')
       Why='Credentials sent over HTTP are recoverable from a packet capture.' }

    # ---------------- password policy ----------------
    @{ Id='PWD-01'; Sev='high'; Cat='Password policy'; Zone='global'
       Title='A password policy is enforced'
       Scope='system password-policy'; Mode='section'
       Assert=@( (C 'status' 'eq' 'enable' 'disable') )
       Fix=@('set status enable','set minimum-length 12','set min-lower-case-letter 1',
             'set min-upper-case-letter 1','set min-number 1','set min-non-alphanumeric 1')
       Why='Without a policy the device accepts any password an admin chooses.' }

    @{ Id='PWD-02'; Sev='medium'; Cat='Password policy'; Zone='global'
       Title='Minimum password length is at least 12'
       Scope='system password-policy'; Mode='section'
       Where=@( (C 'status' 'eq' 'enable') )
       Assert=@( (C 'minimum-length' 'gte' 12 '8') )
       Fix=@('set minimum-length 12')
       Why='Short passwords fall to offline cracking quickly.' }

    # ---------------- exposed services ----------------
    @{ Id='IFC-01'; Sev='critical'; Cat='Exposed services'; Zone='any'
       Title='Telnet is not permitted on any interface'
       Scope='system interface'; Mode='each'
       Where=@( (C 'allowaccess' 'exists') )
       Assert=@( (C 'allowaccess' 'nothas' @('telnet')) )
       Fix=@('# re-issue allowaccess without telnet, e.g.','# set allowaccess ping https ssh')
       Why='Telnet carries credentials in clear text.' }

    @{ Id='IFC-02'; Sev='high'; Cat='Exposed services'; Zone='any'
       Title='Plain HTTP management is not permitted on any interface'
       Scope='system interface'; Mode='each'
       Where=@( (C 'allowaccess' 'exists') )
       Assert=@( (C 'allowaccess' 'nothas' @('http')) )
       Fix=@('# re-issue allowaccess without http, e.g.','# set allowaccess ping https ssh')
       Why='Same exposure as telnet, for the web interface.' }

    @{ Id='IFC-03'; Sev='high'; Cat='Exposed services'; Zone='any'
       Title='Management is not reachable from a WAN interface'
       Scope='system interface'; Mode='each'
       Where=@( (C 'role' 'eq' 'wan'), (C 'allowaccess' 'exists') )
       Assert=@( (C 'allowaccess' 'nothas' @('http','https','ssh','telnet')) )
       Fix=@('# remove management protocols from the WAN side, e.g.','# set allowaccess ping')
       Why='Management exposed to the internet is the most common entry point. Only interfaces explicitly tagged role=wan are evaluated, so an untagged internet link will not be caught here.' }

    @{ Id='IFC-04'; Sev='medium'; Cat='Exposed services'; Zone='any'
       Title='Speed-test is not left open on an interface'
       Scope='system interface'; Mode='each'
       Where=@( (C 'allowaccess' 'exists') )
       Assert=@( (C 'allowaccess' 'nothas' @('speed-test')) )
       Fix=@('# re-issue allowaccess without speed-test')
       Why='Unauthenticated services should not sit on production interfaces.' }

    # ---------------- SNMP ----------------
    @{ Id='SNM-01'; Sev='critical'; Cat='SNMP'; Zone='any'
       Title='No default SNMP community strings'
       Scope='system snmp community'; Mode='each'
       Assert=@( (C 'name' 'notin' @('public','private','Public','Private')) )
       Fix=@('# rename the community to a non-guessable value','# set name <unique-string>')
       Why='public and private are the first two strings any scanner tries.' }

    @{ Id='SNM-02'; Sev='high'; Cat='SNMP'; Zone='any'
       Title='SNMPv1 and v2c are not enabled'
       Scope='system snmp community'; Mode='each'
       Assert=@( (C 'status' 'eq' 'disable' 'enable') )
       Fix=@('# migrate to SNMPv3 under config system snmp user','# set status disable')
       Why='v1 and v2c send the community string in clear text and have no integrity protection.' }

    # ---------------- logging ----------------
    @{ Id='LOG-01'; Sev='high'; Cat='Logging'; Zone='any'
       Title='Logs are shipped off the device'
       Scope='log fortianalyzer setting'; Mode='section'
       Assert=@( (C 'status' 'eq' 'enable' 'disable') )
       Fix=@('set status enable','# set server <fortianalyzer-ip>')
       Why='Local storage is small and is lost with the device. Without off-box logging there is no incident timeline.' }

    @{ Id='LOG-02'; Sev='medium'; Cat='Logging'; Zone='any'
       Title='Accepted traffic is logged'
       Scope='firewall policy'; Mode='each'
       Where=@( (C 'action' 'eq' 'accept'), (C 'status' 'ne' 'disable' 'enable') )
       Assert=@( (C 'logtraffic' 'in' @('all','utm') 'utm') )
       Fix=@('set logtraffic all')
       Why='A permit rule that logs nothing cannot be audited or investigated.' }

    @{ Id='LOG-03'; Sev='medium'; Cat='Logging'; Zone='any'
       Title='Implicit deny traffic is logged'
       Scope='log setting'; Mode='section'
       Assert=@( (C 'fwpolicy-implicit-log' 'eq' 'enable' 'disable') )
       Fix=@('set fwpolicy-implicit-log enable')
       Why='Blocked traffic is the earliest signal of scanning or misconfiguration.' }

    # ---------------- firewall policy ----------------
    @{ Id='POL-01'; Sev='critical'; Cat='Firewall policy'; Zone='any'
       Title='No policy accepts any source to any destination on all services'
       Scope='firewall policy'; Mode='each'
       Where=@( (C 'action' 'eq' 'accept'), (C 'status' 'ne' 'disable' 'enable'),
                (C 'srcaddr' 'has' @('all')), (C 'dstaddr' 'has' @('all')) )
       Assert=@( (C 'service' 'nothas' @('ALL')) )
       Fix=@('# replace ALL with the services actually required, e.g.','# set service "HTTPS" "DNS"')
       Why='An any-any-all permit makes every rule below it decorative.' }

    @{ Id='POL-02'; Sev='medium'; Cat='Firewall policy'; Zone='any'
       Title='Policies are bound to specific interfaces'
       Scope='firewall policy'; Mode='each'
       Where=@( (C 'action' 'eq' 'accept'), (C 'status' 'ne' 'disable' 'enable') )
       Assert=@( (C 'srcintf' 'nothas' @('any')), (C 'dstintf' 'nothas' @('any')) )
       Fix=@('# bind to real interfaces, e.g.','# set srcintf "internal"','# set dstintf "wan1"')
       Why='Interface any widens a rule far beyond its intent and defeats segmentation.' }

    @{ Id='POL-03'; Sev='low'; Cat='Firewall policy'; Zone='any'
       Title='Policies carry a name'
       Scope='firewall policy'; Mode='each'
       Assert=@( (C 'name' 'exists') )
       Fix=@('# set name "<purpose>"')
       Why='Unnamed rules are the ones nobody dares remove years later.' }

    @{ Id='POL-04'; Sev='medium'; Cat='Firewall policy'; Zone='any'
       Title='Outbound NAT rules apply a security profile'
       Scope='firewall policy'; Mode='each'
       Where=@( (C 'action' 'eq' 'accept'), (C 'status' 'ne' 'disable' 'enable'),
                (C 'nat' 'eq' 'enable') )
       Assert=@( (C 'utm-status' 'eq' 'enable' 'disable') )
       Fix=@('set utm-status enable','# set av-profile "default"','# set ips-sensor "default"')
       Why='Outbound NAT rules are the usual malware egress path.' }

    # ---------------- VPN ----------------
    @{ Id='VPN-01'; Sev='high'; Cat='VPN'; Zone='any'
       Title='SSL VPN does not accept obsolete TLS versions'
       Scope='vpn ssl settings'; Mode='section'
       Where=@( (C 'status' 'eq' 'enable') )
       Assert=@( (C 'ssl-min-proto-ver' 'in' @('tls1-2','tls1-3') 'tls1-2') )
       Fix=@('set ssl-min-proto-ver tls1-2')
       Why='TLS 1.0 and 1.1 are withdrawn and fail most audits outright.' }

    @{ Id='VPN-02'; Sev='medium'; Cat='VPN'; Zone='any'
       Title='SSL VPN sessions have an idle timeout'
       Scope='vpn ssl settings'; Mode='section'
       Where=@( (C 'status' 'eq' 'enable') )
       Assert=@( (C 'idle-timeout' 'gte' 1 '300'), (C 'idle-timeout' 'lte' 3600 '300') )
       Fix=@('set idle-timeout 300')
       Why='Abandoned tunnels stay authenticated without a timeout. A value of 0 disables it entirely.' }

    @{ Id='VPN-03'; Sev='high'; Cat='VPN'; Zone='any'
       Title='SSL VPN listens on a restricted source range'
       Scope='vpn ssl settings'; Mode='section'
       Where=@( (C 'status' 'eq' 'enable') )
       Assert=@( (C 'source-address' 'exists') )
       Fix=@('# set source-address "<geo-or-corp-range>"')
       Why='Limiting who can reach the portal at all removes most credential stuffing.' }

    @{ Id='VPN-04'; Sev='high'; Cat='VPN'; Zone='any'
       Title='IPsec phase 1 avoids broken ciphers'
       Scope='vpn ipsec phase1-interface'; Mode='each'
       Assert=@( (C 'proposal' 'notmatch' 'des-|-md5|-sha1$|3des') )
       Fix=@('set proposal aes256-sha256 aes128-sha256')
       Why='DES and MD5 are broken. 3DES and SHA1 are deprecated.' }

    @{ Id='VPN-05'; Sev='medium'; Cat='VPN'; Zone='any'
       Title='IPsec phase 1 uses a modern DH group'
       Scope='vpn ipsec phase1-interface'; Mode='each'
       Assert=@( (C 'dhgrp' 'nothas' @('1','2','5')) )
       Fix=@('set dhgrp 14 15')
       Why='Groups 1, 2 and 5 are within reach of well-funded attackers.' }

    # ---------------- system hygiene ----------------
    @{ Id='SYS-01'; Sev='medium'; Cat='System hygiene'; Zone='global'
       Title='NTP is enabled'
       Scope='system ntp'; Mode='section'
       Assert=@( (C 'ntpsync' 'eq' 'enable' 'enable') )
       Fix=@('set ntpsync enable','set type custom','# configure your own NTP servers')
       Why='Log correlation and certificate validation both depend on correct time.' }

    @{ Id='SYS-02'; Sev='low'; Cat='System hygiene'; Zone='global'
       Title='A device hostname is set'
       Scope='system global'; Mode='section'
       Assert=@( (C 'hostname' 'exists'), (C 'hostname' 'notin' @('FortiGate','fortigate')) )
       Fix=@('# set hostname "<site-role-nn>"')
       Why='A default hostname makes logs from a fleet indistinguishable.' }

    @{ Id='SYS-03'; Sev='medium'; Cat='System hygiene'; Zone='global'
       Title='A pre-login banner is displayed'
       Scope='system global'; Mode='section'
       Assert=@( (C 'pre-login-banner' 'eq' 'enable' 'disable') )
       Fix=@('set pre-login-banner enable')
       Why='Many jurisdictions require notice before access for prosecution.' }

    @{ Id='SYS-04'; Sev='high'; Cat='System hygiene'; Zone='global'
       Title='Strong cryptography is enforced for management'
       Scope='system global'; Mode='section'
       Assert=@( (C 'strong-crypto' 'eq' 'enable' 'disable') )
       Fix=@('set strong-crypto enable')
       Why='Disables weak ciphers across HTTPS, SSH and the TLS clients on the device.' }

    @{ Id='SYS-05'; Sev='medium'; Cat='System hygiene'; Zone='global'
       Title='USB firmware and config auto-install is disabled'
       Scope='system auto-install'; Mode='section'
       Assert=@( (C 'auto-install-config' 'ne' 'enable' 'disable'),
                 (C 'auto-install-image' 'ne' 'enable' 'disable') )
       Fix=@('set auto-install-config disable','set auto-install-image disable')
       Why='Physical access should not be enough to replace the configuration.' }

    @{ Id='SYS-06'; Sev='medium'; Cat='System hygiene'; Zone='global'
       Title='Maintainer account access is disabled'
       Scope='system global'; Mode='section'
       Assert=@( (C 'admin-maintainer' 'ne' 'enable' 'enable') )
       Fix=@('set admin-maintainer disable')
       Why='The maintainer account allows console password recovery with physical access. Disable only where physical security is weaker than the risk of losing access.' }

    @{ Id='DNS-01'; Sev='low'; Cat='System hygiene'; Zone='any'
       Title='DNS servers are configured'
       Scope='system dns'; Mode='section'
       Assert=@( (C 'primary' 'exists') )
       Fix=@('# set primary <dns-ip>','# set secondary <dns-ip>')
       Why='FQDN address objects and FortiGuard both depend on name resolution.' }
)

