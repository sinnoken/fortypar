<#
    FortiToolkit - Network view add-on

    A FortiGate config is a network design, not just an audit target. The
    parser already extracts interfaces, routes, VPNs and policy interface
    pairs; this file gives that data a shape that matches it:

        interfaces   tree     physical -> vlan children, aggregate -> members
        routing      grid     flat and sortable
        vpn          tree     phase1 -> phase2 children
        traffic      matrix   srcintf x dstintf, shaded by policy count
        services     grid     dhcp, dns, ntp, ha, snmp

    INSTALL
      Put this file next to FortiToolkit.ps1 and add ONE line to the main
      script, immediately before  $form.Add_Shown({ :

          . "$PSScriptRoot\FortiNetworkTab.ps1"

      Nothing else changes. The tab is appended last so existing TabPages
      indices stay valid, and it fills itself lazily the first time you
      open it, so Load-File does not need touching.

    Requires the main script's helpers: Strip-Quotes, Split-Tokens,
    Get-MaskBits, and the variables $tabs, $tree, $fntMono, $script:Audit.
#>

$script:NetLast     = $null
$script:NetLastZone = '~'

# =================================================================== MODEL

function Get-NetCidr {
    param([string]$Raw)
    if (-not $Raw) { return '' }
    $v = Strip-Quotes $Raw
    $sp = $v.IndexOf(' ')
    if ($sp -lt 0) { return $v }
    $ip = $v.Substring(0, $sp)
    $mk = $v.Substring($sp + 1).Trim()
    if ($ip -eq '0.0.0.0' -and ($mk -eq '0.0.0.0' -or $mk -eq '')) { return '0.0.0.0/0' }
    return "$ip/$(Get-MaskBits $mk)"
}

function Get-NetModel {
    param($Objects)

    $ifaces = [System.Collections.Generic.List[object]]::new()
    $routes = [System.Collections.Generic.List[object]]::new()
    $ph1    = [System.Collections.Generic.List[object]]::new()
    $ph2    = [System.Collections.Generic.List[object]]::new()
    $svcs   = [System.Collections.Generic.List[object]]::new()
    $zoneOf = @{}
    $polPair = @{}
    $vdomPol = @{}

    foreach ($o in $Objects) {

        # ---------- zones ----------
        if ($o.S -eq 'system zone' -and -not $o.Sect) {
            foreach ($m in (Split-Tokens $o.T['interface'])) {
                $zoneOf["$($o.V)|$m"] = $o.N
            }
            continue
        }

        # ---------- interfaces ----------
        if ($o.S -eq 'system interface' -and -not $o.Sect) {
            $t = $o.T
            $addr = ''
            $mode = Strip-Quotes ([string]$t['mode'])
            if ($mode -eq 'dhcp' -or $mode -eq 'pppoe') {
                $addr = "($mode)"
            } else {
                $addr = Get-NetCidr ([string]$t['ip'])
                if ($addr -eq '0.0.0.0/0' -or $addr -eq '0.0.0.0/32') { $addr = '' }
            }
            $ifaces.Add(@{
                V      = $o.V
                N      = $o.N
                Type   = Strip-Quotes ([string]$t['type'])
                Addr   = $addr
                Parent = Strip-Quotes ([string]$t['interface'])
                Vlan   = Strip-Quotes ([string]$t['vlanid'])
                Role   = Strip-Quotes ([string]$t['role'])
                Access = Strip-Quotes ([string]$t['allowaccess'])
                Status = Strip-Quotes ([string]$t['status'])
                Alias  = Strip-Quotes ([string]$t['alias'])
                Desc   = Strip-Quotes ([string]$t['description'])
                Member = Split-Tokens ([string]$t['member'])
                Mtu    = Strip-Quotes ([string]$t['mtu'])
                L      = $o.L
            })
            continue
        }

        # ---------- static routes ----------
        if (($o.S -eq 'router static' -or $o.S -eq 'router static6') -and -not $o.Sect) {
            $t = $o.T
            $dst = Get-NetCidr ([string]$t['dst'])
            if (-not $dst) {
                $named = Strip-Quotes ([string]$t['dstaddr'])
                if ($named) { $dst = $named } else { $dst = '0.0.0.0/0' }
            }
            $gw = Strip-Quotes ([string]$t['gateway'])
            if (Strip-Quotes ([string]$t['blackhole']) -eq 'enable') { $gw = '(blackhole)' }
            $d = Strip-Quotes ([string]$t['distance'])
            if (-not $d) { $d = '10' }
            $st = Strip-Quotes ([string]$t['status'])
            if (-not $st) { $st = 'enable' }
            $routes.Add(@{
                V = $o.V; Seq = $o.N; Dst = $dst; Gw = $gw
                Dev = Strip-Quotes ([string]$t['device'])
                Dist = $d
                Pri = Strip-Quotes ([string]$t['priority'])
                Status = $st
                Cmt = Strip-Quotes ([string]$t['comment'])
                L = $o.L
            })
            continue
        }

        # ---------- ipsec ----------
        if (($o.S -eq 'vpn ipsec phase1-interface' -or $o.S -eq 'vpn ipsec phase1') -and -not $o.Sect) {
            $t = $o.T
            $ph1.Add(@{
                V = $o.V; N = $o.N
                Peer = Strip-Quotes ([string]$t['remote-gw'])
                Intf = Strip-Quotes ([string]$t['interface'])
                Prop = Strip-Quotes ([string]$t['proposal'])
                Dh   = Strip-Quotes ([string]$t['dhgrp'])
                Ike  = Strip-Quotes ([string]$t['ike-version'])
                Type = Strip-Quotes ([string]$t['type'])
                Peert= Strip-Quotes ([string]$t['peertype'])
                L = $o.L
            })
            continue
        }
        if (($o.S -eq 'vpn ipsec phase2-interface' -or $o.S -eq 'vpn ipsec phase2') -and -not $o.Sect) {
            $t = $o.T
            $ph2.Add(@{
                V = $o.V; N = $o.N
                P1  = Strip-Quotes ([string]$t['phase1name'])
                Src = Get-NetCidr ([string]$t['src-subnet'])
                Dst = Get-NetCidr ([string]$t['dst-subnet'])
                Prop= Strip-Quotes ([string]$t['proposal'])
                L = $o.L
            })
            continue
        }

        # ---------- policy interface pairs ----------
        if (($o.S -eq 'firewall policy' -or $o.S -eq 'firewall policy6') -and -not $o.Sect) {
            $act = Strip-Quotes ([string]$o.T['action'])
            if (-not $act) { $act = 'deny' }
            $off = (Strip-Quotes ([string]$o.T['status'])) -eq 'disable'
            foreach ($si in (Split-Tokens ([string]$o.T['srcintf']))) {
                foreach ($di in (Split-Tokens ([string]$o.T['dstintf']))) {
                    $k = "$($o.V)|$si|$di"
                    $c = $polPair[$k]
                    if ($c -eq $null) {
                        $c = @{ V = $o.V; Src = $si; Dst = $di; N = 0; Acc = 0; Den = 0; Off = 0 }
                        $polPair[$k] = $c
                    }
                    $c.N = $c.N + 1
                    if ($off) { $c.Off = $c.Off + 1 }
                    elseif ($act -eq 'accept') { $c.Acc = $c.Acc + 1 }
                    else { $c.Den = $c.Den + 1 }
                }
            }
            if ($vdomPol.ContainsKey($o.V)) { $vdomPol[$o.V] = $vdomPol[$o.V] + 1 }
            else { $vdomPol[$o.V] = 1 }
            continue
        }

        # ---------- services ----------
        if ($o.S -eq 'system dhcp server' -and -not $o.Sect) {
            $t = $o.T
            $svcs.Add(@{
                V = $o.V; Kind = 'DHCP server'; Name = "id $($o.N)"
                Detail = "interface $(Strip-Quotes ([string]$t['interface']))  gw $(Strip-Quotes ([string]$t['default-gateway']))  mask $(Strip-Quotes ([string]$t['netmask']))  dns $(Strip-Quotes ([string]$t['dns-server1']))"
                L = $o.L
            })
            continue
        }
        if ($o.S -eq 'system dns' -and $o.Sect) {
            $svcs.Add(@{
                V = $o.V; Kind = 'DNS'; Name = ''
                Detail = "primary $(Strip-Quotes ([string]$o.T['primary']))  secondary $(Strip-Quotes ([string]$o.T['secondary']))"
                L = $o.L
            })
            continue
        }
        if ($o.S -eq 'system ntp' -and $o.Sect) {
            $svcs.Add(@{
                V = $o.V; Kind = 'NTP'; Name = ''
                Detail = "sync $(Strip-Quotes ([string]$o.T['ntpsync']))  type $(Strip-Quotes ([string]$o.T['type']))  server-mode $(Strip-Quotes ([string]$o.T['server-mode']))"
                L = $o.L
            })
            continue
        }
        if ($o.S -eq 'system ha' -and $o.Sect) {
            $svcs.Add(@{
                V = $o.V; Kind = 'HA'; Name = Strip-Quotes ([string]$o.T['group-name'])
                Detail = "mode $(Strip-Quotes ([string]$o.T['mode']))  priority $(Strip-Quotes ([string]$o.T['priority']))  hbdev $(Strip-Quotes ([string]$o.T['hbdev']))  override $(Strip-Quotes ([string]$o.T['override']))"
                L = $o.L
            })
            continue
        }
        if ($o.S -eq 'vpn ssl settings' -and $o.Sect) {
            $svcs.Add(@{
                V = $o.V; Kind = 'SSL VPN'; Name = ''
                Detail = "status $(Strip-Quotes ([string]$o.T['status']))  port $(Strip-Quotes ([string]$o.T['port']))  interface $(Strip-Quotes ([string]$o.T['source-interface']))  pool $(Strip-Quotes ([string]$o.T['tunnel-ip-pools']))  min-tls $(Strip-Quotes ([string]$o.T['ssl-min-proto-ver']))"
                L = $o.L
            })
            continue
        }
        if ($o.S -eq 'system sdwan' -and $o.Sect) {
            $svcs.Add(@{
                V = $o.V; Kind = 'SD-WAN'; Name = ''
                Detail = "status $(Strip-Quotes ([string]$o.T['status']))  load-balance $(Strip-Quotes ([string]$o.T['load-balance-mode']))"
                L = $o.L
            })
            continue
        }
        if ($o.S -eq 'system snmp sysinfo' -and $o.Sect) {
            $svcs.Add(@{
                V = $o.V; Kind = 'SNMP'; Name = ''
                Detail = "status $(Strip-Quotes ([string]$o.T['status']))  contact $(Strip-Quotes ([string]$o.T['contact-info']))"
                L = $o.L
            })
            continue
        }
    }

    # attach zone labels
    foreach ($i in $ifaces) {
        $z = $zoneOf["$($i.V)|$($i.N)"]
        if ($z) { $i.Zone = $z } else { $i.Zone = '' }
    }

    return @{
        Ifaces = $ifaces
        Routes = $routes
        Ph1    = $ph1
        Ph2    = $ph2
        Svcs   = $svcs
        Pairs  = $polPair
        VdomPol= $vdomPol
    }
}

# =================================================================== UI

$tabNet = New-Object System.Windows.Forms.TabPage
$tabNet.Text = 'Network'

$netInner = New-Object System.Windows.Forms.TabControl
$netInner.Dock = 'Fill'
$tabNet.Controls.Add($netInner)
[void]$tabs.TabPages.Add($tabNet)

function New-NetPage {
    param([string]$Title, [string]$Hint)
    $tp = New-Object System.Windows.Forms.TabPage
    $tp.Text = $Title
    if ($Hint) {
        $lb = New-Object System.Windows.Forms.Label
        $lb.Text = $Hint
        $lb.Dock = 'Top'
        $lb.Height = 26
        $lb.TextAlign = 'MiddleLeft'
        $lb.BackColor = [System.Drawing.Color]::FromArgb(246, 247, 250)
        $lb.ForeColor = [System.Drawing.Color]::FromArgb(85, 88, 95)
        $lb.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)
        $tp.Tag = $lb
    }
    [void]$netInner.TabPages.Add($tp)
    return $tp
}

function New-NetGrid {
    param($Page, [string[]]$Cols, [int[]]$W)
    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.ReadOnly = $true
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.AutoSizeColumnsMode = 'None'
    $g.RowHeadersVisible = $false
    $g.BorderStyle = 'None'
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(247, 247, 250)
    $g.EnableHeadersVisualStyles = $false
    $g.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(238, 238, 242)
    $g.ColumnHeadersHeightSizeMode = 'DisableResizing'

    $Page.Controls.Add($g)
    if ($Page.Tag) { $Page.Controls.Add($Page.Tag) }

    $dt = New-Object System.Data.DataTable
    foreach ($c in $Cols) { [void]$dt.Columns.Add($c) }
    $g.DataSource = $dt
    for ($i = 0; $i -lt $g.Columns.Count -and $i -lt $W.Length; $i++) {
        $g.Columns[$i].Width = $W[$i]
    }
    return @{ G = $g; T = $dt; W = $W }
}

# ---------- interfaces: tree ----------
$pgIf = New-NetPage 'Interfaces' 'Physical ports expand into their VLAN sub-interfaces; aggregates expand into members. Zone membership is shown in brackets.'
$treeIf = New-Object System.Windows.Forms.TreeView
$treeIf.Dock = 'Fill'
$treeIf.Font = $fntMono
$treeIf.ItemHeight = 20
$treeIf.HideSelection = $false
$treeIf.BorderStyle = 'None'
$pgIf.Controls.Add($treeIf)
if ($pgIf.Tag) { $pgIf.Controls.Add($pgIf.Tag) }

# ---------- routing ----------
$pgRt = New-NetPage 'Routing' 'Static routes only. Dynamic protocols are not resolved from a config file.'
$gridRt = New-NetGrid $pgRt @('Zone','Seq','Destination','Gateway','Device','Dist','Pri','Status','Comment') @(90,50,150,130,110,50,45,65,240)

# ---------- vpn ----------
$pgVpn = New-NetPage 'VPN' 'IPsec phase 1 tunnels with their phase 2 selectors underneath.'
$treeVpn = New-Object System.Windows.Forms.TreeView
$treeVpn.Dock = 'Fill'
$treeVpn.Font = $fntMono
$treeVpn.ItemHeight = 20
$treeVpn.HideSelection = $false
$treeVpn.BorderStyle = 'None'
$pgVpn.Controls.Add($treeVpn)
if ($pgVpn.Tag) { $pgVpn.Controls.Add($pgVpn.Tag) }

# ---------- traffic matrix ----------
$pgMx = New-NetPage 'Traffic design' 'Policy count per source/destination interface pair. Blank means no policy allows that direction at all.'
$gridMx = New-Object System.Windows.Forms.DataGridView
$gridMx.Dock = 'Fill'
$gridMx.ReadOnly = $true
$gridMx.AllowUserToAddRows = $false
$gridMx.AllowUserToResizeRows = $false
$gridMx.RowHeadersVisible = $false
$gridMx.BorderStyle = 'None'
$gridMx.BackgroundColor = [System.Drawing.Color]::White
$gridMx.EnableHeadersVisualStyles = $false
$gridMx.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(238, 238, 242)
$gridMx.SelectionMode = 'CellSelect'
$pgMx.Controls.Add($gridMx)
if ($pgMx.Tag) { $pgMx.Controls.Add($pgMx.Tag) }

$gridMx.Add_CellFormatting({
    param($s, $e)
    if ($e.ColumnIndex -eq 0) {
        $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(244, 245, 248)
        $e.CellStyle.Font = New-Object System.Drawing.Font($s.Font, [System.Drawing.FontStyle]::Bold)
        return
    }
    $v = [string]$e.Value
    if (-not $v) { return }
    $n = 0
    if (-not [int]::TryParse($v, [ref]$n)) { return }
    if ($n -ge 100)     { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(196, 216, 244) }
    elseif ($n -ge 25)  { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(219, 232, 249) }
    elseif ($n -ge 5)   { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(235, 242, 252) }
    else                { $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb(247, 250, 254) }
})

# ---------- services ----------
$pgSv = New-NetPage 'Services' 'Device services parsed from the config.'
$gridSv = New-NetGrid $pgSv @('Zone','Service','Name','Detail') @(90,110,140,700)

# =================================================================== FILL

function Fill-NetIfaces {
    param($M, [string]$Zone)

    $treeIf.BeginUpdate()
    $treeIf.Nodes.Clear()

    $byV = @{}
    foreach ($i in $M.Ifaces) {
        if ($Zone -ne '*' -and $i.V -ne $Zone) { continue }
        $lst = $byV[$i.V]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byV[$i.V] = $lst }
        $lst.Add($i)
    }

    foreach ($v in ($byV.Keys | Sort-Object)) {
        $vn = New-Object System.Windows.Forms.TreeNode
        $vn.Text = "$v   ($($byV[$v].Count) interfaces)"
        $vn.NodeFont = New-Object System.Drawing.Font($treeIf.Font, [System.Drawing.FontStyle]::Bold)
        [void]$treeIf.Nodes.Add($vn)

        # index children by parent and by aggregate membership
        $childOf = @{}
        $isChild = @{}
        foreach ($i in $byV[$v]) {
            if ($i.Parent -and $i.Parent -ne $i.N) {
                $lst = $childOf[$i.Parent]
                if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $childOf[$i.Parent] = $lst }
                $lst.Add($i)
                $isChild[$i.N] = $true
            }
        }
        $memberOf = @{}
        foreach ($i in $byV[$v]) {
            foreach ($m in $i.Member) {
                $memberOf[$m] = $i.N
                $isChild[$m] = $true
            }
        }

        $byName = @{}
        foreach ($i in $byV[$v]) { $byName[$i.N] = $i }

        foreach ($i in ($byV[$v] | Sort-Object @{e = { $_.N }})) {
            if ($isChild.ContainsKey($i.N)) { continue }
            $n = New-Object System.Windows.Forms.TreeNode
            $n.Text = (Format-IfaceLine $i)
            if ($i.Status -eq 'down') { $n.ForeColor = [System.Drawing.Color]::FromArgb(160, 162, 168) }
            [void]$vn.Nodes.Add($n)

            # vlan sub-interfaces
            $kids = $childOf[$i.N]
            if ($kids -ne $null) {
                foreach ($k in ($kids | Sort-Object @{e = { [int]$_.Vlan }}, @{e = { $_.N }})) {
                    $cn = New-Object System.Windows.Forms.TreeNode
                    $cn.Text = (Format-IfaceLine $k)
                    if ($k.Status -eq 'down') { $cn.ForeColor = [System.Drawing.Color]::FromArgb(160, 162, 168) }
                    [void]$n.Nodes.Add($cn)
                }
            }
            # aggregate members
            foreach ($m in $i.Member) {
                $mi = $byName[$m]
                $cn = New-Object System.Windows.Forms.TreeNode
                if ($mi) { $cn.Text = (Format-IfaceLine $mi) + '   [member]' }
                else { $cn.Text = ("{0,-16} [member]" -f $m) }
                $cn.ForeColor = [System.Drawing.Color]::FromArgb(120, 124, 132)
                [void]$n.Nodes.Add($cn)
            }
        }
        $vn.Expand()
    }
    $treeIf.EndUpdate()
}

function Format-IfaceLine {
    param($I)
    $addr = $I.Addr
    if (-not $addr) { $addr = '-' }
    $extra = ''
    if ($I.Vlan) { $extra = $extra + " vlan $($I.Vlan)" }
    if ($I.Zone) { $extra = $extra + " [zone $($I.Zone)]" }
    if ($I.Role) { $extra = $extra + " $($I.Role)" }
    if ($I.Access) { $extra = $extra + "  access: $($I.Access)" }
    if ($I.Alias) { $extra = $extra + "  ($($I.Alias))" }
    return ("{0,-18} {1,-22} {2,-11}{3}" -f $I.N, $addr, $I.Type, $extra)
}

function Fill-NetGridRows {
    param($GH, $Rows)
    $GH.G.DataSource = $null
    $GH.T.Clear()
    $GH.T.BeginLoadData()
    foreach ($r in $Rows) { [void]$GH.T.LoadDataRow($r, $true) }
    $GH.T.EndLoadData()
    $GH.G.DataSource = $GH.T
    for ($i = 0; $i -lt $GH.G.Columns.Count -and $i -lt $GH.W.Length; $i++) {
        $GH.G.Columns[$i].Width = $GH.W[$i]
    }
}

function Fill-NetRoutes {
    param($M, [string]$Zone)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in ($M.Routes | Sort-Object @{e = { $_.V }}, @{e = { $_.Dst }})) {
        if ($Zone -ne '*' -and $r.V -ne $Zone) { continue }
        $rows.Add(@($r.V, $r.Seq, $r.Dst, $r.Gw, $r.Dev, $r.Dist, $r.Pri, $r.Status, $r.Cmt))
    }
    Fill-NetGridRows $gridRt $rows
}

function Fill-NetVpn {
    param($M, [string]$Zone)

    $treeVpn.BeginUpdate()
    $treeVpn.Nodes.Clear()

    $kids = @{}
    foreach ($p in $M.Ph2) {
        $k = "$($p.V)|$($p.P1)"
        $lst = $kids[$k]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $kids[$k] = $lst }
        $lst.Add($p)
    }

    $any = $false
    foreach ($p in ($M.Ph1 | Sort-Object @{e = { $_.V }}, @{e = { $_.N }})) {
        if ($Zone -ne '*' -and $p.V -ne $Zone) { continue }
        $any = $true
        $n = New-Object System.Windows.Forms.TreeNode
        $peer = $p.Peer
        if (-not $peer) { $peer = '(dialup)' }
        $n.Text = ("{0,-22} peer {1,-18} via {2,-10} {3}  dh {4}  ike {5}" -f $p.N, $peer, $p.Intf, $p.Prop, $p.Dh, $p.Ike)
        $n.NodeFont = New-Object System.Drawing.Font($treeVpn.Font, [System.Drawing.FontStyle]::Bold)
        [void]$treeVpn.Nodes.Add($n)

        $lst = $kids["$($p.V)|$($p.N)"]
        if ($lst -ne $null) {
            foreach ($c in ($lst | Sort-Object @{e = { $_.N }})) {
                $cn = New-Object System.Windows.Forms.TreeNode
                $src = $c.Src
                $dst = $c.Dst
                if (-not $src) { $src = '0.0.0.0/0' }
                if (-not $dst) { $dst = '0.0.0.0/0' }
                $cn.Text = ("{0,-22} local {1,-20} remote {2}" -f $c.N, $src, $dst)
                [void]$n.Nodes.Add($cn)
            }
        }
        $n.Expand()
    }
    if (-not $any) {
        $n = New-Object System.Windows.Forms.TreeNode
        $n.Text = 'No IPsec tunnels in this scope.'
        $n.ForeColor = [System.Drawing.Color]::FromArgb(140, 143, 150)
        [void]$treeVpn.Nodes.Add($n)
    }
    $treeVpn.EndUpdate()
}

function Fill-NetMatrix {
    param($M, [string]$Zone)

    # one matrix at a time; interface names repeat across VDOMs
    $v = $Zone
    if ($v -eq '*') {
        $best = ''
        $max = -1
        foreach ($k in $M.VdomPol.Keys) {
            if ($M.VdomPol[$k] -gt $max) { $max = $M.VdomPol[$k]; $best = $k }
        }
        $v = $best
    }

    $lbl = $pgMx.Tag
    $srcs = @{}
    $dsts = @{}
    $cell = @{}
    foreach ($p in $M.Pairs.Values) {
        if ($p.V -ne $v) { continue }
        $srcs[$p.Src] = $true
        $dsts[$p.Dst] = $true
        $cell["$($p.Src)|$($p.Dst)"] = $p
    }

    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('from \ to')
    $dstList = @($dsts.Keys | Sort-Object)
    foreach ($d in $dstList) { [void]$dt.Columns.Add($d) }

    foreach ($s in ($srcs.Keys | Sort-Object)) {
        $row = New-Object System.Collections.ArrayList
        [void]$row.Add($s)
        foreach ($d in $dstList) {
            $p = $cell["$s|$d"]
            if ($p -eq $null) { [void]$row.Add('') }
            else { [void]$row.Add([string]$p.N) }
        }
        [void]$dt.Rows.Add($row.ToArray())
    }

    $gridMx.DataSource = $dt
    $gridMx.Columns[0].Width = 150
    for ($i = 1; $i -lt $gridMx.Columns.Count; $i++) {
        $gridMx.Columns[$i].Width = 78
        $gridMx.Columns[$i].DefaultCellStyle.Alignment = 'MiddleCenter'
    }
    if ($lbl) {
        if ($srcs.Count -eq 0) {
            $lbl.Text = "  No firewall policies in this scope."
        } else {
            $lbl.Text = "  VDOM $v - policy count per source/destination interface pair. Blank means no policy covers that direction. Darker means more rules, which usually means room to consolidate."
        }
    }
}

function Fill-NetSvcs {
    param($M, [string]$Zone)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in ($M.Svcs | Sort-Object @{e = { $_.V }}, @{e = { $_.Kind }}, @{e = { $_.Name }})) {
        if ($Zone -ne '*' -and $s.V -ne $Zone) { continue }
        $rows.Add(@($s.V, $s.Kind, $s.Name, $s.Detail))
    }
    Fill-NetGridRows $gridSv $rows
}

function Fill-Network {
    if (-not $script:Audit) { return }

    $same = [object]::ReferenceEquals($script:NetLast, $script:Audit)
    if ($same -and $script:NetLastZone -eq $script:CurZone) { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    try {
        if (-not $same) {
            $script:NetModel = Get-NetModel $script:Audit.Objects
            $script:NetLast = $script:Audit
        }
        $z = $script:CurZone
        Fill-NetIfaces  $script:NetModel $z
        Fill-NetRoutes  $script:NetModel $z
        Fill-NetVpn     $script:NetModel $z
        Fill-NetMatrix  $script:NetModel $z
        Fill-NetSvcs    $script:NetModel $z
        $script:NetLastZone = $z
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

# lazy: build only when the Network tab is actually opened
$tabs.Add_SelectedIndexChanged({
    if ($tabs.SelectedTab -eq $tabNet) { Fill-Network }
})
# zone changes invalidate the view; refresh if we are looking at it
$tree.Add_AfterSelect({
    if ($tabs.SelectedTab -eq $tabNet) { Fill-Network }
})
