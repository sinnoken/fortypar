<#
    FortiGate Config Toolkit
    Cleanup analysis and compliance checking over one parsed config.

    Drop a config file in, read the findings, tick what you want, copy the CLI.

    Design notes
    ------------
    1. One parser feeds everything. Cleanup and compliance disagree about what
       matters but they agree about what the config says.

    2. Reference analysis scans EVERY value of EVERY object. A whitelist of
       "fields that can hold a reference" is silently wrong when incomplete,
       and it fails toward deletion. Roots are derived, not listed.

    3. Compliance rules run on the object tree, not on the text. A regex like
           config system admin(.|\n)*edit "remoteuser"(.|\n)*set trusthost1
       passes as soon as ANY later account has a trusthost, because the
       wildcard walks past 'next' into the next object. Structural matching
       removes that entire class of false pass.

    4. FortiOS omits settings sitting at factory default, so an absent key is
       not an unset value. Rules declare the default to assume.

    Requires: Windows PowerShell 5.1 or PowerShell 7 (Windows). Run with -STA.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }

foreach ($m in @('Core','Rules','Cli')) {
    $p = Join-Path $here "FortiToolkit.$m.ps1"
    if (-not (Test-Path -LiteralPath $p)) {
        [System.Windows.Forms.MessageBox]::Show("Missing module: FortiToolkit.$m.ps1", 'Startup') | Out-Null
        return
    }
    . $p
}

[System.Windows.Forms.Application]::EnableVisualStyles()


# =================================================================== GUI

$form = New-Object System.Windows.Forms.Form
$form.Text = 'FortiGate Config Toolkit'
$form.Size = New-Object System.Drawing.Size(1400, 900)
$form.StartPosition = 'CenterScreen'
$form.MinimumSize = New-Object System.Drawing.Size(1100, 680)
$form.AllowDrop = $true
$form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
$fntMono = New-Object System.Drawing.Font('Consolas', 9.5)

$script:Audit    = $null
$script:Lines    = $null
$script:Path     = ''
$script:CurZone  = '*'
$script:Suspend  = $false
$script:ShowPass = $false

$script:Grids     = @{}
$script:Tables    = @{}
$script:Widths    = @{}
$script:Recs      = @{}
$script:TypeBar   = @{}
$script:TypeSplit = @{}
$script:TypeAuto  = @{}
$script:EmptyLbl  = @{}

$script:SevRank = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3; 'info' = 4 }
$script:SevColor = @{
    'critical' = @(253, 220, 220, 150, 20, 20)
    'high'     = @(255, 232, 214, 150, 70, 10)
    'medium'   = @(255, 246, 214, 120, 95, 10)
    'low'      = @(238, 244, 252, 60, 90, 140)
    'info'     = @(242, 242, 245, 100, 100, 105)
}

# ---------- top bar ----------
$pnlTop = New-Object System.Windows.Forms.Panel
$pnlTop.Dock = 'Top'
$pnlTop.Height = 40
$pnlTop.BackColor = [System.Drawing.Color]::FromArgb(250, 250, 252)

$lblPath = New-Object System.Windows.Forms.Label
$lblPath.Text = 'No file loaded'
$lblPath.Location = New-Object System.Drawing.Point(12, 12)
$lblPath.AutoSize = $true
$lblPath.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 95)

$btnOpen = New-Object System.Windows.Forms.Button
$btnOpen.Text = 'Open config'
$btnOpen.Size = New-Object System.Drawing.Size(100, 26)
$btnOpen.FlatStyle = 'System'

$btnRules = New-Object System.Windows.Forms.Button
$btnRules.Text = 'Import rules'
$btnRules.Size = New-Object System.Drawing.Size(100, 26)
$btnRules.FlatStyle = 'System'

$chkPass = New-Object System.Windows.Forms.CheckBox
$chkPass.Text = 'Show passing'
$chkPass.Size = New-Object System.Drawing.Size(105, 24)

$chkCross = New-Object System.Windows.Forms.CheckBox
$chkCross.Text = 'Compare across VDOMs'
$chkCross.Size = New-Object System.Drawing.Size(160, 24)
$chkCross.Visible = $false

$pnlTop.Controls.AddRange(@($lblPath, $chkCross, $chkPass, $btnRules, $btnOpen))

$status = New-Object System.Windows.Forms.StatusStrip
$statusLabel = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text = 'Drop a FortiGate config file anywhere on this window.'
[void]$status.Items.Add($statusLabel)

# ---------- split ----------
$splitMain = New-Object System.Windows.Forms.SplitContainer
$splitMain.Dock = 'Fill'
$splitMain.Orientation = 'Vertical'
$splitMain.SplitterWidth = 6

$tree = New-Object System.Windows.Forms.TreeView
$tree.Dock = 'Fill'
$tree.HideSelection = $false
$tree.BorderStyle = 'None'
$tree.ItemHeight = 22
$tree.ShowRootLines = $false

$lblZone = New-Object System.Windows.Forms.Label
$lblZone.Text = '  Logical zones'
$lblZone.Dock = 'Top'
$lblZone.Height = 26
$lblZone.TextAlign = 'MiddleLeft'
$lblZone.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 244)
$lblZone.ForeColor = [System.Drawing.Color]::FromArgb(70, 70, 75)

$splitMain.Panel1.Controls.Add($tree)
$splitMain.Panel1.Controls.Add($lblZone)

$splitRight = New-Object System.Windows.Forms.SplitContainer
$splitRight.Dock = 'Fill'
$splitRight.Orientation = 'Horizontal'
$splitRight.SplitterWidth = 6
$splitMain.Panel2.Controls.Add($splitRight)

$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Dock = 'Fill'
$splitRight.Panel1.Controls.Add($tabs)

# ---------- bottom CLI ----------
$pnlCli = New-Object System.Windows.Forms.Panel
$pnlCli.Dock = 'Fill'

$barCli = New-Object System.Windows.Forms.Panel
$barCli.Dock = 'Top'
$barCli.Height = 32
$barCli.BackColor = [System.Drawing.Color]::FromArgb(240, 240, 244)

$lblCli = New-Object System.Windows.Forms.Label
$lblCli.Text = 'CLI for the ticked rows'
$lblCli.Location = New-Object System.Drawing.Point(10, 8)
$lblCli.AutoSize = $true

$btnAll  = New-Object System.Windows.Forms.Button
$btnAll.Text = 'Tick all'
$btnAll.Size = New-Object System.Drawing.Size(70, 24)
$btnAll.FlatStyle = 'System'

$btnNone = New-Object System.Windows.Forms.Button
$btnNone.Text = 'Clear'
$btnNone.Size = New-Object System.Drawing.Size(60, 24)
$btnNone.FlatStyle = 'System'

$btnCopy = New-Object System.Windows.Forms.Button
$btnCopy.Text = 'Copy'
$btnCopy.Size = New-Object System.Drawing.Size(70, 24)
$btnCopy.FlatStyle = 'System'

$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = 'Save report'
$btnSave.Size = New-Object System.Drawing.Size(90, 24)
$btnSave.FlatStyle = 'System'

$barCli.Controls.AddRange(@($lblCli, $btnAll, $btnNone, $btnCopy, $btnSave))

$txtCli = New-Object System.Windows.Forms.TextBox
$txtCli.Multiline = $true
$txtCli.ScrollBars = 'Both'
$txtCli.WordWrap = $false
$txtCli.Dock = 'Fill'
$txtCli.Font = $fntMono
$txtCli.BackColor = [System.Drawing.Color]::FromArgb(252, 252, 253)

$pnlCli.Controls.Add($txtCli)
$pnlCli.Controls.Add($barCli)
$splitRight.Panel2.Controls.Add($pnlCli)

# ---------- drop overlay ----------
$pnlDrop = New-Object System.Windows.Forms.Panel
$pnlDrop.Dock = 'Fill'
$pnlDrop.BackColor = [System.Drawing.Color]::FromArgb(248, 249, 251)
$pnlDrop.AllowDrop = $true

$lblDrop = New-Object System.Windows.Forms.Label
$lblDrop.Text = "Drop a FortiGate config file here`r`n`r`nor click to browse`r`n`r`n.conf   .txt   .cfg"
$lblDrop.Dock = 'Fill'
$lblDrop.TextAlign = 'MiddleCenter'
$lblDrop.Font = New-Object System.Drawing.Font('Segoe UI', 13)
$lblDrop.ForeColor = [System.Drawing.Color]::FromArgb(130, 135, 145)
$lblDrop.AllowDrop = $true
$pnlDrop.Controls.Add($lblDrop)

$form.Controls.Add($splitMain)
$form.Controls.Add($pnlDrop)
$form.Controls.Add($pnlTop)
$form.Controls.Add($status)
$pnlDrop.BringToFront()

function Update-TopLayout {
    $w = $pnlTop.ClientSize.Width
    if ($w -lt 200) { return }
    $btnOpen.Location  = New-Object System.Drawing.Point(($w - 112), 7)
    $btnRules.Location = New-Object System.Drawing.Point(($w - 218), 7)
    $chkPass.Location  = New-Object System.Drawing.Point(($w - 330), 8)
    $chkCross.Location = New-Object System.Drawing.Point(($w - 496), 8)
}
function Update-CliBar {
    $w = $barCli.ClientSize.Width
    if ($w -lt 200) { return }
    $btnSave.Location = New-Object System.Drawing.Point(($w - 100), 4)
    $btnCopy.Location = New-Object System.Drawing.Point(($w - 176), 4)
    $btnNone.Location = New-Object System.Drawing.Point(($w - 242), 4)
    $btnAll.Location  = New-Object System.Drawing.Point(($w - 318), 4)
}
$pnlTop.Add_SizeChanged({ Update-TopLayout })
$barCli.Add_SizeChanged({ Update-CliBar })

# ---------- text tabs ----------
function New-TextTab {
    param([string]$Title, [string]$Initial)
    $tp = New-Object System.Windows.Forms.TabPage
    $tp.Text = $Title
    $t = New-Object System.Windows.Forms.TextBox
    $t.Multiline = $true; $t.ReadOnly = $true
    $t.ScrollBars = 'Both'; $t.WordWrap = $false
    $t.Dock = 'Fill'; $t.Font = $fntMono
    $t.BackColor = [System.Drawing.Color]::White
    if ($Initial) { $t.Text = $Initial }
    $tp.Controls.Add($t)
    [void]$tabs.TabPages.Add($tp)
    return $t
}

$txtOv = New-TextTab 'Overview' ''

# ---------- grid tabs ----------
function New-GridTab {
    param([string]$Key, [string]$Title, [string[]]$Cols, [int[]]$W, [string]$Hint)

    $tp = New-Object System.Windows.Forms.TabPage
    $tp.Text = $Title
    $tp.Tag = $Key

    $lb = New-Object System.Windows.Forms.Label
    $lb.Text = $Hint
    $lb.Dock = 'Top'
    $lb.Height = 28
    $lb.TextAlign = 'MiddleLeft'
    $lb.BackColor = [System.Drawing.Color]::FromArgb(255, 252, 240)
    $lb.ForeColor = [System.Drawing.Color]::FromArgb(90, 80, 50)
    $lb.Padding = New-Object System.Windows.Forms.Padding(8, 0, 0, 0)

    # per-type checkbox strip; wraps and can be dragged taller or shorter
    $fp = New-Object System.Windows.Forms.FlowLayoutPanel
    $fp.Dock = 'Top'
    $fp.Height = 60
    $fp.AutoScroll = $true
    $fp.WrapContents = $true
    $fp.BackColor = [System.Drawing.Color]::FromArgb(246, 247, 250)
    $fp.Padding = New-Object System.Windows.Forms.Padding(8, 6, 8, 4)
    $fp.Visible = $false
    $fp.Tag = $Key
    $fp.Add_SizeChanged({
        param($src, $e)
        if ($script:Suspend) { return }
        if ($script:TypeAuto[$src.Tag]) { Fit-TypeBar $src.Tag }
    })

    $sp = New-Object System.Windows.Forms.Splitter
    $sp.Dock = 'Top'
    $sp.Height = 5
    $sp.BackColor = [System.Drawing.Color]::FromArgb(222, 224, 230)
    $sp.MinExtra = 120
    $sp.MinSize = 30
    $sp.Cursor = [System.Windows.Forms.Cursors]::HSplit
    $sp.Visible = $false
    $sp.Tag = $Key
    $sp.Add_SplitterMoved({
        param($src, $e)
        $script:TypeAuto[$src.Tag] = $false
    })
    $sp.Add_DoubleClick({
        param($src, $e)
        $k = $src.Tag
        $bar = $script:TypeBar[$k]
        if ($bar.Height -gt 34) {
            $script:TypeAuto[$k] = $false
            $bar.Height = 30
        } else {
            $script:TypeAuto[$k] = $true
            Fit-TypeBar $k
        }
    })

    $g = New-Object System.Windows.Forms.DataGridView
    $g.Dock = 'Fill'
    $g.AllowUserToAddRows = $false
    $g.AllowUserToDeleteRows = $false
    $g.AllowUserToResizeRows = $false
    $g.SelectionMode = 'FullRowSelect'
    $g.AutoSizeColumnsMode = 'None'
    $g.AutoSizeRowsMode = 'None'
    $g.RowHeadersVisible = $false
    $g.BorderStyle = 'None'
    $g.BackgroundColor = [System.Drawing.Color]::White
    $g.AlternatingRowsDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(247, 247, 250)
    $g.ColumnHeadersHeightSizeMode = 'DisableResizing'
    $g.EnableHeadersVisualStyles = $false
    $g.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(238, 238, 242)

    $el = New-Object System.Windows.Forms.Label
    $el.Dock = 'Fill'
    $el.TextAlign = 'MiddleCenter'
    $el.BackColor = [System.Drawing.Color]::White
    $el.ForeColor = [System.Drawing.Color]::FromArgb(120, 124, 132)
    $el.Font = New-Object System.Drawing.Font('Segoe UI', 10)
    $el.Visible = $false

    $tp.Controls.Add($el)
    $tp.Controls.Add($g)
    $tp.Controls.Add($sp)
    $tp.Controls.Add($fp)
    $tp.Controls.Add($lb)
    [void]$tabs.TabPages.Add($tp)

    $dt = New-Object System.Data.DataTable
    [void]$dt.Columns.Add('Fix', [bool])
    foreach ($c in $Cols) { [void]$dt.Columns.Add($c) }
    [void]$dt.Columns.Add('Ref', [int])

    $script:Grids[$Key]     = $g
    $script:Tables[$Key]    = $dt
    $script:Widths[$Key]    = $W
    $script:TypeBar[$Key]   = $fp
    $script:TypeSplit[$Key] = $sp
    $script:EmptyLbl[$Key]  = $el
    $script:TypeAuto[$Key]  = $true
}

New-GridTab 'Comp' 'Compliance' `
    @('Sev','Zone','ID','Category','Requirement','Object','Observed','Line') `
    @(38, 68, 78, 60, 128, 290, 145, 290, 55) `
    'Rules run on the parsed object tree, so a setting on one entry can never satisfy a rule about another.'

New-GridTab 'Safe' 'Safe to remove' `
    @('Zone','Kind','Type','Name','Value','Why','Line') `
    @(38, 78, 96, 145, 165, 190, 260, 55) `
    'Nothing in the config points at these. Verify with refcnt on the device before deleting.'

New-GridTab 'Decide' 'Needs a decision' `
    @('Zone','Category','Same value','Count','Suggested keep','Would drop','Lines') `
    @(38, 78, 118, 215, 50, 140, 215, 85) `
    'Same value, different names. Pick a keeper, repoint every reference, then delete. Deletes are generated commented out.'

$txtRules = New-TextTab 'Rule pack' ''
$txtLint  = New-TextTab 'Imported rule review' "Use 'Import rules' to load an NCM style XML rule folder.`r`n`r`nThose rules are reviewed, not executed. A text pattern that spans object`r`nboundaries reports compliant when it is not, so importing them here shows`r`nwhich ones cannot be trusted."

# =================================================================== FILL

function Get-TabKey {
    if ($tabs.SelectedTab -and $tabs.SelectedTab.Tag) { return [string]$tabs.SelectedTab.Tag }
    return $null
}

function Get-TypeCol {
    param([string]$Key)
    if ($Key -eq 'Comp')   { return 'Sev' }
    if ($Key -eq 'Safe')   { return 'Type' }
    if ($Key -eq 'Decide') { return 'Category' }
    return $null
}

function Fit-TypeBar {
    param([string]$Key)
    $fp = $script:TypeBar[$Key]
    if (-not $fp.Visible -or $fp.Controls.Count -eq 0) { return }
    $bottom = 0
    foreach ($c in $fp.Controls) {
        $b = $c.Bottom + $c.Margin.Bottom
        if ($b -gt $bottom) { $bottom = $b }
    }
    $want = $bottom + $fp.Padding.Bottom + 4
    $cap = [int]($fp.Parent.ClientSize.Height * 0.45)
    if ($cap -lt 40) { $cap = 40 }
    if ($want -gt $cap) { $want = $cap }
    if ($want -lt 34) { $want = 34 }
    $fp.Height = $want
}

function Set-TypeTicks {
    param([string]$Key, [string]$Type, [bool]$On)
    $g = $script:Grids[$Key]
    if (-not $g.DataSource) { return }
    $col = Get-TypeCol $Key
    if (-not $col) { return }
    $script:Suspend = $true
    foreach ($row in $g.Rows) {
        if ([string]$row.Cells[$col].Value -eq $Type) { $row.Cells['Fix'].Value = $On }
    }
    $script:Suspend = $false
    Refresh-Cli
}

function Build-TypeBar {
    param([string]$Key)

    $fp = $script:TypeBar[$Key]
    $g  = $script:Grids[$Key]
    $col = Get-TypeCol $Key

    $fp.Controls.Clear()
    if (-not $col -or -not $g.DataSource) {
        $fp.Visible = $false
        $script:TypeSplit[$Key].Visible = $false
        return
    }

    $cnt = @{}
    foreach ($row in $g.Rows) {
        $t = [string]$row.Cells[$col].Value
        if ($cnt.ContainsKey($t)) { $cnt[$t] = $cnt[$t] + 1 } else { $cnt[$t] = 1 }
    }
    if ($cnt.Count -eq 0) {
        $fp.Visible = $false
        $script:TypeSplit[$Key].Visible = $false
        return
    }

    $lb = New-Object System.Windows.Forms.Label
    $lb.Text = 'Select by type:'
    $lb.AutoSize = $true
    $lb.Margin = New-Object System.Windows.Forms.Padding(2, 5, 8, 0)
    $lb.ForeColor = [System.Drawing.Color]::FromArgb(90, 90, 95)
    [void]$fp.Controls.Add($lb)

    $keys = $cnt.Keys
    if ($col -eq 'Sev') {
        $keys = $cnt.Keys | Sort-Object @{e = { $script:SevRank[$_] }}
    } else {
        $keys = $cnt.Keys | Sort-Object
    }

    foreach ($t in $keys) {
        $cb = New-Object System.Windows.Forms.CheckBox
        $cb.Text = "$t ($($cnt[$t]))"
        $cb.AutoSize = $true
        $cb.Margin = New-Object System.Windows.Forms.Padding(0, 3, 14, 0)
        $cb.Tag = @($Key, $t)
        $cb.Add_Click({
            param($src, $e)
            $tag = $src.Tag
            Set-TypeTicks $tag[0] $tag[1] $src.Checked
        })
        [void]$fp.Controls.Add($cb)
    }
    $fp.Visible = $true
    $script:TypeSplit[$Key].Visible = $true
    if ($script:TypeAuto[$Key]) { Fit-TypeBar $Key }
}

function Sync-TypeBar {
    param([string]$Key)

    $fp = $script:TypeBar[$Key]
    $g  = $script:Grids[$Key]
    $col = Get-TypeCol $Key
    if (-not $col -or -not $fp.Visible) { return }

    $tot = @{}
    $on  = @{}
    foreach ($row in $g.Rows) {
        $t = [string]$row.Cells[$col].Value
        if ($tot.ContainsKey($t)) { $tot[$t] = $tot[$t] + 1 } else { $tot[$t] = 1 }
        if ($row.Cells['Fix'].Value -eq $true) {
            if ($on.ContainsKey($t)) { $on[$t] = $on[$t] + 1 } else { $on[$t] = 1 }
        }
    }
    foreach ($c in $fp.Controls) {
        if (-not ($c -is [System.Windows.Forms.CheckBox])) { continue }
        $t = $c.Tag[1]
        $n = 0
        if ($on.ContainsKey($t)) { $n = $on[$t] }
        $d = 0
        if ($tot.ContainsKey($t)) { $d = $tot[$t] }
        if ($d -gt 0 -and $n -eq $d) { $c.CheckState = [System.Windows.Forms.CheckState]::Checked }
        elseif ($n -gt 0) { $c.CheckState = [System.Windows.Forms.CheckState]::Indeterminate }
        else { $c.CheckState = [System.Windows.Forms.CheckState]::Unchecked }
    }
}

function Show-Empty {
    param([string]$Key, [int]$Rows)

    $lb = $script:EmptyLbl[$Key]
    if ($Rows -gt 0) { $lb.Visible = $false; return }

    $zone = 'this device'
    if ($script:CurZone -ne '*') { $zone = "zone '$($script:CurZone)'" }

    $what = 'items'
    if ($Key -eq 'Comp')   { $what = 'compliance findings' }
    if ($Key -eq 'Safe')   { $what = 'objects that can be removed' }
    if ($Key -eq 'Decide') { $what = 'duplicate values' }

    $n = 0
    if ($script:CurZone -ne '*') {
        foreach ($o in $script:Audit.Objects) { if ($o.V -eq $script:CurZone) { $n++ } }
    } else {
        $n = $script:Audit.Objects.Count
    }

    $msg = "No $what in $zone."
    if ($Key -eq 'Safe' -and $n -gt 0) {
        $msg = $msg + "`r`n`r`n$n object(s) were parsed here, but none are deletion candidates." +
               "`r`nCertificates, interfaces, admin accounts and system settings are" +
               "`r`nnever offered for removal - only address, service, VIP, pool," +
               "`r`nschedule and shaper objects are."
    }
    if ($Key -eq 'Comp' -and -not $script:ShowPass) {
        $msg = $msg + "`r`n`r`nPassing checks are hidden. Tick 'Show passing' to see them."
    }
    $lb.Text = $msg
    $lb.Visible = $true
    $lb.BringToFront()
}

function Apply-View {
    param([string]$Key)
    $dt = $script:Tables[$Key]
    $view = New-Object System.Data.DataView($dt)
    if ($script:CurZone -ne '*') {
        $z = $script:CurZone.Replace("'", "''")
        if ($Key -eq 'Decide') { $view.RowFilter = "[Zone] LIKE '%$z%'" }
        else { $view.RowFilter = "[Zone] = '$z'" }
    }
    $script:Grids[$Key].DataSource = $view
    Build-TypeBar $Key
    Sync-TypeBar $Key
    Show-Empty $Key $view.Count
}

function Fill-Tab {
    param([string]$Key)

    $dt = $script:Tables[$Key]
    $g  = $script:Grids[$Key]
    $recs = [System.Collections.Generic.List[object]]::new()

    $g.DataSource = $null
    $dt.Clear()
    $dt.BeginLoadData()

    $i = 0
    switch ($Key) {
        'Comp' {
            foreach ($r in $script:Audit.Comp) {
                if ($r.Skip) { continue }
                if ($r.Pass -and -not $script:ShowPass) { continue }
                [void]$recs.Add($r)
                [void]$dt.LoadDataRow(@($false, $r.Sev, $r.Zone, $r.Id, $r.Cat, $r.Title, $r.Obj, $r.Detail, $r.Line, $i), $true)
                $i++
            }
        }
        'Safe' {
            foreach ($r in $script:Audit.Safe) {
                [void]$recs.Add($r)
                [void]$dt.LoadDataRow(@($false, $r.V, $r.Kind, $r.S, $r.N, $r.Val, $r.Why, $r.L, $i), $true)
                $i++
            }
        }
        'Decide' {
            foreach ($r in $script:Audit.Decide) {
                [void]$recs.Add($r)
                [void]$dt.LoadDataRow(@($false, $r.V, $r.C, $r.K, $r.Cnt, $r.Keep, $r.Drop, $r.L, $i), $true)
                $i++
            }
        }
    }
    $dt.EndLoadData()
    $script:Recs[$Key] = $recs

    Apply-View $Key

    $w = $script:Widths[$Key]
    for ($c = 0; $c -lt $g.Columns.Count; $c++) {
        if ($c -lt $w.Length) { $g.Columns[$c].Width = $w[$c] }
        $g.Columns[$c].SortMode = 'NotSortable'
        if ($c -gt 0) { $g.Columns[$c].ReadOnly = $true }
    }
    $g.Columns['Ref'].Visible = $false
    $g.Columns[0].HeaderText = ''
}

$script:Grids['Comp'].Add_CellFormatting({
    param($s, $e)
    if ($s.Columns[$e.ColumnIndex].Name -ne 'Sev') { return }
    $c = $script:SevColor[[string]$e.Value]
    if ($c -eq $null) { return }
    $e.CellStyle.BackColor = [System.Drawing.Color]::FromArgb($c[0], $c[1], $c[2])
    $e.CellStyle.ForeColor = [System.Drawing.Color]::FromArgb($c[3], $c[4], $c[5])
})

foreach ($k in @('Comp','Safe','Decide')) {
    $g = $script:Grids[$k]
    $g.Add_CurrentCellDirtyStateChanged({
        param($s, $e)
        if ($s.IsCurrentCellDirty) {
            $s.CommitEdit([System.Windows.Forms.DataGridViewDataErrorContexts]::Commit)
        }
    })
    $g.Add_CellValueChanged({
        param($s, $e)
        if ($e.ColumnIndex -ne 0) { return }
        if ($script:Suspend) { return }
        $kk = Get-TabKey
        if ($kk) { Sync-TypeBar $kk }
        Refresh-Cli
    })
    $g.Add_CellDoubleClick({
        param($s, $e)
        if ($e.RowIndex -lt 0) { return }
        $kk = Get-TabKey
        if (-not $kk) { return }
        $idx = [int]$s.Rows[$e.RowIndex].Cells['Ref'].Value
        Show-Detail $kk $script:Recs[$kk][$idx]
    })
}

function Show-Detail {
    param([string]$Key, $R)

    $f = New-Object System.Windows.Forms.Form
    $f.Size = New-Object System.Drawing.Size(840, 580)
    $f.StartPosition = 'CenterParent'
    $t = New-Object System.Windows.Forms.TextBox
    $t.Multiline = $true; $t.ReadOnly = $true; $t.ScrollBars = 'Both'
    $t.WordWrap = $true; $t.Dock = 'Fill'; $t.Font = $fntMono

    $sb = New-Object System.Text.StringBuilder
    $line = 0

    if ($Key -eq 'Comp') {
        $f.Text = "$($R.Id)  -  $($R.Title)"
        [void]$sb.AppendLine("Rule       $($R.Id)   severity $($R.Sev)")
        [void]$sb.AppendLine("Category   $($R.Cat)")
        [void]$sb.AppendLine("Zone       $($R.Zone)")
        [void]$sb.AppendLine("Section    $($R.Scope)")
        if ($R.Obj) { [void]$sb.AppendLine("Object     $($R.Obj)") }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('REQUIREMENT')
        [void]$sb.AppendLine("  $($R.Title)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('RESULT')
        if ($R.Pass) { [void]$sb.AppendLine('  pass') }
        else { [void]$sb.AppendLine("  FAIL - $($R.Detail)") }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('WHY IT MATTERS')
        [void]$sb.AppendLine("  $($R.Why)")
        [void]$sb.AppendLine('')
        if ($R.Fix) {
            [void]$sb.AppendLine('SUGGESTED REMEDIATION')
            foreach ($x in $R.Fix) { [void]$sb.AppendLine("  $x") }
            [void]$sb.AppendLine('')
        }
        $line = $R.Line
    }
    elseif ($Key -eq 'Safe') {
        $f.Text = "$($R.Kind)  -  $($R.N)"
        [void]$sb.AppendLine("Zone       $($R.V)")
        [void]$sb.AppendLine("Section    $($R.S)")
        [void]$sb.AppendLine("Name       $($R.N)")
        [void]$sb.AppendLine("Value      $($R.Val)")
        if ($R.Cm) { [void]$sb.AppendLine("Comment    $($R.Cm)") }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('WHY IT IS LISTED')
        [void]$sb.AppendLine("  $($R.Why)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('HOW THAT WAS DECIDED')
        [void]$sb.AppendLine('  Every value of every object in this file was tokenised, and any')
        [void]$sb.AppendLine('  token matching a known object name counts as a reference. There is')
        [void]$sb.AppendLine('  no list of "fields that can hold a reference": such a list fails')
        [void]$sb.AppendLine('  silently and fails toward deletion.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  A config file cannot show references held by FortiManager, SDN')
        [void]$sb.AppendLine('  connectors, or device memory. Confirm before deleting:')
        $p = $script:CmdbPath[$R.S]
        if ($p) { [void]$sb.AppendLine("    diagnose sys cmdb refcnt show $p $($R.N)") }
        [void]$sb.AppendLine("    show | grep -f $($R.N)")
        [void]$sb.AppendLine('')
        $line = $R.L
    }
    else {
        $f.Text = "$($R.C)  -  $($R.K)"
        [void]$sb.AppendLine("Zone       $($R.V)")
        [void]$sb.AppendLine("Category   $($R.C)")
        [void]$sb.AppendLine("Value      $($R.K)")
        [void]$sb.AppendLine("Count      $($R.Cnt)")
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('OBJECTS SHARING THIS VALUE')
        foreach ($o in $R.Items) {
            $mark = '   '
            if ($o.N -eq $R.Keep) { $mark = ' * ' }
            $ub = $script:Audit.UsedBy[$o]
            $u = 'no reference found in this file'
            if ($ub) { $u = "used by $ub" }
            [void]$sb.AppendLine("  $mark $($o.N)   line $($o.L)")
            [void]$sb.AppendLine("        $u")
        }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('  * suggested keeper: the one that is actually referenced.')
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('MERGING IS NOT A BULK OPERATION')
        [void]$sb.AppendLine('  Repoint every reference at the keeper first. FortiOS will refuse')
        [void]$sb.AppendLine('  the delete while anything still points at the object.')
        [void]$sb.AppendLine('')
        $line = [int]($R.L.Split(',')[0])
    }

    if ($line -gt 0 -and $script:Lines) {
        [void]$sb.AppendLine('CONFIG SOURCE')
        $a = $line - 3
        if ($a -lt 0) { $a = 0 }
        $b = $line + 14
        if ($b -ge $script:Lines.Length) { $b = $script:Lines.Length - 1 }
        for ($k = $a; $k -le $b; $k++) {
            $mk = '  '
            if (($k + 1) -eq $line) { $mk = '>>' }
            [void]$sb.AppendLine(("  {0} {1,6} | {2}" -f $mk, ($k + 1), $script:Lines[$k]))
        }
    }

    $t.Text = $sb.ToString() -replace "`n", "`r`n"
    $f.Controls.Add($t)
    [void]$f.ShowDialog()
}

# =================================================================== CLI

function Get-Ticked {
    param([string]$Key)
    $out = [System.Collections.Generic.List[object]]::new()
    $g = $script:Grids[$Key]
    if (-not $g -or -not $g.DataSource) { return $out }
    foreach ($row in $g.Rows) {
        if ($row.Cells['Fix'].Value -eq $true) {
            [void]$out.Add($script:Recs[$Key][[int]$row.Cells['Ref'].Value])
        }
    }
    return $out
}

function Refresh-Cli {
    $Key = Get-TabKey
    if (-not $Key -or -not $script:Audit) {
        $txtCli.Text = ''
        return
    }
    $sel = Get-Ticked $Key
    if ($sel.Count -eq 0) {
        $txtCli.Text = '# Tick a row above to build the CLI for it.'
        $lblCli.Text = 'CLI for the ticked rows'
        return
    }
    $vm = [bool]$script:Audit.VdomMode
    switch ($Key) {
        'Comp' {
            $fails = [System.Collections.Generic.List[object]]::new()
            foreach ($r in $sel) { if (-not $r.Pass) { [void]$fails.Add($r) } }
            if ($fails.Count -eq 0) {
                $txtCli.Text = '# Only passing checks are ticked. Nothing to remediate.'
                return
            }
            $txtCli.Text = Build-FixCli $fails $vm
            $lblCli.Text = "Remediation CLI  -  $($fails.Count) finding(s) ticked"
        }
        'Safe' {
            $txtCli.Text = Build-SafeCli $sel $vm
            $lblCli.Text = "Cleanup CLI  -  $($sel.Count) object(s) ticked"
        }
        'Decide' {
            $txtCli.Text = Build-DecideCli $sel $vm $script:Audit.UsedBy
            $lblCli.Text = "Merge plan  -  $($sel.Count) group(s) ticked"
        }
    }
}

function Set-AllTicks {
    param([bool]$On)
    $Key = Get-TabKey
    if (-not $Key) { return }
    $g = $script:Grids[$Key]
    if (-not $g.DataSource) { return }
    $script:Suspend = $true
    foreach ($row in $g.Rows) { $row.Cells['Fix'].Value = $On }
    $script:Suspend = $false
    Sync-TypeBar $Key
    Refresh-Cli
}

# =================================================================== LOAD

function Load-File {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        [System.Windows.Forms.MessageBox]::Show('File not found.', 'Error') | Out-Null
        return
    }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $statusLabel.Text = 'Reading...'
    $status.Refresh()
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        # the network view caches its model against the previous $script:Audit
        # by reference; clearing it here keeps that cache honest even if the
        # audit hashtable is ever updated in place instead of rebuilt
        $script:NetLast = $null

        $full = (Resolve-Path -LiteralPath $Path).ProviderPath
        $script:Path = $full
        $script:Lines = [System.IO.File]::ReadAllLines($full)

        $statusLabel.Text = 'Parsing...'
        $status.Refresh()
        $parsed = Parse-FortiConfig -Lines $script:Lines
        $tParse = $sw.Elapsed.TotalSeconds

        $statusLabel.Text = 'Analysing references...'
        $status.Refresh()
        $clean = Invoke-Cleanup -Parsed $parsed -CrossVdom $chkCross.Checked

        $statusLabel.Text = 'Evaluating rules...'
        $status.Refresh()
        $comp = Invoke-Compliance -Objects $parsed.Objects -Rules $script:Pack -VdomMode $parsed.VdomMode

        foreach ($r in $comp) {
            $p = 1
            if (-not $r.Pass) { $p = 0 }
            $r.SortKey = "$p$($script:SevRank[$r.Sev])|$($r.Zone)|$($r.Id)|$($r.Obj)"
        }
        $compSorted = $comp | Sort-Object -Property SortKey

        $sw.Stop()

        $script:Audit = @{
            Objects  = $parsed.Objects
            Header   = $parsed.Header
            VdomMode = $parsed.VdomMode
            Sections = $clean.Sections
            Safe     = $clean.Safe
            Decide   = $clean.Decide
            Held     = $clean.Held
            UsedBy   = $clean.UsedBy
            Comp     = $compSorted
        }

        Build-Tree
        foreach ($k in @('Comp','Safe','Decide')) { Fill-Tab $k }
        Build-Overview $tParse $sw.Elapsed.TotalSeconds
        Build-RulePack

        $fail = 0
        foreach ($r in $compSorted) { if (-not $r.Pass -and -not $r.Skip) { $fail++ } }
        $tabs.TabPages[1].Text = "Compliance ($fail)"
        $tabs.TabPages[2].Text = "Safe to remove ($($clean.Safe.Count))"
        $tabs.TabPages[3].Text = "Needs a decision ($($clean.Decide.Count))"

        $lblPath.Text = [System.IO.Path]::GetFileName($full)
        $chkCross.Visible = [bool]$parsed.VdomMode
        $pnlDrop.Visible = $false
        $txtCli.Text = '# Tick a row above to build the CLI for it.'
        if ($tabs.SelectedIndex -eq 0) { $tabs.SelectedIndex = 1 }

        $statusLabel.Text = "$($script:Lines.Length) lines, $($parsed.Objects.Count) objects  |  $fail compliance, $($clean.Safe.Count) removable, $($clean.Decide.Count) duplicate  |  $([math]::Round($sw.Elapsed.TotalSeconds,2))s"
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Failed: $($_.Exception.Message)`r`n`r`n$($_.ScriptStackTrace)", 'Error') | Out-Null
        $statusLabel.Text = 'Failed'
    }
    finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Build-Tree {
    $tree.Nodes.Clear()

    $dev = 'FortiGate'
    foreach ($h in $script:Audit.Header) {
        if ($h -match 'config-version=([^:]+)') { $dev = $Matches[1]; break }
    }
    foreach ($o in $script:Audit.Objects) {
        if ($o.S -eq 'system global' -and $o.T['hostname']) {
            $dev = Strip-Quotes ([string]$o.T['hostname'])
            break
        }
    }

    $zones = @{}
    $todo  = @{}
    foreach ($o in $script:Audit.Objects) { $zones[$o.V] = $true }

    foreach ($r in $script:Audit.Comp) {
        if ($r.Pass -or $r.Skip) { continue }
        $zones[$r.Zone] = $true
        if ($todo.ContainsKey($r.Zone)) { $todo[$r.Zone] = $todo[$r.Zone] + 1 } else { $todo[$r.Zone] = 1 }
    }
    foreach ($r in $script:Audit.Safe) {
        if ($todo.ContainsKey($r.V)) { $todo[$r.V] = $todo[$r.V] + 1 } else { $todo[$r.V] = 1 }
    }
    foreach ($r in $script:Audit.Decide) {
        foreach ($z in ($r.V -split ',')) {
            $zz = $z.Trim()
            if ($todo.ContainsKey($zz)) { $todo[$zz] = $todo[$zz] + 1 } else { $todo[$zz] = 1 }
        }
    }
    $total = 0
    foreach ($k in $todo.Keys) { $total = $total + $todo[$k] }

    $root = New-Object System.Windows.Forms.TreeNode
    $root.Text = "$dev   $total to review"
    $root.Tag = '*'
    $root.NodeFont = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    [void]$tree.Nodes.Add($root)

    if ($script:Audit.VdomMode) {
        $splitMain.Panel1Collapsed = $false
        foreach ($z in ($zones.Keys | Sort-Object)) {
            $n = New-Object System.Windows.Forms.TreeNode
            $lab = $z
            if ($z -eq 'global') { $lab = 'global (device-wide)' }
            $f = 0
            if ($todo.ContainsKey($z)) { $f = $todo[$z] }
            $n.Text = "$lab   $f"
            $n.Tag = $z
            if ($f -eq 0) { $n.ForeColor = [System.Drawing.Color]::FromArgb(150, 152, 158) }
            [void]$root.Nodes.Add($n)
        }
        $lblZone.Text = "  Logical zones - $($zones.Count)"
    } else {
        $lblZone.Text = '  VDOM mode is off'
        $splitMain.Panel1Collapsed = $true
    }
    $root.Expand()
    $script:CurZone = '*'
    $tree.SelectedNode = $root
}

function Build-Overview {
    param([double]$TParse, [double]$TAll)

    $a = $script:Audit
    $sb = New-Object System.Text.StringBuilder

    [void]$sb.AppendLine('DEVICE')
    foreach ($h in $a.Header) { [void]$sb.AppendLine("  $h") }
    [void]$sb.AppendLine("  file        $script:Path")
    [void]$sb.AppendLine("  lines       $($script:Lines.Length)")
    [void]$sb.AppendLine("  objects     $($a.Objects.Count)")
    if ($a.VdomMode) { [void]$sb.AppendLine('  vdom mode   enabled') }
    else { [void]$sb.AppendLine('  vdom mode   disabled (single logical zone)') }
    [void]$sb.AppendLine(("  parse       {0:N2} s" -f $TParse))
    [void]$sb.AppendLine(("  total       {0:N2} s" -f $TAll))
    [void]$sb.AppendLine('')

    $hi = 0; $me = 0; $lo = 0; $cr = 0; $pass = 0; $skip = 0
    foreach ($r in $a.Comp) {
        if ($r.Skip) { $skip++; continue }
        if ($r.Pass) { $pass++; continue }
        switch ($r.Sev) {
            'critical' { $cr++ }
            'high'     { $hi++ }
            'medium'   { $me++ }
            default    { $lo++ }
        }
    }

    [void]$sb.AppendLine('WHAT TO DO')
    [void]$sb.AppendLine("  Compliance          $($cr + $hi + $me + $lo)   critical $cr / high $hi / medium $me / low $lo")
    [void]$sb.AppendLine("  Safe to remove      $($a.Safe.Count)   unreferenced objects, empty groups, disabled policies")
    [void]$sb.AppendLine("  Needs a decision    $($a.Decide.Count)   duplicate values that need a keeper chosen")
    [void]$sb.AppendLine("  Passing checks      $pass")
    [void]$sb.AppendLine("  Not applicable      $skip   (rule had no matching object in that zone)")
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('HOW COMPLIANCE IS EVALUATED')
    [void]$sb.AppendLine('  Rules run against the parsed object tree, not the config text. A rule')
    [void]$sb.AppendLine('  such as "every admin account needs a trusted host" can only look at one')
    [void]$sb.AppendLine('  account at a time, so a setting belonging to a different entry can')
    [void]$sb.AppendLine('  never satisfy it. A regex with an unbounded wildcard does exactly that')
    [void]$sb.AppendLine('  and reports compliant when it should not.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('  FortiOS omits settings sitting at their factory default, so an absent')
    [void]$sb.AppendLine('  key is not an unset value. Each rule declares the default to assume,')
    [void]$sb.AppendLine('  and findings mark such values as (default).')
    [void]$sb.AppendLine('')

    [void]$sb.AppendLine('HOW THE UNREFERENCED LIST WAS BUILT')
    [void]$sb.AppendLine('  Every value of every object is tokenised, and any token matching a')
    [void]$sb.AppendLine('  known object name counts as a reference. There is no list of "fields')
    [void]$sb.AppendLine('  that can hold a reference" - such a list fails silently and fails')
    [void]$sb.AppendLine('  toward deletion.')
    [void]$sb.AppendLine('  Starting points are derived: every object that is not itself a deletion')
    [void]$sb.AppendLine('  candidate is a root, including blocks with no edit such as vpn ssl')
    [void]$sb.AppendLine('  settings, and nested sub-tables such as firewall vip/realservers.')
    [void]$sb.AppendLine('  Names resolve in the current VDOM first, then fall back to global.')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('  NOT COVERED BY ANY FILE-BASED METHOD')
    [void]$sb.AppendLine('    references held by FortiManager policy packages')
    [void]$sb.AppendLine('    SDN connector objects resolved at runtime')
    [void]$sb.AppendLine('    references that exist only in device memory')
    [void]$sb.AppendLine('    drift between this export and the device right now')
    [void]$sb.AppendLine('  Confirm on the device before deleting anything:')
    [void]$sb.AppendLine('    diagnose sys cmdb refcnt show <path.object.mkey> <name>')
    [void]$sb.AppendLine('    show | grep -f <name>')
    [void]$sb.AppendLine('')

    if ($a.Held.Count -gt 0) {
        [void]$sb.AppendLine("BUILT-IN OBJECTS HELD BACK  ($($a.Held.Count))")
        [void]$sb.AppendLine('  Zero references, but these ship with FortiOS and are never offered')
        [void]$sb.AppendLine('  for deletion regardless of the analysis result:')
        foreach ($h in ($a.Held | Sort-Object @{e = { $_.N }})) {
            [void]$sb.AppendLine(("    {0,-34} {1}" -f $h.N, $h.S))
        }
        [void]$sb.AppendLine('')
    }

    [void]$sb.AppendLine('SECTIONS FOUND')
    $byV = @{}
    foreach ($s in $a.Sections) {
        $lst = $byV[$s[0]]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byV[$s[0]] = $lst }
        [void]$lst.Add($s)
    }
    foreach ($v in ($byV.Keys | Sort-Object)) {
        [void]$sb.AppendLine("  [$v]")
        foreach ($s in ($byV[$v] | Sort-Object @{e = { [int]$_[2] }; d = $true})) {
            [void]$sb.AppendLine(("    {0,-46} {1,6}" -f $s[1], $s[2]))
        }
    }

    $txtOv.Text = $sb.ToString() -replace "`n", "`r`n"
}

function Build-RulePack {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("BUILT-IN RULE PACK  -  $($script:Pack.Count) rules")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Mode')
    [void]$sb.AppendLine('  each      evaluated once per object in the section')
    [void]$sb.AppendLine('  section   evaluated against the section settings block')
    [void]$sb.AppendLine('  exists    the section must contain at least one matching entry')
    [void]$sb.AppendLine('  absent    the section must not contain any matching entry')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('Zone')
    [void]$sb.AppendLine('  global    only the global scope (ignored when VDOMs are off)')
    [void]$sb.AppendLine('  vdom      every VDOM except global')
    [void]$sb.AppendLine('  any       every zone')
    [void]$sb.AppendLine('')

    $byCat = @{}
    foreach ($r in $script:Pack) {
        $lst = $byCat[$r.Cat]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byCat[$r.Cat] = $lst }
        [void]$lst.Add($r)
    }
    foreach ($c in ($byCat.Keys | Sort-Object)) {
        [void]$sb.AppendLine("[$c]")
        foreach ($r in $byCat[$c]) {
            [void]$sb.AppendLine(("  {0,-8} {1,-9} {2}" -f $r.Id, $r.Sev, $r.Title))
            [void]$sb.AppendLine(("           section {0}   zone {1}   mode {2}" -f $r.Scope, $r.Zone, $r.Mode))
        }
        [void]$sb.AppendLine('')
    }
    $txtRules.Text = $sb.ToString() -replace "`n", "`r`n"
}

# =================================================================== EVENTS

function Open-Dialog {
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'FortiGate config (*.conf;*.txt;*.cfg)|*.conf;*.txt;*.cfg|All files (*.*)|*.*'
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Load-File $dlg.FileName }
}

$btnOpen.Add_Click({ Open-Dialog })
$lblDrop.Add_Click({ Open-Dialog })
$pnlDrop.Add_Click({ Open-Dialog })

$chkCross.Add_CheckedChanged({ if ($script:Path) { Load-File $script:Path } })

$chkPass.Add_CheckedChanged({
    $script:ShowPass = $chkPass.Checked
    if ($script:Audit) { Fill-Tab 'Comp'; Refresh-Cli }
})

$btnRules.Add_Click({
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Folder containing NCM style rule XML files'
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $rules = Import-TextRules $dlg.SelectedPath
    $lint = Lint-TextRules $rules

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("IMPORTED TEXT RULES  -  $($rules.Count) rule(s)")
    [void]$sb.AppendLine("from $($dlg.SelectedPath)")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('These are reviewed, not executed. A text pattern is evaluated against the')
    [void]$sb.AppendLine('whole config as one string, so a wildcard can walk past the end of the')
    [void]$sb.AppendLine('object it anchored on and match a setting belonging to something else.')
    [void]$sb.AppendLine('That failure direction is "compliant", which is worse than a false alarm.')
    [void]$sb.AppendLine('')

    $crit = 0; $high = 0
    foreach ($l in $lint) {
        if ($l.Sev -eq 'critical') { $crit++ }
        if ($l.Sev -eq 'high') { $high++ }
    }
    [void]$sb.AppendLine("  critical problems  $crit")
    [void]$sb.AppendLine("  high problems      $high")
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('---------------------------------------------------------------')

    $byRule = @{}
    foreach ($l in $lint) {
        $k = "$($l.File)|$($l.Name)"
        $lst = $byRule[$k]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byRule[$k] = $lst }
        [void]$lst.Add($l)
    }
    foreach ($k in ($byRule.Keys | Sort-Object)) {
        $first = $byRule[$k][0]
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("RULE   $($first.Name)")
        [void]$sb.AppendLine("file   $($first.File)")
        if ($first.Group) { [void]$sb.AppendLine("group  $($first.Group)") }
        [void]$sb.AppendLine("regex  $($first.Pattern)")
        foreach ($l in $byRule[$k]) {
            [void]$sb.AppendLine("  [$($l.Sev)] $($l.Text)")
            if ($l.Hint) { [void]$sb.AppendLine("     fix: $($l.Hint)") }
        }
    }
    $txtLint.Text = $sb.ToString() -replace "`n", "`r`n"
    $tabs.SelectedTab = $tabs.TabPages[5]
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $statusLabel.Text = "Imported $($rules.Count) text rule(s); $crit critical, $high high problems"
})

$tree.Add_AfterSelect({
    param($s, $e)
    $script:CurZone = [string]$e.Node.Tag
    if (-not $script:Audit) { return }
    foreach ($k in @('Comp','Safe','Decide')) { Apply-View $k }
    Refresh-Cli
})

$tabs.Add_SelectedIndexChanged({ Refresh-Cli })

$btnAll.Add_Click({ Set-AllTicks $true })
$btnNone.Add_Click({ Set-AllTicks $false })

$btnCopy.Add_Click({
    if (-not $txtCli.Text) { return }
    # Clipboard needs an STA thread. PowerShell 7 defaults to MTA, so without
    # -STA this throws; report it on the status bar instead of letting an
    # unhandled exception dialog surface.
    try {
        [System.Windows.Forms.Clipboard]::SetText($txtCli.Text)
        $statusLabel.Text = 'CLI copied to clipboard.'
    }
    catch {
        $statusLabel.Text = 'Clipboard unavailable - start PowerShell with -STA, or select the text and copy manually.'
    }
})

function Write-Csv {
    param([string]$Path, [string[]]$Headers, $Rows)
    $sb = New-Object System.Text.StringBuilder
    $q = @()
    foreach ($h in $Headers) { $q += '"' + $h + '"' }
    [void]$sb.AppendLine($q -join ',')
    foreach ($r in $Rows) {
        $cells = @()
        foreach ($c in $r) { $cells += '"' + ([string]$c).Replace('"', '""') + '"' }
        [void]$sb.AppendLine($cells -join ',')
    }
    [System.IO.File]::WriteAllText($Path, $sb.ToString(), (New-Object System.Text.UTF8Encoding $true))
}

$btnSave.Add_Click({
    if (-not $script:Audit) { return }
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Choose a folder for the report'
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

    $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
    $dir = Join-Path $dlg.SelectedPath ("FortiToolkit_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $enc = New-Object System.Text.UTF8Encoding $true

    [System.IO.File]::WriteAllText((Join-Path $dir '0_overview.txt'), $txtOv.Text, $enc)
    [System.IO.File]::WriteAllText((Join-Path $dir '4_rulepack.txt'), $txtRules.Text, $enc)
    if ($txtCli.Text -and -not $txtCli.Text.StartsWith('# Tick')) {
        [System.IO.File]::WriteAllText((Join-Path $dir '5_cli.txt'), $txtCli.Text, $enc)
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $script:Audit.Comp) {
        if ($r.Skip) { continue }
        $st = 'FAIL'
        if ($r.Pass) { $st = 'pass' }
        [void]$rows.Add(@($st, $r.Sev, $r.Zone, $r.Id, $r.Cat, $r.Title, $r.Obj, $r.Scope, $r.Detail, $r.Line))
    }
    Write-Csv (Join-Path $dir '1_compliance.csv') `
        @('Result','Severity','Zone','RuleID','Category','Requirement','Object','Section','Observed','Line') $rows

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $script:Audit.Safe) {
        [void]$rows.Add(@($r.V, $r.Kind, $r.S, $r.N, $r.Val, $r.Why, $r.Cm, $r.L))
    }
    Write-Csv (Join-Path $dir '2_removable.csv') `
        @('Zone','Kind','Section','Name','Value','Why','Comment','Line') $rows

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $script:Audit.Decide) {
        [void]$rows.Add(@($r.V, $r.C, $r.K, $r.Cnt, $r.Keep, $r.Drop, $r.L))
    }
    Write-Csv (Join-Path $dir '3_duplicates.csv') `
        @('Zone','Category','Value','Count','SuggestedKeep','WouldDrop','Lines') $rows

    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $statusLabel.Text = "Report written to $dir"
    [System.Windows.Forms.MessageBox]::Show("Report written to:`r`n$dir", 'Export complete') | Out-Null
})

$dragEnter = {
    param($s, $e)
    if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
        $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
    }
}
$dragDrop = {
    param($s, $e)
    $f = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
    if ($f.Count -gt 0) { Load-File $f[0] }
}
$form.Add_DragEnter($dragEnter)
$form.Add_DragDrop($dragDrop)
$pnlDrop.Add_DragEnter($dragEnter)
$pnlDrop.Add_DragDrop($dragDrop)
$lblDrop.Add_DragEnter($dragEnter)
$lblDrop.Add_DragDrop($dragDrop)

. (Join-Path $here 'FortiNetworkTab.ps1')
$form.Add_Shown({
    Update-TopLayout
    Update-CliBar
    $splitMain.SplitterDistance = 215
    $splitRight.SplitterDistance = [int]($splitRight.Height * 0.58)
    Build-RulePack
})

[void]$form.ShowDialog()
