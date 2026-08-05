<#
    FortiToolkit - CLI builders and imported rule review

    NOTE: FortiOS treats everything after a command as arguments, so a comment
    must never be appended to a command line. Every comment gets its own line.
    There is a static check for this in the build script; do not "tidy" a
    comment onto the end of a command.
#>

function Get-VdomOpen {
    param([string]$Zone, [bool]$VdomMode)
    if (-not $VdomMode) { return @() }
    if ($Zone -eq 'global') { return @('config global') }
    return @('config vdom', "edit $Zone")
}

function Get-VdomClose {
    param([string]$Zone, [bool]$VdomMode)
    if (-not $VdomMode) { return @() }
    if ($Zone -eq 'global') { return @('end') }
    return @('next', 'end')
}

function Build-SafeCli {
    param($Recs, [bool]$VdomMode)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# --------------------------------------------------------------')
    [void]$sb.AppendLine('# Step 1 - back up first')
    [void]$sb.AppendLine('#   execute backup config tftp before-cleanup.conf <tftp-server>')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# Step 2 - MANDATORY. Do not skip.')
    [void]$sb.AppendLine('#   The delete block below was derived from this config FILE only.')
    [void]$sb.AppendLine('#   A file cannot show references held by FortiManager, SDN')
    [void]$sb.AppendLine('#   connectors, or anything outside it. The DEVICE is the authority.')
    [void]$sb.AppendLine('#   Run every line below and confirm each returns no reference:')

    $seen = @{}
    foreach ($r in $Recs) {
        $p = $script:CmdbPath[$r.S]
        if ($p -eq $null) { continue }
        $k = "$p|$($r.N)"
        if ($seen.ContainsKey($k)) { continue }
        $seen[$k] = $true
        [void]$sb.AppendLine("#   diagnose sys cmdb refcnt show $p $($r.N)")
    }
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('#   A second opinion, recursive over the whole config:')
    [void]$sb.AppendLine('#     show | grep -f <object-name>')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# Step 3 - only if BOTH checks come back empty, run the block below.')
    [void]$sb.AppendLine('#   FortiOS refuses to delete an object that is still in use, so a')
    [void]$sb.AppendLine('#   missed reference gives "Return code -23", not an outage. Treat any')
    [void]$sb.AppendLine('#   such error as a finding: this tool got it wrong, stop and review.')
    [void]$sb.AppendLine('# --------------------------------------------------------------')
    [void]$sb.AppendLine('')

    $byV = @{}
    foreach ($r in $Recs) {
        $lst = $byV[$r.V]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byV[$r.V] = $lst }
        $lst.Add($r)
    }

    foreach ($v in ($byV.Keys | Sort-Object)) {
        foreach ($l in (Get-VdomOpen $v $VdomMode)) { [void]$sb.AppendLine($l) }

        $byS = @{}
        foreach ($r in $byV[$v]) {
            $lst = $byS[$r.S]
            if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byS[$r.S] = $lst }
            $lst.Add($r)
        }
        # groups first, so members are still free when their turn comes
        $order = $byS.Keys | Sort-Object @{e = { if ($script:GroupSet.ContainsKey($_)) { 0 } else { 1 } }}, @{e = { $_ }}

        foreach ($s in $order) {
            [void]$sb.AppendLine("config $s")
            foreach ($r in $byS[$s]) {
                if ($r.Val) { [void]$sb.AppendLine("    # $($r.N) = $($r.Val)") }
                [void]$sb.AppendLine("    delete `"$($r.N)`"")
            }
            [void]$sb.AppendLine('end')
        }
        foreach ($l in (Get-VdomClose $v $VdomMode)) { [void]$sb.AppendLine($l) }
        [void]$sb.AppendLine('')
    }
    return $sb.ToString()
}

function Build-DecideCli {
    param($Recs, [bool]$VdomMode, $UsedBy)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# --------------------------------------------------------------')
    [void]$sb.AppendLine('# Merging duplicates is NOT a safe bulk operation.')
    [void]$sb.AppendLine('# Every policy, group and route pointing at the object you drop must')
    [void]$sb.AppendLine('# be repointed at the keeper BEFORE the delete will succeed.')
    [void]$sb.AppendLine('# The deletes below are commented out on purpose.')
    [void]$sb.AppendLine('# --------------------------------------------------------------')
    [void]$sb.AppendLine('')

    foreach ($r in $Recs) {
        [void]$sb.AppendLine("# ===== $($r.C) : $($r.K)")
        [void]$sb.AppendLine("#   keep   : $($r.Keep)")
        [void]$sb.AppendLine("#   remove : $($r.Drop)")
        [void]$sb.AppendLine('#')
        foreach ($o in $r.DropObjs) {
            $p = $script:CmdbPath[$o.S]
            if ($p -ne $null) {
                [void]$sb.AppendLine("diagnose sys cmdb refcnt show $p $($o.N)")
            }
            $ub = $UsedBy[$o]
            if ($ub) { [void]$sb.AppendLine("#   config file shows it used by: $ub") }
            else { [void]$sb.AppendLine("#   config file shows no reference to $($o.N)") }
        }
        [void]$sb.AppendLine('#')
        [void]$sb.AppendLine('# once every reference points at the keeper:')
        $vd = ($r.DropObjs | ForEach-Object { $_.V }) | Sort-Object -Unique
        foreach ($v in $vd) {
            foreach ($l in (Get-VdomOpen $v $VdomMode)) { [void]$sb.AppendLine("#   $l") }
            $sec = @{}
            foreach ($o in $r.DropObjs) { if ($o.V -eq $v) { $sec[$o.S] = $true } }
            foreach ($s in ($sec.Keys | Sort-Object)) {
                [void]$sb.AppendLine("#   config $s")
                foreach ($o in $r.DropObjs) {
                    if ($o.V -eq $v -and $o.S -eq $s) {
                        [void]$sb.AppendLine("#       delete `"$($o.N)`"")
                    }
                }
                [void]$sb.AppendLine('#   end')
            }
            foreach ($l in (Get-VdomClose $v $VdomMode)) { [void]$sb.AppendLine("#   $l") }
        }
        [void]$sb.AppendLine('')
    }
    return $sb.ToString()
}

function Build-FixCli {
    param($Recs, [bool]$VdomMode)

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# --------------------------------------------------------------')
    [void]$sb.AppendLine('# Remediation for the selected findings.')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# Back up before changing anything:')
    [void]$sb.AppendLine('#   execute backup config tftp before-hardening.conf <tftp-server>')
    [void]$sb.AppendLine('#')
    [void]$sb.AppendLine('# Commented lines need a site specific value. Review every block: a')
    [void]$sb.AppendLine('# hardening change can drop the session you are typing it into, so')
    [void]$sb.AppendLine('# work from the console where possible.')
    [void]$sb.AppendLine('# --------------------------------------------------------------')
    [void]$sb.AppendLine('')

    $byZone = @{}
    foreach ($r in $Recs) {
        $lst = $byZone[$r.Zone]
        if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byZone[$r.Zone] = $lst }
        $lst.Add($r)
    }

    foreach ($z in ($byZone.Keys | Sort-Object)) {
        foreach ($l in (Get-VdomOpen $z $VdomMode)) { [void]$sb.AppendLine($l) }

        $byScope = @{}
        foreach ($r in $byZone[$z]) {
            $lst = $byScope[$r.Scope]
            if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byScope[$r.Scope] = $lst }
            $lst.Add($r)
        }

        foreach ($sc in ($byScope.Keys | Sort-Object)) {
            $byObj = @{}
            $sectRows = [System.Collections.Generic.List[object]]::new()
            foreach ($r in $byScope[$sc]) {
                if ($r.Obj -eq '') { $sectRows.Add($r); continue }
                $lst = $byObj[$r.Obj]
                if ($lst -eq $null) { $lst = [System.Collections.Generic.List[object]]::new(); $byObj[$r.Obj] = $lst }
                $lst.Add($r)
            }

            [void]$sb.AppendLine("config $sc")

            foreach ($r in $sectRows) {
                [void]$sb.AppendLine("    # $($r.Id)  $($r.Title)")
                if ($r.Detail) { [void]$sb.AppendLine("    # observed: $($r.Detail)") }
                foreach ($f in $r.Fix) { [void]$sb.AppendLine("    $f") }
            }

            foreach ($on in ($byObj.Keys | Sort-Object)) {
                [void]$sb.AppendLine("    edit `"$on`"")
                foreach ($r in $byObj[$on]) {
                    [void]$sb.AppendLine("        # $($r.Id)  $($r.Title)")
                    if ($r.Detail) { [void]$sb.AppendLine("        # observed: $($r.Detail)") }
                    foreach ($f in $r.Fix) { [void]$sb.AppendLine("        $f") }
                }
                [void]$sb.AppendLine('    next')
            }

            [void]$sb.AppendLine('end')
            [void]$sb.AppendLine('')
        }

        foreach ($l in (Get-VdomClose $z $VdomMode)) { [void]$sb.AppendLine($l) }
        [void]$sb.AppendLine('')
    }
    return $sb.ToString()
}

# =================================================================== NCM IMPORT + LINT

# Text rules exported from NCM style tools can be loaded for REVIEW. They are
# not executed here, because a wildcard that spans object boundaries reports
# compliant when it is not, and that failure direction is worse than a false
# alarm.

function Import-TextRules {
    param([string]$Folder)

    $out = [System.Collections.Generic.List[object]]::new()
    if (-not (Test-Path -LiteralPath $Folder)) { return $out }

    foreach ($f in (Get-ChildItem -LiteralPath $Folder -Filter *.xml -File)) {
        try { $xml = [xml](Get-Content -LiteralPath $f.FullName -Raw) } catch { continue }
        foreach ($n in $xml.SelectNodes('//PolicyRule')) {
            $out.Add(@{
                File    = $f.Name
                Name    = [string]$n.RuleName
                Group   = [string]$n.Grouping
                Pattern = [string]$n.SimplePatternText
                PType   = [string]$n.PatternType
                Must    = [string]$n.PatternMustExist
                BlkS    = [string]$n.ConfigBlockStart
                BlkE    = [string]$n.ConfigBlockEnd
                BlkMust = [string]$n.ConfigBlockMustExist
                Level   = [string]$n.ErrorLevel
                Owner   = [string]$n.Owner
            })
        }
    }
    return $out
}

function Lint-TextRules {
    param($Rules)

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $Rules) {

        $p = $r.Pattern
        $issues = [System.Collections.Generic.List[object]]::new()

        $unbounded = $false
        foreach ($w in @('(.|\n)*', '(.|\r\n)*', '[\s\S]*', '(?s).*')) {
            if ($p -and $p.Contains($w)) { $unbounded = $true }
        }

        $editCount = 0
        if ($p) { $editCount = ([regex]::Matches($p, 'edit\s')).Count }

        if ($unbounded -and [string]::IsNullOrWhiteSpace($r.BlkS)) {
            $issues.Add(@{
                Sev = 'critical'
                Text = 'Unbounded wildcard with no config block. The match can cross into the next object, so a setting belonging to a different entry satisfies the rule. Fails toward "compliant".'
                Hint = 'Set ConfigBlockStart to the entry, ConfigBlockEnd to next, ConfigBlockMustExist to true, and reduce the pattern to the setting alone.'
            })
        }
        if ($editCount -ge 2 -and $unbounded) {
            $issues.Add(@{
                Sev = 'critical'
                Text = 'Pattern anchors on one entry then searches forward for a setting. Any later entry carrying that setting will satisfy it.'
                Hint = 'Split into a config block plus a single setting pattern.'
            })
        }
        if ($r.Must -eq 'true' -and $r.BlkMust -eq 'false' -and -not [string]::IsNullOrWhiteSpace($r.BlkS)) {
            $issues.Add(@{
                Sev = 'high'
                Text = 'Pattern must exist, but the block is not required. If the block is absent the rule passes silently instead of flagging the missing configuration.'
                Hint = 'Set ConfigBlockMustExist to true.'
            })
        }
        if ([string]::IsNullOrWhiteSpace($p)) {
            $issues.Add(@{ Sev = 'high'; Text = 'Empty pattern. The rule evaluates nothing.'; Hint = '' })
        }
        if ($r.PType -eq 'Regex' -and $p) {
            try { [void][regex]::new($p) }
            catch {
                $issues.Add(@{ Sev = 'high'; Text = "Invalid regular expression: $($_.Exception.Message)"; Hint = '' })
            }
        }
        if ($p -and $p.EndsWith(' ')) {
            $issues.Add(@{
                Sev = 'low'
                Text = 'Pattern ends with a space. Harmless in most engines but easy to break when edited.'
                Hint = ''
            })
        }

        if ($issues.Count -eq 0) {
            $issues.Add(@{
                Sev = 'ok'
                Text = 'No structural problem detected. Text matching still cannot tell a factory default from an omitted setting.'
                Hint = ''
            })
        }

        foreach ($i in $issues) {
            $out.Add(@{
                File = $r.File; Name = $r.Name; Group = $r.Group
                Sev = $i.Sev; Text = $i.Text; Hint = $i.Hint; Pattern = $p
            })
        }
    }
    return $out
}
