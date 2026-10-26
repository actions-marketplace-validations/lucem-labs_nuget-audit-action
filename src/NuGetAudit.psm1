Set-StrictMode -Version Latest

$script:SeverityRank = @{ low = 1; moderate = 2; high = 3; critical = 4 }

function Get-SeverityRank {
    param([Parameter(Mandatory)][string] $Severity)

    $key = $Severity.Trim().ToLowerInvariant()
    if (-not $script:SeverityRank.ContainsKey($key)) {
        throw "Unknown severity '$Severity'. Use one of: low, moderate, high, critical."
    }
    $script:SeverityRank[$key]
}

function Get-AdvisoryId {
    param([Parameter(Mandatory)][string] $Advisory)

    $Advisory.Trim().TrimEnd('/').Split('/')[-1].ToUpperInvariant()
}

function Get-RelativePath {
    param(
        [Parameter(Mandatory)][string] $Path,
        [string] $Root
    )

    $normalized = $Path -replace '\\', '/'
    if (-not $Root) { return $normalized }
    $relative = [System.IO.Path]::GetRelativePath($Root, $Path) -replace '\\', '/'
    if ($relative.StartsWith('../') -or [System.IO.Path]::IsPathRooted($relative)) { return $normalized }
    $relative
}

function Get-OptionalProperty {
    param($Object, [string] $Name)

    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) { $Object.$Name }
}

function ConvertFrom-ListPackageJson {
    param(
        [Parameter(Mandatory)][string] $Json,
        [string] $Root
    )

    $document = $Json | ConvertFrom-Json
    $findings = [System.Collections.Generic.List[object]]::new()
    $problems = [System.Collections.Generic.List[object]]::new()

    foreach ($problem in @(Get-OptionalProperty $document 'problems')) {
        if ($null -eq $problem) { continue }
        $problems.Add([pscustomobject]@{
            Level   = [string](Get-OptionalProperty $problem 'level')
            Text    = [string](Get-OptionalProperty $problem 'text')
            Project = [string](Get-OptionalProperty $problem 'project')
        })
    }

    foreach ($project in @(Get-OptionalProperty $document 'projects')) {
        if ($null -eq $project) { continue }
        $projectPath = Get-RelativePath -Path $project.path -Root $Root

        foreach ($problem in @(Get-OptionalProperty $project 'problems')) {
            if ($null -eq $problem) { continue }
            $problems.Add([pscustomobject]@{
                Level   = [string](Get-OptionalProperty $problem 'level')
                Text    = [string](Get-OptionalProperty $problem 'text')
                Project = $projectPath
            })
        }

        foreach ($framework in @(Get-OptionalProperty $project 'frameworks')) {
            if ($null -eq $framework) { continue }
            $groups = @(
                @{ Packages = Get-OptionalProperty $framework 'topLevelPackages'; Transitive = $false },
                @{ Packages = Get-OptionalProperty $framework 'transitivePackages'; Transitive = $true }
            )
            foreach ($group in $groups) {
                foreach ($package in @($group.Packages)) {
                    if ($null -eq $package) { continue }
                    foreach ($vulnerability in @(Get-OptionalProperty $package 'vulnerabilities')) {
                        if ($null -eq $vulnerability) { continue }
                        $existing = $findings | Where-Object {
                            $_.Project -eq $projectPath -and
                            $_.Package -eq $package.id -and
                            $_.Version -eq $package.resolvedVersion -and
                            $_.AdvisoryUrl -eq $vulnerability.advisoryurl
                        } | Select-Object -First 1
                        if ($existing) {
                            if ($existing.Frameworks -notcontains $framework.framework) {
                                $existing.Frameworks += $framework.framework
                            }
                            continue
                        }
                        $findings.Add([pscustomobject]@{
                            Project     = $projectPath
                            Package     = [string]$package.id
                            Version     = [string]$package.resolvedVersion
                            Transitive  = $group.Transitive
                            Severity    = (Get-Culture).TextInfo.ToTitleCase(([string]$vulnerability.severity).ToLowerInvariant())
                            AdvisoryUrl = [string]$vulnerability.advisoryurl
                            AdvisoryId  = Get-AdvisoryId $vulnerability.advisoryurl
                            Frameworks  = @([string]$framework.framework)
                        })
                    }
                }
            }
        }
    }

    [pscustomobject]@{ Findings = $findings.ToArray(); Problems = $problems.ToArray() }
}

function Read-SuppressionFile {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][datetime] $Today,
        [int] $MaxDays = 0
    )

    $result = [pscustomobject]@{ Suppressions = @(); Errors = @() }
    if (-not (Test-Path -LiteralPath $Path)) { return $result }

    try {
        $document = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    }
    catch {
        $result.Errors = @("Cannot parse $Path as JSON: $($_.Exception.Message)")
        return $result
    }

    $suppressions = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    $entries = @(Get-OptionalProperty $document 'suppressions')
    for ($index = 0; $index -lt $entries.Count; $index++) {
        $entry = $entries[$index]
        if ($null -eq $entry) { continue }
        $label = "suppressions[$index]"
        $advisory = [string](Get-OptionalProperty $entry 'advisory')
        $until = [string](Get-OptionalProperty $entry 'until')
        $reason = [string](Get-OptionalProperty $entry 'reason')

        if (-not $advisory) { $errors.Add("${label}: 'advisory' is required (GHSA id or advisory URL)."); continue }
        $label = "$label ($advisory)"
        if (-not $reason) { $errors.Add("${label}: 'reason' is required."); continue }
        $untilDate = [datetime]::MinValue
        if (-not [datetime]::TryParseExact($until, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, 'None', [ref]$untilDate)) {
            $errors.Add("${label}: 'until' is required and must be a date in yyyy-MM-dd format.")
            continue
        }
        if ($MaxDays -gt 0 -and $untilDate -gt $Today.Date.AddDays($MaxDays)) {
            $errors.Add("${label}: 'until' $until is more than $MaxDays days away. Pick an earlier date and review it then.")
            continue
        }

        $suppressions.Add([pscustomobject]@{
            Index      = $index
            AdvisoryId = Get-AdvisoryId $advisory
            Package    = [string](Get-OptionalProperty $entry 'package')
            Projects   = @(Get-OptionalProperty $entry 'projects' | Where-Object { $_ } | ForEach-Object { ([string]$_) -replace '\\', '/' })
            Until      = $untilDate
            Reason     = $reason
            Expired    = $untilDate -lt $Today.Date
            Used       = $false
        })
    }

    $result.Suppressions = $suppressions.ToArray()
    $result.Errors = $errors.ToArray()
    $result
}

function Test-SuppressionMatch {
    param($Suppression, $Finding)

    if ($Suppression.AdvisoryId -ne $Finding.AdvisoryId) { return $false }
    if ($Suppression.Package -and $Suppression.Package -ne $Finding.Package) { return $false }
    if ($Suppression.Projects.Count -gt 0 -and $Suppression.Projects -notcontains $Finding.Project) { return $false }
    $true
}

function Resolve-Finding {
    param(
        [object[]] $Findings = @(),
        [object[]] $Suppressions = @(),
        [Parameter(Mandatory)][string] $FailSeverity
    )

    $threshold = Get-SeverityRank $FailSeverity
    foreach ($finding in $Findings) {
        $match = $Suppressions | Where-Object { Test-SuppressionMatch $_ $finding } |
            Sort-Object Expired |
            Select-Object -First 1
        $status = 'Active'
        if ($match) {
            $match.Used = $true
            $status = if ($match.Expired) { 'Expired' } else { 'Suppressed' }
        }
        $finding | Add-Member -NotePropertyName Status -NotePropertyValue $status -Force
        $finding | Add-Member -NotePropertyName Suppression -NotePropertyValue $match -Force
        $finding | Add-Member -NotePropertyName Fails -NotePropertyValue ($status -ne 'Suppressed' -and (Get-SeverityRank $finding.Severity) -ge $threshold) -Force
    }
    $Findings
}

function Format-MarkdownCell {
    param([string] $Text)

    ($Text -replace '\|', '\|') -replace '\r?\n', ' '
}

function Format-AuditReport {
    param(
        [object[]] $Findings = @(),
        [object[]] $Suppressions = @(),
        [object[]] $Problems = @(),
        [string[]] $SuppressionErrors = @(),
        [Parameter(Mandatory)][string] $FailSeverity,
        [string] $SuppressionFile,
        [string] $Target
    )

    $active = @($Findings | Where-Object Status -ne 'Suppressed' |
        Sort-Object @{ Expression = { Get-SeverityRank $_.Severity }; Descending = $true }, Project, Package, AdvisoryId)
    $suppressed = @($Findings | Where-Object Status -eq 'Suppressed' | Sort-Object Project, Package, AdvisoryId)
    $failing = @($active | Where-Object Fails)
    $unused = @($Suppressions | Where-Object { -not $_.Used })
    $errors = @($Problems | Where-Object Level -eq 'error')

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add('## NuGet vulnerability audit')
    $lines.Add('')

    $verdict = if ($failing.Count -gt 0 -or $errors.Count -gt 0 -or $SuppressionErrors.Count -gt 0) { ':x: **Failed**' }
        elseif ($active.Count -gt 0) { ':warning: **Passed with findings below the failure threshold**' }
        else { ':white_check_mark: **Passed**' }
    $lines.Add($verdict)
    $lines.Add('')
    $lines.Add("| Active | Failing (>= $FailSeverity) | Suppressed | Scanned |")
    $lines.Add('|---:|---:|---:|---|')
    $lines.Add("| $($active.Count) | $($failing.Count) | $($suppressed.Count) | ``$(Format-MarkdownCell $Target)`` |")
    $lines.Add('')

    if ($SuppressionErrors.Count -gt 0) {
        $lines.Add("### Invalid suppressions in ``$SuppressionFile``")
        $lines.Add('')
        foreach ($message in $SuppressionErrors) { $lines.Add("- $message") }
        $lines.Add('')
    }

    if ($Problems.Count -gt 0) {
        $lines.Add('### Problems reported by `dotnet list package`')
        $lines.Add('')
        foreach ($problem in $Problems) {
            $where = if ($problem.Project) { " (``$($problem.Project)``)" } else { '' }
            $lines.Add("- **$($problem.Level)**${where}: $(Format-MarkdownCell $problem.Text)")
        }
        $lines.Add('')
    }

    if ($active.Count -gt 0) {
        $lines.Add('### Vulnerable packages')
        $lines.Add('')
        $lines.Add('| Severity | Package | Version | Reference | Project | Frameworks | Advisory | Note |')
        $lines.Add('|---|---|---|---|---|---|---|---|')
        foreach ($finding in $active) {
            $reference = if ($finding.Transitive) { 'transitive' } else { 'direct' }
            $note = if ($finding.Status -eq 'Expired') { "suppression expired $($finding.Suppression.Until.ToString('yyyy-MM-dd'))" }
                elseif (-not $finding.Fails) { 'below threshold' }
                else { '' }
            $lines.Add("| $($finding.Severity) | $($finding.Package) | $($finding.Version) | $reference | ``$($finding.Project)`` | $($finding.Frameworks -join ', ') | [$($finding.AdvisoryId)]($($finding.AdvisoryUrl)) | $note |")
        }
        $lines.Add('')
        $lines.Add("To silence a finding until the maintainer ships a fix, add it to ``$SuppressionFile`` with an ``until`` date and a ``reason``.")
        $lines.Add('')
    }

    if ($suppressed.Count -gt 0) {
        $lines.Add('### Suppressed')
        $lines.Add('')
        $lines.Add('| Severity | Package | Version | Project | Advisory | Until | Reason |')
        $lines.Add('|---|---|---|---|---|---|---|')
        foreach ($finding in $suppressed) {
            $lines.Add("| $($finding.Severity) | $($finding.Package) | $($finding.Version) | ``$($finding.Project)`` | [$($finding.AdvisoryId)]($($finding.AdvisoryUrl)) | $($finding.Suppression.Until.ToString('yyyy-MM-dd')) | $(Format-MarkdownCell $finding.Suppression.Reason) |")
        }
        $lines.Add('')
    }

    if ($unused.Count -gt 0) {
        $lines.Add('### Unused suppressions')
        $lines.Add('')
        $lines.Add('These entries match no current finding and can be removed:')
        $lines.Add('')
        foreach ($suppression in $unused) {
            $scope = @($suppression.Package) + $suppression.Projects | Where-Object { $_ }
            $suffix = if ($scope) { " ($($scope -join ', '))" } else { '' }
            $lines.Add("- $($suppression.AdvisoryId)$suffix, until $($suppression.Until.ToString('yyyy-MM-dd'))")
        }
        $lines.Add('')
    }

    $lines -join "`n"
}

function Format-WorkflowCommandValue {
    param([string] $Text, [switch] $Property)

    $escaped = $Text -replace '%', '%25' -replace "`r", '%0D' -replace "`n", '%0A'
    if ($Property) { $escaped = $escaped -replace ':', '%3A' -replace ',', '%2C' }
    $escaped
}

function Find-PackageLine {
    param([string] $ProjectFile, [string] $Package)

    if (-not $ProjectFile -or -not (Test-Path -LiteralPath $ProjectFile)) { return $null }
    $pattern = 'Include\s*=\s*"' + [regex]::Escape($Package) + '"'
    $match = Select-String -LiteralPath $ProjectFile -Pattern $pattern | Select-Object -First 1
    if ($match) { $match.LineNumber }
}

function Format-Annotation {
    param(
        [object[]] $Findings = @(),
        [object[]] $Suppressions = @(),
        [object[]] $Problems = @(),
        [string[]] $SuppressionErrors = @(),
        [string] $SuppressionFile,
        [string] $Root
    )

    foreach ($message in $SuppressionErrors) {
        "::error file=$(Format-WorkflowCommandValue $SuppressionFile -Property),title=Invalid NuGet audit suppression::$(Format-WorkflowCommandValue $message)"
    }

    foreach ($problem in $Problems) {
        $level = if ($problem.Level -eq 'error') { 'error' } else { 'warning' }
        $file = if ($problem.Project) { "file=$(Format-WorkflowCommandValue $problem.Project -Property)," } else { '' }
        "::$level ${file}title=dotnet list package::$(Format-WorkflowCommandValue $problem.Text)"
    }

    foreach ($finding in $Findings | Where-Object Status -ne 'Suppressed') {
        $level = if ($finding.Fails) { 'error' } else { 'warning' }
        $reference = if ($finding.Transitive) { 'transitive' } else { 'direct' }
        $location = "file=$(Format-WorkflowCommandValue $finding.Project -Property)"
        if (-not $finding.Transitive) {
            $projectFile = if ($Root) { Join-Path $Root $finding.Project } else { $finding.Project }
            $line = Find-PackageLine -ProjectFile $projectFile -Package $finding.Package
            if ($line) { $location += ",line=$line" }
        }
        $title = "$($finding.Severity) vulnerability in $($finding.Package) $($finding.Version)"
        $message = "$($finding.Package) $($finding.Version) ($reference) is affected by $($finding.AdvisoryUrl)"
        if ($finding.Status -eq 'Expired') { $message += " - suppression expired on $($finding.Suppression.Until.ToString('yyyy-MM-dd'))" }
        "::$level $location,title=$(Format-WorkflowCommandValue $title -Property)::$(Format-WorkflowCommandValue $message)"
    }

    foreach ($suppression in $Suppressions | Where-Object { -not $_.Used }) {
        "::notice file=$(Format-WorkflowCommandValue $SuppressionFile -Property),title=Unused NuGet audit suppression::$(Format-WorkflowCommandValue "$($suppression.AdvisoryId) matches no current finding and can be removed.")"
    }
}

Export-ModuleMember -Function ConvertFrom-ListPackageJson, Read-SuppressionFile, Resolve-Finding, Format-AuditReport, Format-Annotation, Get-SeverityRank, Get-AdvisoryId
