[CmdletBinding()]
param(
    [string] $Target = '.',
    [string] $SuppressionFile = '.github/nuget-audit-suppressions.json',
    [string] $FailSeverity = 'low',
    [string] $FailOnVulnerable = 'true',
    [string] $IncludeTransitive = 'true',
    [string] $Restore = 'true',
    [int] $MaxSuppressionDays = 90,
    [string] $ListArguments = '',
    [string] $Root = $(if ($env:GITHUB_WORKSPACE) { $env:GITHUB_WORKSPACE } else { (Get-Location).Path }),
    [string] $OutputDirectory = $(if ($env:RUNNER_TEMP) { Join-Path $env:RUNNER_TEMP 'nuget-audit' } else { Join-Path (Get-Location).Path 'nuget-audit' }),
    [datetime] $Today = [datetime]::UtcNow.Date
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'NuGetAudit.psm1') -Force

function Test-Truthy([string] $Value) { $Value.Trim().ToLowerInvariant() -in @('true', '1', 'yes') }

function Write-GitHubFile([string] $Variable, [string[]] $Lines) {
    $path = [Environment]::GetEnvironmentVariable($Variable)
    if ($path) { Add-Content -LiteralPath $path -Value $Lines -Encoding utf8 }
}

$null = Get-SeverityRank $FailSeverity
$Root = (Resolve-Path -LiteralPath $Root).Path
$targetPath = if ([System.IO.Path]::IsPathRooted($Target)) { $Target } else { Join-Path $Root $Target }
$suppressionPath = if ([System.IO.Path]::IsPathRooted($SuppressionFile)) { $SuppressionFile } else { Join-Path $Root $SuppressionFile }
$suppressionDisplay = ([System.IO.Path]::GetRelativePath($Root, $suppressionPath)) -replace '\\', '/'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

if (Test-Truthy $Restore) {
    Write-Host "::group::dotnet restore $Target"
    & dotnet restore $targetPath -p:NuGetAudit=false
    $restoreExit = $LASTEXITCODE
    Write-Host '::endgroup::'
    if ($restoreExit -ne 0) {
        Write-Host "::error title=NuGet audit::dotnet restore failed with exit code $restoreExit."
        exit $restoreExit
    }
}

$listArgs = @('list', $targetPath, 'package', '--vulnerable', '--format', 'json', '--output-version', '1')
if (Test-Truthy $IncludeTransitive) { $listArgs += '--include-transitive' }
if ($ListArguments.Trim()) { $listArgs += $ListArguments.Trim() -split '\s+' }

Write-Host "::group::dotnet $($listArgs -join ' ')"
$listOutput = & dotnet @listArgs
$listExit = $LASTEXITCODE
$json = ($listOutput | ForEach-Object { "$_" }) -join "`n"
Write-Host $json
Write-Host '::endgroup::'

$jsonStart = $json.IndexOf('{')
if ($listExit -ne 0 -or $jsonStart -lt 0) {
    Write-Host "::error title=NuGet audit::dotnet list package failed with exit code $listExit. See the step log for details."
    exit $(if ($listExit -ne 0) { $listExit } else { 1 })
}
$json = $json.Substring($jsonStart)
$rawPath = Join-Path $OutputDirectory 'dotnet-list-package.json'
Set-Content -LiteralPath $rawPath -Value $json -Encoding utf8

$parsed = ConvertFrom-ListPackageJson -Json $json -Root $Root
$suppressionResult = Read-SuppressionFile -Path $suppressionPath -Today $Today -MaxDays $MaxSuppressionDays
$findings = @(Resolve-Finding -Findings $parsed.Findings -Suppressions $suppressionResult.Suppressions -FailSeverity $FailSeverity)

$reportArgs = @{
    Findings          = $findings
    Suppressions      = $suppressionResult.Suppressions
    Problems          = $parsed.Problems
    SuppressionErrors = $suppressionResult.Errors
    SuppressionFile   = $suppressionDisplay
}
$report = Format-AuditReport @reportArgs -FailSeverity $FailSeverity -Target $Target
$reportPath = Join-Path $OutputDirectory 'nuget-audit-report.md'
Set-Content -LiteralPath $reportPath -Value $report -Encoding utf8

$resultPath = Join-Path $OutputDirectory 'nuget-audit-findings.json'
$findings | Select-Object Project, Package, Version, Transitive, Severity, AdvisoryId, AdvisoryUrl, Frameworks, Status, Fails,
    @{ Name = 'SuppressedUntil'; Expression = { if ($_.Suppression) { $_.Suppression.Until.ToString('yyyy-MM-dd') } } },
    @{ Name = 'SuppressionReason'; Expression = { if ($_.Suppression) { $_.Suppression.Reason } } } |
    ConvertTo-Json -AsArray -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding utf8

Format-Annotation @reportArgs -Root $Root | ForEach-Object { Write-Host $_ }
Write-GitHubFile 'GITHUB_STEP_SUMMARY' @($report)

$active = @($findings | Where-Object Status -ne 'Suppressed')
$suppressed = @($findings | Where-Object Status -eq 'Suppressed')
$failing = @($active | Where-Object Fails)
$problemErrors = @($parsed.Problems | Where-Object Level -eq 'error')

Write-GitHubFile 'GITHUB_OUTPUT' @(
    "vulnerable-count=$($active.Count)",
    "failing-count=$($failing.Count)",
    "suppressed-count=$($suppressed.Count)",
    "report-path=$reportPath",
    "findings-path=$resultPath"
)

Write-Host "Active: $($active.Count), failing (>= $FailSeverity): $($failing.Count), suppressed: $($suppressed.Count). Report: $reportPath"

if ($suppressionResult.Errors.Count -gt 0 -or $problemErrors.Count -gt 0) { exit 1 }
if ($failing.Count -gt 0 -and (Test-Truthy $FailOnVulnerable)) { exit 1 }
exit 0
