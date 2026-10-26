BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../src/NuGetAudit.psm1') -Force
    $script:Root = 'C:/git/nuget-audit-action/test/fixtures/sample'
    $script:SampleJson = Get-Content -Raw (Join-Path $PSScriptRoot 'fixtures/list-package-sample.json')
    $script:Today = [datetime]'2026-10-26'

    function New-SuppressionFile([object[]] $Entries) {
        $path = Join-Path $TestDrive ([guid]::NewGuid().ToString() + '.json')
        @{ suppressions = $Entries } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $path
        $path
    }
}

Describe 'ConvertFrom-ListPackageJson' {
    It 'returns one finding per project, package and advisory' {
        $result = ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root

        $result.Findings.Count | Should -Be 13
        $result.Problems.Count | Should -Be 0
    }

    It 'makes project paths relative to the root' {
        $result = ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root

        $result.Findings.Project | Sort-Object -Unique | Should -Be @('App/App.csproj', 'Lib/Lib.csproj')
    }

    It 'marks direct and transitive references' {
        $result = ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root
        $app = $result.Findings | Where-Object Project -eq 'App/App.csproj'

        ($app | Where-Object Package -eq 'Newtonsoft.Json').Transitive | Should -BeFalse
        ($app | Where-Object Package -eq 'Microsoft.Extensions.Caching.Memory').Transitive | Should -BeTrue
    }

    It 'extracts the advisory id from the url' {
        $result = ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root
        $finding = $result.Findings | Where-Object Package -eq 'Newtonsoft.Json'

        $finding.AdvisoryId | Should -Be 'GHSA-5CRP-9R3C-P9VR'
        $finding.Severity | Should -Be 'High'
        $finding.Version | Should -Be '12.0.1'
    }

    It 'merges frameworks of a multi-targeted project into one finding' {
        $json = @{
            version  = 1
            projects = @(@{
                path       = "$Root/Multi/Multi.csproj"
                frameworks = @('net8.0', 'net10.0' | ForEach-Object {
                    @{
                        framework        = $_
                        topLevelPackages = @(@{ id = 'Pkg'; resolvedVersion = '1.0.0'; vulnerabilities = @(@{ severity = 'Critical'; advisoryurl = 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' }) })
                    }
                })
            })
        } | ConvertTo-Json -Depth 10

        $result = ConvertFrom-ListPackageJson -Json $json -Root $Root

        $result.Findings.Count | Should -Be 1
        $result.Findings[0].Frameworks | Should -Be @('net8.0', 'net10.0')
    }

    It 'returns nothing for a clean project' {
        $json = '{ "version": 1, "projects": [ { "path": "C:/x/clean.csproj" } ] }'

        $result = ConvertFrom-ListPackageJson -Json $json

        $result.Findings.Count | Should -Be 0
    }

    It 'collects problems from the document and its projects' {
        $json = '{ "version": 1, "problems": [ { "level": "warning", "text": "source down" } ], "projects": [ { "path": "C:/x/a.csproj", "problems": [ { "level": "error", "text": "No assets file" } ] } ] }'

        $result = ConvertFrom-ListPackageJson -Json $json

        $result.Problems.Count | Should -Be 2
        ($result.Problems | Where-Object Level -eq 'error').Project | Should -Be 'C:/x/a.csproj'
    }
}

Describe 'Read-SuppressionFile' {
    It 'returns nothing when the file is missing' {
        $result = Read-SuppressionFile -Path (Join-Path $TestDrive 'missing.json') -Today $Today

        $result.Suppressions.Count | Should -Be 0
        $result.Errors.Count | Should -Be 0
    }

    It 'accepts a GHSA id or an advisory url' {
        $path = New-SuppressionFile @(
            @{ advisory = 'GHSA-5crp-9r3c-p9vr'; until = '2026-11-30'; reason = 'r' },
            @{ advisory = 'https://github.com/advisories/GHSA-qj66-m88j-hmgj'; until = '2026-11-30'; reason = 'r' }
        )

        $result = Read-SuppressionFile -Path $path -Today $Today

        $result.Suppressions.AdvisoryId | Should -Be @('GHSA-5CRP-9R3C-P9VR', 'GHSA-QJ66-M88J-HMGJ')
    }

    It 'rejects entries without until or reason' {
        $path = New-SuppressionFile @(
            @{ advisory = 'GHSA-1'; reason = 'r' },
            @{ advisory = 'GHSA-2'; until = '2026-11-30' },
            @{ advisory = 'GHSA-3'; until = '30/11/2026'; reason = 'r' }
        )

        $result = Read-SuppressionFile -Path $path -Today $Today

        $result.Suppressions.Count | Should -Be 0
        $result.Errors.Count | Should -Be 3
    }

    It 'rejects an until date beyond the maximum' {
        $path = New-SuppressionFile @(@{ advisory = 'GHSA-1'; until = '2027-06-01'; reason = 'r' })

        $result = Read-SuppressionFile -Path $path -Today $Today -MaxDays 90

        $result.Errors | Should -Match 'more than 90 days'
    }

    It 'marks past dates as expired and keeps today active' {
        $path = New-SuppressionFile @(
            @{ advisory = 'GHSA-1'; until = '2026-10-25'; reason = 'r' },
            @{ advisory = 'GHSA-2'; until = '2026-10-26'; reason = 'r' }
        )

        $result = Read-SuppressionFile -Path $path -Today $Today

        $result.Suppressions.Expired | Should -Be @($true, $false)
    }

    It 'reports invalid json' {
        $path = Join-Path $TestDrive 'broken.json'
        Set-Content -LiteralPath $path -Value '{ "suppressions": ['

        $result = Read-SuppressionFile -Path $path -Today $Today

        $result.Errors | Should -Match 'Cannot parse'
    }
}

Describe 'Resolve-Finding' {
    BeforeEach {
        $script:Findings = (ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root).Findings
    }

    It 'fails every unsuppressed finding at the lowest threshold' {
        $result = Resolve-Finding -Findings $Findings -FailSeverity low

        @($result | Where-Object Fails).Count | Should -Be 13
    }

    It 'only fails findings at or above the threshold' {
        $result = Resolve-Finding -Findings $Findings -FailSeverity high

        @($result | Where-Object Fails).Severity | Sort-Object -Unique | Should -Be 'High'
        @($result | Where-Object { -not $_.Fails }).Count | Should -Be 8
    }

    It 'suppresses an advisory in every project' {
        $path = New-SuppressionFile @(@{ advisory = 'GHSA-qj66-m88j-hmgj'; until = '2026-11-30'; reason = 'no fix yet' })
        $suppressions = (Read-SuppressionFile -Path $path -Today $Today).Suppressions

        $result = Resolve-Finding -Findings $Findings -Suppressions $suppressions -FailSeverity low

        $suppressed = @($result | Where-Object Status -eq 'Suppressed')
        $suppressed.Count | Should -Be 2
        $suppressed.Fails | Should -Not -Contain $true
        $suppressions[0].Used | Should -BeTrue
    }

    It 'limits a suppression to the listed package and projects' {
        $path = New-SuppressionFile @(@{ advisory = 'GHSA-m5vv-6r4h-3vj9'; package = 'Azure.Identity'; projects = @('Lib/Lib.csproj'); until = '2026-11-30'; reason = 'r' })
        $suppressions = (Read-SuppressionFile -Path $path -Today $Today).Suppressions

        $result = Resolve-Finding -Findings $Findings -Suppressions $suppressions -FailSeverity low

        $suppressed = @($result | Where-Object Status -eq 'Suppressed')
        $suppressed.Count | Should -Be 1
        $suppressed[0].Project | Should -Be 'Lib/Lib.csproj'
        $suppressed[0].Package | Should -Be 'Azure.Identity'
    }

    It 'reactivates findings whose suppression expired' {
        $path = New-SuppressionFile @(@{ advisory = 'GHSA-5crp-9r3c-p9vr'; until = '2026-10-01'; reason = 'r' })
        $suppressions = (Read-SuppressionFile -Path $path -Today $Today).Suppressions

        $result = Resolve-Finding -Findings $Findings -Suppressions $suppressions -FailSeverity low

        $finding = $result | Where-Object Package -eq 'Newtonsoft.Json'
        $finding.Status | Should -Be 'Expired'
        $finding.Fails | Should -BeTrue
    }

    It 'prefers an active suppression over an expired one' {
        $path = New-SuppressionFile @(
            @{ advisory = 'GHSA-5crp-9r3c-p9vr'; until = '2026-10-01'; reason = 'old' },
            @{ advisory = 'GHSA-5crp-9r3c-p9vr'; until = '2026-12-01'; reason = 'new' }
        )
        $suppressions = (Read-SuppressionFile -Path $path -Today $Today).Suppressions

        $result = Resolve-Finding -Findings $Findings -Suppressions $suppressions -FailSeverity low

        ($result | Where-Object Package -eq 'Newtonsoft.Json').Status | Should -Be 'Suppressed'
    }
}

Describe 'Format-AuditReport' {
    BeforeAll {
        $path = New-SuppressionFile @(
            @{ advisory = 'GHSA-qj66-m88j-hmgj'; until = '2026-11-30'; reason = 'waiting | for fix' },
            @{ advisory = 'GHSA-zzzz-zzzz-zzzz'; until = '2026-11-30'; reason = 'gone' }
        )
        $script:Suppressions = (Read-SuppressionFile -Path $path -Today $Today).Suppressions
        $findings = (ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root).Findings
        $script:Resolved = Resolve-Finding -Findings $findings -Suppressions $Suppressions -FailSeverity moderate
        $script:Report = Format-AuditReport -Findings $Resolved -Suppressions $Suppressions -FailSeverity moderate -SuppressionFile '.github/nuget-audit-suppressions.json' -Target 'Sample.slnx'
    }

    It 'shows the verdict and counts' {
        $Report | Should -Match ':x: \*\*Failed\*\*'
        $Report | Should -Match '\| 11 \| 9 \| 2 \| `Sample.slnx` \|'
    }

    It 'lists each vulnerable package with its project and advisory link' {
        $Report | Should -Match '\| High \| Newtonsoft.Json \| 12.0.1 \| direct \| `App/App.csproj` \| net10.0 \| \[GHSA-5CRP-9R3C-P9VR\]\(https://github.com/advisories/GHSA-5crp-9r3c-p9vr\) \|  \|'
        $Report | Should -Match '\| Low \| Microsoft.Identity.Client \| 4.54.1 \| transitive \| `App/App.csproj` .* below threshold \|'
    }

    It 'lists suppressed findings with until and escaped reason' {
        $Report | Should -Match '### Suppressed'
        $Report | Should -Match '\| 2026-11-30 \| waiting \\\| for fix \|'
    }

    It 'lists unused suppressions' {
        $Report | Should -Match '### Unused suppressions'
        $Report | Should -Match 'GHSA-ZZZZ-ZZZZ-ZZZZ, until 2026-11-30'
    }

    It 'passes when nothing is found' {
        $report = Format-AuditReport -FailSeverity low -Target '.'

        $report | Should -Match ':white_check_mark: \*\*Passed\*\*'
        $report | Should -Not -Match '### Vulnerable packages'
    }
}

Describe 'Format-Annotation' {
    It 'writes an error per failing finding with the package line for direct references' {
        $projectDir = Join-Path $TestDrive 'App'
        New-Item -ItemType Directory -Path $projectDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $projectDir 'App.csproj') -Value @('<Project>', '  <ItemGroup>', '    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />', '  </ItemGroup>', '</Project>')
        $findings = (ConvertFrom-ListPackageJson -Json $SampleJson -Root $Root).Findings | Where-Object Project -eq 'App/App.csproj'
        $resolved = Resolve-Finding -Findings $findings -FailSeverity high

        $lines = @(Format-Annotation -Findings $resolved -SuppressionFile 's.json' -Root $TestDrive)

        $lines | Should -Contain '::error file=App/App.csproj,line=3,title=High vulnerability in Newtonsoft.Json 12.0.1::Newtonsoft.Json 12.0.1 (direct) is affected by https://github.com/advisories/GHSA-5crp-9r3c-p9vr'
        @($lines | Where-Object { $_ -like '::warning *' }).Count | Should -Be 4
    }

    It 'writes errors for invalid suppressions and notices for unused ones' {
        $unused = [pscustomobject]@{ AdvisoryId = 'GHSA-1'; Used = $false }

        $lines = @(Format-Annotation -Suppressions @($unused) -SuppressionErrors @('bad: entry') -SuppressionFile '.github/s.json')

        $lines[0] | Should -Be '::error file=.github/s.json,title=Invalid NuGet audit suppression::bad: entry'
        $lines[1] | Should -BeLike '::notice file=.github/s.json,title=Unused NuGet audit suppression::GHSA-1 *'
    }
}
