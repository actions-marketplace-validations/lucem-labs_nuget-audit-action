# NuGet vulnerability audit action

A GitHub Action that scans .NET solutions for NuGet packages with known vulnerabilities and shows the results in the GitHub UI. It runs

```
dotnet list package --vulnerable --include-transitive --format json
```

and turns the output into:

- a **job summary** on the workflow run page, with one row per vulnerable package, project and advisory;
- **annotations** on the project files (errors at or above the failure threshold, warnings below it), with the line of the `PackageReference` for direct references;
- a Markdown report and a JSON findings file as step outputs, so you can upload them as artifacts or post them elsewhere.

Findings can be **suppressed for a limited time** when the maintainer has not shipped a fix yet. A suppression always has an end date; when it passes, the finding fails the build again.

The vulnerability data comes from the [NuGet audit](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages) feed of your package sources (for nuget.org, the GitHub Advisory Database).

## Usage

```yaml
name: NuGet audit

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * 1"

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-dotnet@v5
        with:
          dotnet-version: 10.0.x
      - uses: lucem-labs/nuget-audit-action@v1
        with:
          path: MySolution.slnx
```

Run it on a schedule as well as on pull requests: new advisories are published for packages you already use, so a repository with no changes can become vulnerable.

The action needs PowerShell 7 (`pwsh`) and the .NET SDK on the runner. GitHub-hosted runners have both. It works with .NET 8 SDK or later, because the JSON output of `dotnet list package` first shipped in .NET 8.

## Inputs

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Solution, project or directory to scan, relative to the workspace. A directory must contain exactly one solution or project file. |
| `suppressions-file` | `.github/nuget-audit-suppressions.json` | Suppressions file, relative to the workspace. A missing file means no suppressions. |
| `fail-severity` | `low` | Lowest severity that fails the step: `low`, `moderate`, `high` or `critical`. Findings below it are reported as warnings. |
| `fail-on-vulnerable` | `true` | Set to `false` to only report. Invalid suppressions and `dotnet` errors still fail the step. |
| `include-transitive` | `true` | Include transitive packages. |
| `restore` | `true` | Run `dotnet restore` before the scan. Set to `false` if an earlier step restored already. |
| `max-suppression-days` | `90` | Reject suppressions whose `until` date is further away than this. `0` turns the limit off. |
| `list-arguments` | | Extra arguments for `dotnet list package`, for example `--config nuget.config`. |

## Outputs

| Output | Description |
|---|---|
| `vulnerable-count` | Unsuppressed findings, including those below `fail-severity`. |
| `failing-count` | Unsuppressed findings at or above `fail-severity`. |
| `suppressed-count` | Findings silenced by an active suppression. |
| `report-path` | Markdown report, same content as the job summary. |
| `findings-path` | JSON file with every finding and its status. |

To keep the report with the run, upload it:

```yaml
      - uses: lucem-labs/nuget-audit-action@v1
        id: audit
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: nuget-audit
          path: |
            ${{ steps.audit.outputs.report-path }}
            ${{ steps.audit.outputs.findings-path }}
```

## Suppressing a finding

Sometimes a package is vulnerable and no fixed version exists yet. Add the advisory to `.github/nuget-audit-suppressions.json`:

```json
{
  "suppressions": [
    {
      "advisory": "GHSA-5crp-9r3c-p9vr",
      "package": "Newtonsoft.Json",
      "projects": ["src/Legacy/Legacy.csproj"],
      "until": "2026-12-31",
      "reason": "No patched version yet. Tracked in #42."
    }
  ]
}
```

| Field | Required | Description |
|---|---|---|
| `advisory` | yes | GHSA id or full advisory URL, as shown in the report. |
| `until` | yes | Last day (`yyyy-MM-dd`, UTC) the suppression applies. From the next day the finding fails again. |
| `reason` | yes | Why the finding is accepted. Shown in the report. |
| `package` | no | Only suppress the advisory for this package id. |
| `projects` | no | Only suppress the advisory in these projects (paths relative to the workspace, as shown in the report). |

The report lists suppressed findings with their end date and reason, so they stay visible. It also lists suppressions that no longer match anything, so you can remove them once the package is updated.

The `until` date may be at most `max-suppression-days` (default 90) in the future. Extend a suppression by changing the date in a pull request, which leaves a review trail.

### Why not `NuGetAuditSuppress`?

NuGet has its own [`<NuGetAuditSuppress>`](https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages#excluding-advisories) MSBuild item. It has no end date, so a suppressed advisory stays hidden after a fix ships. `dotnet list package --vulnerable` does not read it either. This action uses its own file so every suppression expires.

## Relation to restore-time NuGet audit

Since .NET 8, `dotnet restore` reports vulnerable packages as `NU1901`–`NU1904` warnings. This action restores with `-p:NuGetAudit=false`, so a project that treats those warnings as errors does not fail the restore before the scan can report anything. Your normal build keeps its own NuGet audit settings.

## Development

```
pwsh -c "Invoke-Pester ./test"
```

`test/fixtures/sample` is a small solution that references packages with known vulnerabilities. CI scans it with the action itself. Dependabot alerts for this repository come from that fixture and are expected.

## License

[MIT](LICENSE)
