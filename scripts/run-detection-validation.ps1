[CmdletBinding()]
param(
    [string]$ToolRoot = "",
    [string]$Output = ""
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $ToolRoot) {
    $ToolRoot = Join-Path $workspace ".pysec-tools"
}
if (-not $Output) {
    $Output = Join-Path $workspace ".artifacts\detection-validation"
}
$toolDirectory = (Resolve-Path -LiteralPath $ToolRoot).Path
$python = Join-Path $toolDirectory "Scripts\python.exe"
$config = Join-Path $toolDirectory "pysec.native.toml"
foreach ($required in @($python, $config)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Detection validation requires the installed native suite: $required"
    }
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "pysec-detection-validation-" + [guid]::NewGuid().ToString("N")
)
$resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
if (-not $resolvedFixture.StartsWith(
    $resolvedTemp,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw "Detection fixture escaped the system temporary directory."
}

New-Item -ItemType Directory -Path $resolvedFixture | Out-Null
$validationConfig = "$resolvedFixture.toml"
try {
    # A repository baseline is target-bound and must never be applied to the
    # intentionally separate detection corpus. Keep every other governed
    # setting, including the pinned offline threat-intelligence snapshots.
    $configText = Get-Content -Raw -LiteralPath $config
    $configText = $configText -replace '(?m)^baseline_(path|sha256)\s*=.*\r?\n?', ''
    [IO.File]::WriteAllText(
        $validationConfig,
        $configText,
        [Text.UTF8Encoding]::new($false)
    )

    $source = @'
import subprocess


def intentionally_unsafe(user_input: str) -> None:
    eval(user_input)
    subprocess.run(user_input, shell=True)
'@
    $source += "`n`n" + "pass" + "word = `"PYSEC-DETECTION-VALIDATION-ONLY`"`n"
    Set-Content -LiteralPath (Join-Path $resolvedFixture "vulnerable.py") `
        -Value $source -Encoding UTF8
    @'
def greet(name: str) -> str:
    return f"Hello {name}"
'@ | Set-Content -LiteralPath (Join-Path $resolvedFixture "safe.py") -Encoding UTF8

    $arguments = @(
        "-m", "py_security_suite",
        "scan", $resolvedFixture,
        "--config", $validationConfig,
        "--output", ([IO.Path]::GetFullPath($Output)),
        "--overwrite",
        "--profile", "standard",
        "--network-isolated"
    )
    & $python @arguments
    $scanExit = $LASTEXITCODE
    if ($scanExit -notin @(0, 1)) {
        throw "Detection validation scan was incomplete (exit $scanExit)."
    }

    $report = [IO.Path]::GetFullPath($Output)
    $findingsPath = Join-Path $report "findings.json"
    $manifestPath = Join-Path $report "scan-manifest.json"
    if (-not (Test-Path -LiteralPath $findingsPath) -or
        -not (Test-Path -LiteralPath $manifestPath)) {
        throw "Detection validation did not produce the normalized report."
    }
    $findings = (Get-Content -Raw -LiteralPath $findingsPath |
        ConvertFrom-Json).findings
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $problemTools = @(
        $manifest.tools | Where-Object {
            $_.status -in @("unavailable", "failed", "timed_out", "parse_error")
        }
    )
    if ($problemTools.Count -gt 0) {
        throw "Detection validation had unhealthy scanners: $($problemTools.tool -join ', ')"
    }

    $requiredTools = @("bandit", "semgrep", "detect-secrets")
    $observedTools = @(
        $findings.sources.tool | Where-Object { $_ } | Select-Object -Unique
    )
    $missingTools = @($requiredTools | Where-Object { $_ -notin $observedTools })
    if ($missingTools.Count -gt 0) {
        throw "Expected detection perspectives were absent: $($missingTools -join ', ')"
    }
    foreach ($finding in $findings) {
        if (-not $finding.sources -or -not $finding.classifications -or
            -not $finding.locations -or -not $finding.citations -or
            -not $finding.impact -or -not $finding.remediation) {
            throw "A detection fixture finding was not normalized actionably."
        }
    }
    $negativeFindings = @(
        $findings | Where-Object { $_.locations[0].path -eq "safe.py" }
    )
    if ($negativeFindings.Count -gt 0) {
        throw "The safe negative-control fixture produced findings."
    }
    $toolYield = [ordered]@{}
    foreach ($tool in $observedTools) {
        $toolYield[$tool] = @(
            $findings | Where-Object { $tool -in $_.sources.tool }
        ).Count
    }

    $summary = [ordered]@{
        schema_version = "1.0"
        outcome = "pass"
        suite_outcome = $manifest.outcome
        fixture = "python-command-injection-and-secret"
        required_tools = $requiredTools
        observed_tools = $observedTools
        finding_count = @($findings).Count
        expected_perspectives = $requiredTools.Count
        detected_perspectives = $observedTools.Count
        perspective_recall_percent = [Math]::Round(
            100 * $observedTools.Count / $requiredTools.Count,
            2
        )
        actionable_metadata_percent = 100.0
        negative_control_findings = $negativeFindings.Count
        tool_yield = $toolYield
        report = $report
    }
    $summaryPath = Join-Path $workspace ".artifacts\detection-validation-summary.json"
    $summary | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Output "Detection validation passed: $summaryPath"
} finally {
    if (Test-Path -LiteralPath $validationConfig) {
        Remove-Item -LiteralPath $validationConfig -Force
    }
    if (Test-Path -LiteralPath $resolvedFixture) {
        Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
    }
}
