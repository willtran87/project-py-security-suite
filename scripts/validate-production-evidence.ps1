[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EvidenceDirectory,
    [ValidateSet("production", "release")][string]$GateProfile = "production",
    [string]$Python = ""
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$evidence = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
if (-not $Python) {
    $native = Join-Path $workspace ".pysec-tools\Scripts\python.exe"
    $Python = if (Test-Path -LiteralPath $native) {
        $native
    } else {
        (Get-Command python -ErrorAction Stop).Source
    }
}

$required = [ordered]@{
    "hypothesis" = @("junit", "hypothesis-junit.xml")
    "crosshair" = @("assurance", "crosshair.json")
    "atheris" = @("assurance", "atheris.json")
    "mutmut" = @("assurance", "mutmut.json")
    "pytm" = @("assurance", "pytm.json")
    "scorecard" = @("scorecard", "scorecard.json")
}
if ($GateProfile -eq "release") {
    $required["check-manifest"] = @("assurance", "check-manifest.json")
    $required["clamav"] = @("assurance", "clamav.json")
    $required["github-attestation"] = @("assurance", "github-attestation.json")
    $required["in-toto"] = @("assurance", "in-toto.json")
    $required["oci-image"] = @("assurance", "oci-image.json")
    $required["reproducible-build"] = @("assurance", "reproducible-build.json")
    $required["yara"] = @("assurance", "yara.json")
}

$validated = @()
foreach ($entry in $required.GetEnumerator()) {
    $kind = $entry.Key
    $mode = $entry.Value[0]
    $path = Join-Path $evidence $entry.Value[1]
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "$GateProfile evidence is incomplete; missing $kind evidence: $path"
    }
    $arguments = @("-m", "py_security_suite.evidence_ingest", $mode)
    if ($mode -eq "assurance") {
        $arguments += $kind
    }
    $arguments += $path
    & $Python @arguments *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "$kind evidence failed bounded validation: $path"
    }
    $validated += $kind
}

[ordered]@{
    schema_version = "1.0"
    profile = $GateProfile
    evidence_directory = $evidence
    validated_controls = $validated
} | ConvertTo-Json -Depth 4
