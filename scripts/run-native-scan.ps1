[CmdletBinding()]
param(
    [string]$Target = "",
    [string]$Output = "",
    [string]$ToolRoot = "",
    [ValidateSet(
        "quick",
        "standard",
        "extended",
        "deep",
        "supply-chain",
        "artifact",
        "quality",
        "iac-deep",
        "governance",
        "repo-health",
        "repo",
        "comprehensive",
        "production",
        "release"
    )]
    [Alias("Profile")]
    [string]$ScanProfile = "",
    [switch]$NetworkIsolated
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $Target) {
    $Target = $workspace
}
if (-not $Output) {
    $Output = Join-Path $workspace ".artifacts\native-self-scan"
}
if (-not $ToolRoot) {
    $ToolRoot = Join-Path $workspace ".pysec-tools"
}
$targetPath = (Resolve-Path -LiteralPath $Target).Path
$outputPath = [IO.Path]::GetFullPath($Output)
$toolDirectory = (Resolve-Path -LiteralPath $ToolRoot).Path
$venvPython = Join-Path $toolDirectory "Scripts\python.exe"
$configPath = Join-Path $toolDirectory "pysec.native.toml"
$installMarker = Join-Path $toolDirectory "native-install.json"
foreach ($required in @($venvPython, $configPath, $installMarker)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Native tool environment is incomplete; missing: $required"
    }
}

$arguments = @(
    "-m", "py_security_suite",
    "scan", $targetPath,
    "--config", $configPath,
    "--output", $outputPath,
    "--overwrite"
)
if ($ScanProfile) {
    $arguments += @("--profile", $ScanProfile)
}
if ($NetworkIsolated) {
    $arguments += "--network-isolated"
} else {
    Write-Warning (
        "No external network-isolation attestation was supplied. Scanners will " +
        "run in offline modes, but policy will correctly report INCOMPLETE."
    )
    $arguments += "--diagnostic-without-isolation"
}

& $venvPython @arguments
$scanExit = $LASTEXITCODE
Write-Output "Python Security Suite native exit code: $scanExit"
Write-Output "Report: $outputPath"
exit $scanExit
