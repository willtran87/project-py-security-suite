[CmdletBinding()]
param(
    [string]$Image = "py-security-suite-scanners:0.1.0",
    [string]$ReportName = "self-scan"
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$artifactRoot = Join-Path $workspace ".artifacts"
New-Item -ItemType Directory -Path $artifactRoot -Force | Out-Null
$artifactRoot = (Resolve-Path -LiteralPath $artifactRoot).Path

docker run `
    --rm `
    --network none `
    --read-only `
    --cap-drop ALL `
    --security-opt no-new-privileges `
    --pids-limit 256 `
    --memory 3g `
    --cpus 4 `
    --tmpfs /tmp:rw,noexec,nosuid,size=512m `
    --mount "type=bind,source=$workspace,target=/workspace,readonly" `
    --mount "type=bind,source=$artifactRoot,target=/out" `
    --env PYTHONDONTWRITEBYTECODE=1 `
    $Image `
    scan /workspace `
    --config /opt/pysec-suite/pysec.toml `
    --output "/out/$ReportName" `
    --network-isolated `
    --overwrite

$scanExit = $LASTEXITCODE
Write-Host "Python Security Suite exit code: $scanExit"
Write-Host "Report: $(Join-Path $artifactRoot $ReportName)"
exit $scanExit
