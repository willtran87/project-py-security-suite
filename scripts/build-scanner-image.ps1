[CmdletBinding()]
param(
    [string]$Tag = "py-security-suite-scanners:0.1.0"
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$dockerfile = Join-Path $workspace "containers\scanner\Dockerfile"

docker build `
    --no-cache `
    --file $dockerfile `
    --tag $Tag `
    $workspace

if ($LASTEXITCODE -ne 0) {
    throw "Scanner image build failed with exit code $LASTEXITCODE"
}

docker image inspect $Tag --format "{{.Id}}"

