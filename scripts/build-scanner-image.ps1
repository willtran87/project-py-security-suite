[CmdletBinding()]
param(
    [string]$Tag = "",
    [Parameter(Mandatory = $true)]
    [string]$OsvDatabaseDirectory,
    [string]$EvidenceDirectory = ""
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
$versionLine = Select-String -LiteralPath (Join-Path $workspace "src\py_security_suite\version.py") `
    -Pattern '^__version__ = "([0-9A-Za-z.+!-]+)"$'
if ($versionLine.Matches.Count -ne 1) {
    throw "Package version authority is invalid"
}
$suiteVersion = $versionLine.Matches[0].Groups[1].Value
if (-not $Tag) {
    $Tag = "py-security-suite-scanners:$suiteVersion"
}
$dockerfile = Join-Path $workspace "containers\scanner\Dockerfile"
$databaseDirectory = (Resolve-Path -LiteralPath $OsvDatabaseDirectory).Path
$database = Join-Path $databaseDirectory "osv-pypi-all.zip"
$metadataPath = Join-Path $databaseDirectory "metadata.json"

if (-not (Test-Path -LiteralPath $database -PathType Leaf)) {
    throw "Prepared OSV database is missing: $database"
}
if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
    throw "Prepared OSV database metadata is missing: $metadataPath"
}
$metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
if ([string]$metadata.kind -ne "osv-pypi-database-snapshot") {
    throw "Prepared OSV database metadata has an unexpected artifact kind"
}
if ([string]$metadata.build_input -ne "osv-pypi-all.zip") {
    throw "Prepared OSV database metadata names an unexpected build input"
}
if ([string]$metadata.source_url -ne "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip") {
    throw "Prepared OSV database metadata names an unauthorized source"
}
$expectedDigest = [string]$metadata.sha256
if ($expectedDigest -notmatch '^[0-9a-f]{64}$') {
    throw "Prepared OSV database metadata has an invalid digest"
}
$expectedBytes = [long]$metadata.bytes
$actualBytes = (Get-Item -LiteralPath $database).Length
if ($expectedBytes -le 0 -or $actualBytes -ne $expectedBytes) {
    throw "Prepared OSV database size does not match its metadata"
}
$actualDigest = (Get-FileHash -LiteralPath $database -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualDigest -ne $expectedDigest) {
    throw "Prepared OSV database digest does not match its metadata"
}

docker build `
    --no-cache `
    --build-context "osv_database=$databaseDirectory" `
    --build-arg "OSV_PYPI_DATABASE_SHA256=$expectedDigest" `
    --file $dockerfile `
    --tag $Tag `
    $workspace

if ($LASTEXITCODE -ne 0) {
    throw "Scanner image build failed with exit code $LASTEXITCODE"
}

# Exercise the exact identity model used by CI. This is intentionally neither
# root nor the image's declared user and catches unreadable COPY assets before
# the expensive end-to-end scan begins.
$runtimeProbe = docker run --rm --network none --read-only --user 42424:42424 `
    --entrypoint python $Tag -c (
        "from pathlib import Path; " +
        "assets = (Path('/opt/osv-db/osv-scanner/PyPI/all.zip'), " +
        "Path('/opt/pysec-bundle/python-sbom.cdx.json')); " +
        "assert all(path.is_file() and path.stat().st_size > 0 for path in assets); " +
        "[path.open('rb').read(1) for path in assets]; print('arbitrary-uid-assets-readable')"
    )
if ($LASTEXITCODE -ne 0 -or ($runtimeProbe -join "`n") -notmatch "arbitrary-uid-assets-readable") {
    throw "Scanner image arbitrary-UID governed-asset probe failed"
}

$imageId = (docker image inspect $Tag --format "{{.Id}}").Trim()
if ($LASTEXITCODE -ne 0 -or $imageId -notmatch '^sha256:[0-9a-f]{64}$') {
    throw "Scanner image identity is invalid"
}
Write-Output $imageId

if ($EvidenceDirectory) {
    New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
    $evidenceRoot = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
    if ((Get-Item -LiteralPath $evidenceRoot).LinkType) {
        throw "Scanner image evidence directory must not be a link"
    }
    $sbomPath = Join-Path $evidenceRoot "python-sbom.cdx.json"
    $receiptPath = Join-Path $evidenceRoot "scanner-image-evidence.json"
    if ((Test-Path -LiteralPath $sbomPath) -or (Test-Path -LiteralPath $receiptPath)) {
        throw "Scanner image evidence output already exists"
    }
    $sbomRaw = docker run --rm --network none --entrypoint sh $Tag `
        -c "cat /opt/pysec-bundle/python-sbom.cdx.json"
    if ($LASTEXITCODE -ne 0) {
        throw "Scanner image SBOM extraction failed"
    }
    $sbomText = ($sbomRaw -join "`n") + "`n"
    $sbom = $sbomText | ConvertFrom-Json
    if ([string]$sbom.bomFormat -ne "CycloneDX" -or [string]$sbom.specVersion -ne "1.6" -or $sbom.components.Count -lt 1) {
        throw "Scanner image SBOM is invalid"
    }
    [IO.File]::WriteAllText($sbomPath, $sbomText, [Text.UTF8Encoding]::new($false))
    $sbomDigest = (Get-FileHash -LiteralPath $sbomPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt = [ordered]@{
        schema_version = "1.0"
        image_tag = $Tag
        image_id = $imageId
        osv_database_sha256 = $expectedDigest
        python_sbom_sha256 = $sbomDigest
        python_sbom_components = [int]$sbom.components.Count
        claim_boundary = "This receipt binds the local OCI image configuration identity, sealed OSV input, and embedded Python CycloneDX SBOM; registry manifest identity is established only after publication."
    }
    $receiptText = ($receipt | ConvertTo-Json -Depth 5) + "`n"
    [IO.File]::WriteAllText($receiptPath, $receiptText, [Text.UTF8Encoding]::new($false))
}
