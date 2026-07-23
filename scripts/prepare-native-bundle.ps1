[CmdletBinding()]
param(
    [string]$BundlePath = "",
    [string]$Python = "",
    [switch]$Force,
    [string]$BanditVersion = "1.9.4",
    [string]$SemgrepVersion = "1.170.0",
    [string]$DetectSecretsVersion = "1.5.0",
    [string]$RuffVersion = "0.15.22",
    [string]$CycloneDxVersion = "7.3.0",
    [string]$ZizmorVersion = "1.28.0",
    [string]$ScanCodeVersion = "32.5.0",
    [string]$RunCodeQlVersion = "1.6.0",
    [string]$PyPiAttestationsVersion = "0.0.29",
    [string]$CheckWheelContentsVersion = "0.6.3",
    [string]$TwineVersion = "6.2.0",
    [string]$OsvScannerVersion = "2.3.8",
    [string]$OsvScannerSha256 = "cb04e79dd9698a7bc821bbfdddec916a416d1409fda79c927c509d37d00c9716", # pragma: allowlist secret
    [string]$TrivyVersion = "0.69.3",
    [string]$TrivyWindowsArchiveSha256 = "74362dc711383255308230ecbeb587eb1e4e83a8d332be5b0259afac6e0c2224", # pragma: allowlist secret
    [string]$GitleaksVersion = "8.30.1",
    [string]$GitleaksWindowsArchiveSha256 = "d29144deff3a68aa93ced33dddf84b7fdc26070add4aa0f4513094c8332afc4e", # pragma: allowlist secret
    [string]$SyftVersion = "1.49.0",
    [string]$SyftWindowsArchiveSha256 = "6edff6c6e06ddd43ae3b779099653f499a856009786b5375a7cf23aed6b67b1a", # pragma: allowlist secret
    [string]$GrypeVersion = "0.116.0",
    [string]$GrypeWindowsArchiveSha256 = "e5301bca123e7bb545a551cb6cc91a66b8400f65d6897005eca9f40fc16ce107", # pragma: allowlist secret
    [string]$TruffleHogVersion = "3.95.9",
    [string]$TruffleHogWindowsArchiveSha256 = "25cc731f678922c870edba49f19c324aa6c8e7190b551c4fbe49d0c4e1c5446a", # pragma: allowlist secret
    # Approved PyPI OSV snapshot retrieved and structurally validated 2026-07-23.
    [string]$OsvDatabaseSha256 = "3e32a8bf2f2af38718e572a96859823f162030df235ec78f773ab0f5df12d9c2" # pragma: allowlist secret
)

$ErrorActionPreference = "Stop"
function Receive-PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($curl) {
        & $curl.Source --fail --location --silent --show-error `
            --output $Destination $Uri
        if ($LASTEXITCODE -ne 0) {
            throw "Download failed: $Uri"
        }
        return
    }
    Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $Destination
}

$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $Python) {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $launched = (& py -3.11 -c "import sys; print(sys.executable)" 2>$null)
        if ($LASTEXITCODE -eq 0 -and $launched) {
            $candidates += $launched.Trim()
        }
    }
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        $candidates += $pythonCommand.Source
    }
    foreach ($candidate in $candidates | Select-Object -Unique) {
        & $candidate -m pip --version *> $null
        if ($LASTEXITCODE -eq 0) {
            $Python = $candidate
            break
        }
    }
    if (-not $Python) {
        throw "No Python 3.11 interpreter with pip was found; pass -Python explicitly."
    }
}
& $Python -c (
    "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)"
)
if ($LASTEXITCODE -ne 0) {
    throw "The native bundle currently requires Python 3.11."
}
if (-not $BundlePath) {
    $BundlePath = Join-Path $workspace ".artifacts\native-bundle"
}
$bundle = [IO.Path]::GetFullPath($BundlePath)
$workspaceRoot = [IO.Path]::GetPathRoot($workspace)
if ($bundle -eq $workspace -or $bundle -eq $workspaceRoot) {
    throw "BundlePath must be a dedicated directory, not the workspace or drive root."
}
if (Test-Path -LiteralPath $bundle) {
    if (-not $Force) {
        throw "BundlePath already exists; choose a new path or pass -Force: $bundle"
    }
    $existingManifest = Join-Path $bundle "bundle-manifest.json"
    if (-not (Test-Path -LiteralPath $existingManifest)) {
        $artifactRoot = [IO.Path]::GetFullPath(
            (Join-Path $workspace ".artifacts")
        )
        if (-not $bundle.StartsWith(
            $artifactRoot + [IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing to replace a directory without bundle-manifest.json: $bundle"
        }
    }
    Remove-Item -LiteralPath $bundle -Recurse -Force
}

$wheelhouse = Join-Path $bundle "wheelhouse"
$binaryDirectory = Join-Path $bundle "bin"
$archiveDirectory = Join-Path $bundle "archives"
$databaseDirectory = Join-Path $bundle "osv-db\osv-scanner\PyPI"
New-Item -ItemType Directory -Path (
    $wheelhouse,
    $binaryDirectory,
    $archiveDirectory,
    $databaseDirectory
) | Out-Null

$requirements = @(
    "bandit==$BanditVersion",
    "semgrep==$SemgrepVersion",
    "detect-secrets==$DetectSecretsVersion",
    "ruff==$RuffVersion",
    "cyclonedx-bom==$CycloneDxVersion",
    "zizmor==$ZizmorVersion"
)
& $Python -m pip download --only-binary=:all: --dest $wheelhouse @requirements
if ($LASTEXITCODE -ne 0) {
    throw "Downloading the pinned native Python wheels failed."
}
$artifactRequirements = @(
    "run-codeql==$RunCodeQlVersion",
    "pypi-attestations==$PyPiAttestationsVersion",
    "check-wheel-contents==$CheckWheelContentsVersion",
    "twine==$TwineVersion"
)
& $Python -m pip download --only-binary=:all: --dest $wheelhouse `
    @artifactRequirements
if ($LASTEXITCODE -ne 0) {
    throw "Downloading the pinned artifact-tool wheels failed."
}
& $Python -m pip download --only-binary=:all: --dest $wheelhouse `
    "scancode-toolkit==$ScanCodeVersion"
if ($LASTEXITCODE -ne 0) {
    throw "Downloading the pinned ScanCode sidecar wheels failed."
}
& $Python -m pip wheel --no-deps --wheel-dir $wheelhouse $workspace
if ($LASTEXITCODE -ne 0) {
    throw "Building the Python Security Suite wheel failed."
}

$osvBinary = Join-Path $binaryDirectory "osv-scanner.exe"
$osvUrl = (
    "https://github.com/google/osv-scanner/releases/download/" +
    "v$OsvScannerVersion/osv-scanner_windows_amd64.exe"
)
Receive-PinnedFile -Uri $osvUrl -Destination $osvBinary
$actualOsvHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $osvBinary).Hash.ToLowerInvariant()
if ($actualOsvHash -ne $OsvScannerSha256.ToLowerInvariant()) {
    throw "OSV-Scanner checksum mismatch: $actualOsvHash"
}

$trivyArchive = Join-Path $archiveDirectory "trivy-windows-amd64.zip"
$trivyUrl = (
    "https://github.com/aquasecurity/trivy/releases/download/" +
    "v$TrivyVersion/trivy_$($TrivyVersion)_windows-64bit.zip"
)
Receive-PinnedFile -Uri $trivyUrl -Destination $trivyArchive
$actualTrivyHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $trivyArchive
).Hash.ToLowerInvariant()
if ($actualTrivyHash -ne $TrivyWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Trivy archive checksum mismatch: $actualTrivyHash"
}

$gitleaksArchive = Join-Path $archiveDirectory "gitleaks-windows-amd64.zip"
$gitleaksUrl = (
    "https://github.com/gitleaks/gitleaks/releases/download/" +
    "v$GitleaksVersion/gitleaks_$($GitleaksVersion)_windows_x64.zip"
)
Receive-PinnedFile -Uri $gitleaksUrl -Destination $gitleaksArchive
$actualGitleaksHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $gitleaksArchive
).Hash.ToLowerInvariant()
if ($actualGitleaksHash -ne $GitleaksWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Gitleaks archive checksum mismatch: $actualGitleaksHash"
}

$syftArchive = Join-Path $archiveDirectory "syft-windows-amd64.zip"
$syftUrl = (
    "https://github.com/anchore/syft/releases/download/" +
    "v$SyftVersion/syft_$($SyftVersion)_windows_amd64.zip"
)
Receive-PinnedFile -Uri $syftUrl -Destination $syftArchive
$actualSyftHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $syftArchive
).Hash.ToLowerInvariant()
if ($actualSyftHash -ne $SyftWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Syft archive checksum mismatch: $actualSyftHash"
}

$grypeArchive = Join-Path $archiveDirectory "grype-windows-amd64.zip"
$grypeUrl = (
    "https://github.com/anchore/grype/releases/download/" +
    "v$GrypeVersion/grype_$($GrypeVersion)_windows_amd64.zip"
)
Receive-PinnedFile -Uri $grypeUrl -Destination $grypeArchive
$actualGrypeHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $grypeArchive
).Hash.ToLowerInvariant()
if ($actualGrypeHash -ne $GrypeWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Grype archive checksum mismatch: $actualGrypeHash"
}

$truffleHogArchive = Join-Path $archiveDirectory "trufflehog-windows-amd64.tar.gz"
$truffleHogUrl = (
    "https://github.com/trufflesecurity/trufflehog/releases/download/" +
    "v$TruffleHogVersion/trufflehog_$($TruffleHogVersion)_windows_amd64.tar.gz"
)
Receive-PinnedFile -Uri $truffleHogUrl -Destination $truffleHogArchive
$actualTruffleHogHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $truffleHogArchive
).Hash.ToLowerInvariant()
if (
    $actualTruffleHogHash -ne
    $TruffleHogWindowsArchiveSha256.ToLowerInvariant()
) {
    throw "TruffleHog archive checksum mismatch: $actualTruffleHogHash"
}

$grypePreparation = Join-Path $bundle "grype-preparation"
$grypeDatabase = Join-Path $bundle "grype-db"
New-Item -ItemType Directory -Path $grypePreparation, $grypeDatabase | Out-Null
Expand-Archive -LiteralPath $grypeArchive -DestinationPath $grypePreparation
$grypeExecutables = @(
    Get-ChildItem -LiteralPath $grypePreparation -Recurse -Filter "grype.exe"
)
if ($grypeExecutables.Count -ne 1) {
    throw "Expected exactly one Grype executable in its verified archive."
}
$previousGrypeDatabase = $env:GRYPE_DB_CACHE_DIR
try {
    $env:GRYPE_DB_CACHE_DIR = $grypeDatabase
    & $grypeExecutables[0].FullName db update
    if ($LASTEXITCODE -ne 0) {
        throw "Downloading the Grype vulnerability database failed."
    }
} finally {
    $env:GRYPE_DB_CACHE_DIR = $previousGrypeDatabase
}

$databaseArchive = Join-Path $databaseDirectory "all.zip"
$databaseUrl = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
Receive-PinnedFile -Uri $databaseUrl -Destination $databaseArchive
$actualDatabaseHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $databaseArchive
).Hash.ToLowerInvariant()
if ($actualDatabaseHash -ne $OsvDatabaseSha256.ToLowerInvariant()) {
    throw "PyPI OSV database checksum mismatch: $actualDatabaseHash"
}

$files = @(
    Get-ChildItem -LiteralPath $bundle -Recurse -File |
        Sort-Object FullName |
        ForEach-Object {
            [ordered]@{
                path = $_.FullName.Substring($bundle.Length + 1).Replace("\", "/")
                sha256 = (
                    Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName
                ).Hash.ToLowerInvariant()
                size = $_.Length
            }
        }
)
$manifest = [ordered]@{
    schema_version = "1"
    created_at = (Get-Date).ToUniversalTime().ToString("o")
    platform = "windows-amd64"
    python = (& $Python --version 2>&1 | Out-String).Trim()
    tools = [ordered]@{
        bandit = $BanditVersion
        semgrep = $SemgrepVersion
        "detect-secrets" = $DetectSecretsVersion
        "osv-scanner" = $OsvScannerVersion
        trivy = $TrivyVersion
        gitleaks = $GitleaksVersion
        ruff = $RuffVersion
        "cyclonedx-bom" = $CycloneDxVersion
        zizmor = $ZizmorVersion
        "scancode-toolkit" = $ScanCodeVersion
        "run-codeql" = $RunCodeQlVersion
        "pypi-attestations" = $PyPiAttestationsVersion
        "check-wheel-contents" = $CheckWheelContentsVersion
        twine = $TwineVersion
        syft = $SyftVersion
        grype = $GrypeVersion
        trufflehog = $TruffleHogVersion
        "py-security-suite" = "0.1.0"
    }
    sources = [ordered]@{
        python_packages = "https://pypi.org/simple/"
        osv_scanner = $osvUrl
        trivy = $trivyUrl
        gitleaks = $gitleaksUrl
        syft = $syftUrl
        grype = $grypeUrl
        trufflehog = $truffleHogUrl
        osv_database = $databaseUrl
    }
    files = $files
}
$manifestPath = Join-Path $bundle "bundle-manifest.json"
$manifest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Host "Native bundle prepared: $bundle"
Write-Host "Files recorded: $($files.Count)"
Write-Host "This connected-lane artifact can now be transferred to an isolated runner."
