[CmdletBinding()]
param(
    [string]$BundlePath = "",
    [string]$Python = "",
    [switch]$Force,
    [string]$BanditVersion = "1.9.4",
    [string]$SemgrepVersion = "1.170.0",
    [string]$DetectSecretsVersion = "1.5.0",
    [string]$DefusedXmlVersion = "0.7.1",
    [string]$RuffVersion = "0.15.22",
    [string]$MypyVersion = "2.1.0",
    [string]$VultureVersion = "2.16",
    [string]$TachVersion = "0.35.0",
    [string]$PylintVersion = "4.0.6",
    [string]$RadonVersion = "6.0.1",
    [string]$ReuseVersion = "6.2.0",
    [string]$FlawfinderVersion = "2.0.20",
    [string]$CycloneDxVersion = "7.3.0",
    [string]$UvVersion = "0.11.19",
    [string]$ZizmorVersion = "1.28.0",
    [string]$ScanCodeVersion = "32.5.0",
    [string]$RunCodeQlVersion = "1.6.0",
    [string]$PyPiAttestationsVersion = "0.0.29",
    [string]$CheckWheelContentsVersion = "0.6.3",
    [string]$TwineVersion = "6.2.0",
    [string]$DeptryVersion = "0.24.0",
    [string]$DiffCoverVersion = "10.2.0",
    [string]$PipdeptreeVersion = "4.2.0",
    [string]$ValidatePyprojectVersion = "0.25",
    [string]$CheckovVersion = "3.2.494",
    [string]$PSScriptAnalyzerVersion = "1.25.0",
    [string]$PyrightVersion = "1.1.411",
    [string]$NodeVersion = "20.20.2",
    [string]$NodeWindowsArchiveSha256 = "dc3700fdd57a63eedb8fd7e3c7baaa32e6a740a1b904167ff4204bc68ed8bf77", # pragma: allowlist secret
    [string]$ShellCheckVersion = "0.11.0",
    [string]$ShellCheckWindowsArchiveSha256 = "8a4e35ab0b331c85d73567b12f2a444df187f483e5079ceffa6bda1faa2e740e", # pragma: allowlist secret
    [string]$CosignVersion = "3.1.2",
    [string]$CosignWindowsSha256 = "fe4d621d7ae5e900ee62089837c00f996ae9acb82027d573d1d157b6ee875cb2", # pragma: allowlist secret
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
    [string]$ActionlintVersion = "1.7.12",
    [string]$ActionlintWindowsArchiveSha256 = "6e7241b51e6817ea6a047693d8e6fed13b31819c9a0dd6c5a726e1592d22f6e9", # pragma: allowlist secret
    [string]$ConftestVersion = "0.68.2",
    [string]$ConftestWindowsArchiveSha256 = "66a88d02e6c03a714e9f0751c3d86ee9c5591739c367ca1b79c4f9f2f90ac4cb", # pragma: allowlist secret
    [string]$GitSizerVersion = "1.5.0",
    [string]$GitSizerWindowsArchiveSha256 = "52093c1cba0bb8e00da14c9eef678eb052fc729c32419415817076f06b5c85d8", # pragma: allowlist secret
    [string]$ValeVersion = "3.17.0",
    [string]$ValeWindowsArchiveSha256 = "7294214b10104bdcbad027f2a59b0e468f24edb739ea03befcef6d491bdcf58f", # pragma: allowlist secret
    [string]$KubeLinterVersion = "0.8.3",
    [string]$KubeLinterWindowsArchiveSha256 = "27132f8505d156e3877c6235970f567f47bedf11102f79fd6780d4ab536f6525", # pragma: allowlist secret
    [string]$HadolintVersion = "2.14.0",
    [string]$HadolintWindowsSha256 = "8e0ee174f88edb14f207a68430c7a53c2883ed509cdbde9a3a26fffa140fa5e4", # pragma: allowlist secret
    [string]$DevSkimVersion = "1.0.70",
    [string]$DevSkimNuGetSha256 = "31e3a53b5d5d7427a260d14b922c69737a1f0e20110864189c2a0117eceabed4", # pragma: allowlist secret
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
$nugetDirectory = Join-Path $bundle "nuget"
$databaseDirectory = Join-Path $bundle "osv-db\osv-scanner\PyPI"
New-Item -ItemType Directory -Path (
    $wheelhouse,
    $binaryDirectory,
    $archiveDirectory,
    $nugetDirectory,
    $databaseDirectory
) | Out-Null

$requirements = @(
    "bandit==$BanditVersion",
    "semgrep==$SemgrepVersion",
    "detect-secrets==$DetectSecretsVersion",
    "defusedxml==$DefusedXmlVersion",
    "ruff==$RuffVersion",
    "mypy==$MypyVersion",
    "vulture==$VultureVersion",
    "tach==$TachVersion",
    "pylint==$PylintVersion",
    "radon==$RadonVersion",
    "flawfinder==$FlawfinderVersion",
    "cyclonedx-bom==$CycloneDxVersion",
    "uv==$UvVersion",
    "zizmor==$ZizmorVersion",
    "deptry==$DeptryVersion",
    "diff-cover==$DiffCoverVersion",
    "pipdeptree==$PipdeptreeVersion",
    "validate-pyproject==$ValidatePyprojectVersion"
)
& $Python -m pip download --only-binary=:all: --dest $wheelhouse @requirements
if ($LASTEXITCODE -ne 0) {
    throw "Downloading the pinned native Python wheels failed."
}
# REUSE 6.2.0 is distributed as an sdist. Build its wheel only in this
# connected preparation lane, then install the resulting immutable wheel in
# the isolated runtime. Dependencies are resolved into the same wheelhouse.
& $Python -m pip wheel --wheel-dir $wheelhouse `
    "reuse[charset-normalizer]==$ReuseVersion"
if ($LASTEXITCODE -ne 0) {
    throw "Building the pinned REUSE wheel failed."
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
& $Python -m pip download --only-binary=:all: --dest $wheelhouse `
    "checkov==$CheckovVersion"
if ($LASTEXITCODE -ne 0) {
    throw "Downloading the pinned Checkov sidecar wheels failed."
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

$actionlintArchive = Join-Path $archiveDirectory "actionlint-windows-amd64.zip"
$actionlintUrl = (
    "https://github.com/rhysd/actionlint/releases/download/" +
    "v$ActionlintVersion/actionlint_$($ActionlintVersion)_windows_x86_64.zip"
)
Receive-PinnedFile -Uri $actionlintUrl -Destination $actionlintArchive
$actualActionlintHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $actionlintArchive
).Hash.ToLowerInvariant()
if ($actualActionlintHash -ne $ActionlintWindowsArchiveSha256.ToLowerInvariant()) {
    throw "actionlint archive checksum mismatch: $actualActionlintHash"
}

$conftestArchive = Join-Path $archiveDirectory "conftest-windows-amd64.zip"
$conftestUrl = (
    "https://github.com/open-policy-agent/conftest/releases/download/" +
    "v$ConftestVersion/conftest_$($ConftestVersion)_Windows_x86_64.zip"
)
Receive-PinnedFile -Uri $conftestUrl -Destination $conftestArchive
$actualConftestHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $conftestArchive
).Hash.ToLowerInvariant()
if ($actualConftestHash -ne $ConftestWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Conftest archive checksum mismatch: $actualConftestHash"
}

$gitSizerArchive = Join-Path $archiveDirectory "git-sizer-windows-amd64.zip"
$gitSizerUrl = (
    "https://github.com/github/git-sizer/releases/download/" +
    "v$GitSizerVersion/git-sizer-$GitSizerVersion-windows-amd64.zip"
)
Receive-PinnedFile -Uri $gitSizerUrl -Destination $gitSizerArchive
$actualGitSizerHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $gitSizerArchive
).Hash.ToLowerInvariant()
if ($actualGitSizerHash -ne $GitSizerWindowsArchiveSha256.ToLowerInvariant()) {
    throw "git-sizer archive checksum mismatch: $actualGitSizerHash"
}

$valeArchive = Join-Path $archiveDirectory "vale-windows-amd64.zip"
$valeUrl = (
    "https://github.com/vale-cli/vale/releases/download/" +
    "v$ValeVersion/vale_$($ValeVersion)_Windows_64-bit.zip"
)
Receive-PinnedFile -Uri $valeUrl -Destination $valeArchive
$actualValeHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $valeArchive
).Hash.ToLowerInvariant()
if ($actualValeHash -ne $ValeWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Vale archive checksum mismatch: $actualValeHash"
}

$kubeLinterArchive = Join-Path $archiveDirectory "kube-linter-windows-amd64.tar.gz"
$kubeLinterUrl = (
    "https://github.com/stackrox/kube-linter/releases/download/" +
    "v$KubeLinterVersion/kube-linter-windows.tar.gz"
)
Receive-PinnedFile -Uri $kubeLinterUrl -Destination $kubeLinterArchive
$actualKubeLinterHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $kubeLinterArchive
).Hash.ToLowerInvariant()
if ($actualKubeLinterHash -ne $KubeLinterWindowsArchiveSha256.ToLowerInvariant()) {
    throw "KubeLinter archive checksum mismatch: $actualKubeLinterHash"
}

$hadolintBinary = Join-Path $binaryDirectory "hadolint.exe"
$hadolintUrl = (
    "https://github.com/hadolint/hadolint/releases/download/" +
    "v$HadolintVersion/hadolint-Windows-x86_64.exe"
)
Receive-PinnedFile -Uri $hadolintUrl -Destination $hadolintBinary
$actualHadolintHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $hadolintBinary
).Hash.ToLowerInvariant()
if ($actualHadolintHash -ne $HadolintWindowsSha256.ToLowerInvariant()) {
    throw "Hadolint checksum mismatch: $actualHadolintHash"
}

$devSkimPackage = Join-Path (
    $nugetDirectory
) "microsoft.cst.devskim.cli.$DevSkimVersion.nupkg"
$devSkimUrl = (
    "https://api.nuget.org/v3-flatcontainer/microsoft.cst.devskim.cli/" +
    "$DevSkimVersion/microsoft.cst.devskim.cli.$DevSkimVersion.nupkg"
)
Receive-PinnedFile -Uri $devSkimUrl -Destination $devSkimPackage
$actualDevSkimHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $devSkimPackage
).Hash.ToLowerInvariant()
if ($actualDevSkimHash -ne $DevSkimNuGetSha256.ToLowerInvariant()) {
    throw "DevSkim NuGet package checksum mismatch: $actualDevSkimHash"
}

$shellCheckArchive = Join-Path $archiveDirectory "shellcheck-windows.zip"
$shellCheckUrl = (
    "https://github.com/koalaman/shellcheck/releases/download/" +
    "v$ShellCheckVersion/shellcheck-v$ShellCheckVersion.zip"
)
Receive-PinnedFile -Uri $shellCheckUrl -Destination $shellCheckArchive
$actualShellCheckHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $shellCheckArchive
).Hash.ToLowerInvariant()
if ($actualShellCheckHash -ne $ShellCheckWindowsArchiveSha256.ToLowerInvariant()) {
    throw "ShellCheck archive checksum mismatch: $actualShellCheckHash"
}

$cosignBinary = Join-Path $binaryDirectory "cosign.exe"
$cosignUrl = (
    "https://github.com/sigstore/cosign/releases/download/" +
    "v$CosignVersion/cosign-windows-amd64.exe"
)
Receive-PinnedFile -Uri $cosignUrl -Destination $cosignBinary
$actualCosignHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $cosignBinary
).Hash.ToLowerInvariant()
if ($actualCosignHash -ne $CosignWindowsSha256.ToLowerInvariant()) {
    throw "Cosign checksum mismatch: $actualCosignHash"
}

$nodeArchive = Join-Path $archiveDirectory "node-windows-x64.zip"
$nodeUrl = "https://nodejs.org/dist/v$NodeVersion/node-v$NodeVersion-win-x64.zip"
Receive-PinnedFile -Uri $nodeUrl -Destination $nodeArchive
$actualNodeHash = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $nodeArchive
).Hash.ToLowerInvariant()
if ($actualNodeHash -ne $NodeWindowsArchiveSha256.ToLowerInvariant()) {
    throw "Node.js archive checksum mismatch: $actualNodeHash"
}

$powerShellModuleDirectory = Join-Path $bundle "powershell-modules"
New-Item -ItemType Directory -Path $powerShellModuleDirectory | Out-Null
Save-Module -Name PSScriptAnalyzer -RequiredVersion $PSScriptAnalyzerVersion `
    -Repository PSGallery -Path $powerShellModuleDirectory

$npm = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npm) {
    throw "Preparing the Pyright bundle requires npm in the connected lane."
}
$nodeToolDirectory = Join-Path $bundle "node-tools"
& $npm.Source install --prefix $nodeToolDirectory --ignore-scripts `
    --no-audit --no-fund --package-lock=false "pyright@$PyrightVersion"
if ($LASTEXITCODE -ne 0) {
    throw "Preparing the pinned Pyright package failed."
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
        mypy = $MypyVersion
        vulture = $VultureVersion
        tach = $TachVersion
        pylint = $PylintVersion
        radon = $RadonVersion
        reuse = $ReuseVersion
        flawfinder = $FlawfinderVersion
        actionlint = $ActionlintVersion
        conftest = $ConftestVersion
        "git-sizer" = $GitSizerVersion
        vale = $ValeVersion
        "kube-linter" = $KubeLinterVersion
        hadolint = $HadolintVersion
        devskim = $DevSkimVersion
        "cyclonedx-bom" = $CycloneDxVersion
        uv = $UvVersion
        zizmor = $ZizmorVersion
        "scancode-toolkit" = $ScanCodeVersion
        "run-codeql" = $RunCodeQlVersion
        "pypi-attestations" = $PyPiAttestationsVersion
        "check-wheel-contents" = $CheckWheelContentsVersion
        twine = $TwineVersion
        deptry = $DeptryVersion
        "diff-cover" = $DiffCoverVersion
        pipdeptree = $PipdeptreeVersion
        "validate-pyproject" = $ValidatePyprojectVersion
        checkov = $CheckovVersion
        psscriptanalyzer = $PSScriptAnalyzerVersion
        pyright = $PyrightVersion
        node = $NodeVersion
        shellcheck = $ShellCheckVersion
        cosign = $CosignVersion
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
        actionlint = $actionlintUrl
        conftest = $conftestUrl
        git_sizer = $gitSizerUrl
        vale = $valeUrl
        kube_linter = $kubeLinterUrl
        hadolint = $hadolintUrl
        devskim = $devSkimUrl
        shellcheck = $shellCheckUrl
        cosign = $cosignUrl
        node = $nodeUrl
        psscriptanalyzer = "https://www.powershellgallery.com/packages/PSScriptAnalyzer"
        pyright = "https://registry.npmjs.org/pyright"
        osv_database = $databaseUrl
    }
    files = $files
}
$manifestPath = Join-Path $bundle "bundle-manifest.json"
$manifest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath $manifestPath -Encoding UTF8

Write-Output "Native bundle prepared: $bundle"
Write-Output "Files recorded: $($files.Count)"
Write-Output "This connected-lane artifact can now be transferred to an isolated runner."
