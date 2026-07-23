[CmdletBinding()]
param(
    [string]$BundlePath = "",
    [string]$ToolRoot = "",
    [string]$Python = "",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
function Get-NativeToolVersion {
    param([Parameter(Mandatory = $true)][string]$Executable)
    $startInfo = New-Object Diagnostics.ProcessStartInfo
    $startInfo.FileName = $Executable
    $startInfo.Arguments = "--version"
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "Tool version check could not start: $Executable"
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) {
        throw (
            "Tool version check failed with exit code $($process.ExitCode): " +
            $Executable
        )
    }
    $output = if ($stdout.Trim()) { $stdout } else { $stderr }
    $firstLine = $output -split "\r?\n" |
        ForEach-Object { $_.Trim() } | Where-Object { $_ } |
        Select-Object -First 1
    if (-not $firstLine) {
        throw "Tool version check returned no output: $Executable"
    }
    return $firstLine
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
        & $candidate -c "import venv" *> $null
        if ($LASTEXITCODE -eq 0) {
            $Python = $candidate
            break
        }
    }
    if (-not $Python) {
        throw "No Python 3.11 interpreter with venv was found; pass -Python explicitly."
    }
}
& $Python -c (
    "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 11) else 1)"
)
if ($LASTEXITCODE -ne 0) {
    throw "The native tool environment currently requires Python 3.11."
}
if (-not $BundlePath) {
    $BundlePath = Join-Path $workspace ".artifacts\native-bundle"
}
if (-not $ToolRoot) {
    $ToolRoot = Join-Path $workspace ".pysec-tools"
}
$bundle = (Resolve-Path -LiteralPath $BundlePath).Path
$toolDirectory = [IO.Path]::GetFullPath($ToolRoot)
$workspaceRoot = [IO.Path]::GetPathRoot($workspace)
if ($toolDirectory -eq $workspace -or $toolDirectory -eq $workspaceRoot) {
    throw "ToolRoot must be a dedicated directory, not the workspace or drive root."
}

$bundleManifestPath = Join-Path $bundle "bundle-manifest.json"
if (-not (Test-Path -LiteralPath $bundleManifestPath)) {
    throw "Native bundle manifest is missing: $bundleManifestPath"
}
$bundleManifest = Get-Content -Raw -LiteralPath $bundleManifestPath |
    ConvertFrom-Json
if ($bundleManifest.schema_version -ne "1") {
    throw "Unsupported native bundle schema."
}
if ($bundleManifest.platform -ne "windows-amd64") {
    throw "This installer requires a windows-amd64 native bundle."
}
foreach ($entry in $bundleManifest.files) {
    $path = Join-Path $bundle ($entry.path.Replace("/", "\"))
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Bundle file is missing: $($entry.path)"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($actual -ne $entry.sha256) {
        throw "Bundle checksum mismatch: $($entry.path)"
    }
}

if (Test-Path -LiteralPath $toolDirectory) {
    if (-not $Force) {
        throw "ToolRoot already exists; choose a new path or pass -Force: $toolDirectory"
    }
    $existingMarker = Join-Path $toolDirectory "native-install.json"
    if (-not (Test-Path -LiteralPath $existingMarker)) {
        $defaultToolRoot = [IO.Path]::GetFullPath(
            (Join-Path $workspace ".pysec-tools")
        )
        if (-not $toolDirectory.Equals(
            $defaultToolRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw "Refusing to replace a directory without native-install.json: $toolDirectory"
        }
    }
    Remove-Item -LiteralPath $toolDirectory -Recurse -Force
}

& $Python -m venv $toolDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Creating the native scanner virtual environment failed."
}
$venvPython = Join-Path $toolDirectory "Scripts\python.exe"
$wheelhouse = Join-Path $bundle "wheelhouse"
$packages = @(
    "bandit==$($bundleManifest.tools.bandit)",
    "semgrep==$($bundleManifest.tools.semgrep)",
    "detect-secrets==$($bundleManifest.tools.'detect-secrets')",
    "ruff==$($bundleManifest.tools.ruff)",
    "cyclonedx-bom==$($bundleManifest.tools.'cyclonedx-bom')",
    "zizmor==$($bundleManifest.tools.zizmor)",
    "py-security-suite==$($bundleManifest.tools.'py-security-suite')"
)
& $venvPython -m pip install --no-index --no-compile `
    --find-links $wheelhouse @packages
if ($LASTEXITCODE -ne 0) {
    throw "Offline installation from the native wheelhouse failed."
}
$scanCodeDirectory = Join-Path $toolDirectory "scancode-env"
& $Python -m venv $scanCodeDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Creating the ScanCode sidecar environment failed."
}
$scanCodePython = Join-Path $scanCodeDirectory "Scripts\python.exe"
& $scanCodePython -m pip install --no-index --no-compile `
    --find-links $wheelhouse `
    "scancode-toolkit==$($bundleManifest.tools.'scancode-toolkit')"
if ($LASTEXITCODE -ne 0) {
    throw "Offline ScanCode sidecar installation failed."
}
$artifactDirectory = Join-Path $toolDirectory "artifact-env"
& $Python -m venv $artifactDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Creating the artifact-tool sidecar environment failed."
}
$artifactPython = Join-Path $artifactDirectory "Scripts\python.exe"
& $artifactPython -m pip install --no-index --no-compile `
    --find-links $wheelhouse `
    "run-codeql==$($bundleManifest.tools.'run-codeql')" `
    "pypi-attestations==$($bundleManifest.tools.'pypi-attestations')" `
    "check-wheel-contents==$($bundleManifest.tools.'check-wheel-contents')" `
    "twine==$($bundleManifest.tools.twine)"
if ($LASTEXITCODE -ne 0) {
    throw "Offline artifact-tool sidecar installation failed."
}

$binDirectory = Join-Path $toolDirectory "bin"
$databaseRoot = Join-Path $toolDirectory "osv-db"
$thirdPartyRoot = Join-Path $toolDirectory "third-party"
$trivyRoot = Join-Path $thirdPartyRoot "trivy"
$gitleaksRoot = Join-Path $thirdPartyRoot "gitleaks"
$syftRoot = Join-Path $thirdPartyRoot "syft"
$grypeRoot = Join-Path $thirdPartyRoot "grype"
$truffleHogRoot = Join-Path $thirdPartyRoot "trufflehog"
$trivyCache = Join-Path $toolDirectory "trivy-cache"
$grypeCache = Join-Path $toolDirectory "grype-db"
New-Item -ItemType Directory -Path (
    $binDirectory,
    $databaseRoot,
    $trivyRoot,
    $gitleaksRoot,
    $syftRoot,
    $grypeRoot,
    $truffleHogRoot,
    $trivyCache,
    $grypeCache
) | Out-Null
Copy-Item -LiteralPath (Join-Path $bundle "bin\osv-scanner.exe") `
    -Destination (Join-Path $binDirectory "osv-scanner.exe")
Copy-Item -LiteralPath (Join-Path $bundle "osv-db\osv-scanner") `
    -Destination $databaseRoot -Recurse
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\trivy-windows-amd64.zip"
) -DestinationPath $trivyRoot
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\gitleaks-windows-amd64.zip"
) -DestinationPath $gitleaksRoot
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\syft-windows-amd64.zip"
) -DestinationPath $syftRoot
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\grype-windows-amd64.zip"
) -DestinationPath $grypeRoot
& tar.exe -xzf (
    Join-Path $bundle "archives\trufflehog-windows-amd64.tar.gz"
) -C $truffleHogRoot
if ($LASTEXITCODE -ne 0) {
    throw "Extracting the TruffleHog archive failed."
}
Copy-Item -Path (Join-Path $bundle "grype-db\*") `
    -Destination $grypeCache -Recurse -Force
$trivyExecutables = @(Get-ChildItem -LiteralPath $trivyRoot -Recurse -Filter "trivy.exe")
$gitleaksExecutables = @(
    Get-ChildItem -LiteralPath $gitleaksRoot -Recurse -Filter "gitleaks.exe"
)
$syftExecutables = @(
    Get-ChildItem -LiteralPath $syftRoot -Recurse -Filter "syft.exe"
)
$grypeExecutables = @(
    Get-ChildItem -LiteralPath $grypeRoot -Recurse -Filter "grype.exe"
)
$truffleHogExecutables = @(
    Get-ChildItem -LiteralPath $truffleHogRoot -Recurse -Filter "trufflehog.exe"
)
if (
    $trivyExecutables.Count -ne 1 -or
    $gitleaksExecutables.Count -ne 1 -or
    $syftExecutables.Count -ne 1 -or
    $grypeExecutables.Count -ne 1 -or
    $truffleHogExecutables.Count -ne 1
) {
    throw "Expected exactly one executable for every bundled native scanner."
}

$rulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/python-security.yml'))"
)).Trim()
$gitleaksRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/gitleaks.toml'))"
)).Trim()
$truffleHogExcludesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/trufflehog-exclude.txt'))"
)).Trim()
$toTomlPath = {
    param([string]$Value)
    return $Value.Replace("\", "/").Replace('"', '\"')
}
$bandit = & $toTomlPath (Join-Path $toolDirectory "Scripts\bandit.exe")
$semgrep = & $toTomlPath (Join-Path $toolDirectory "Scripts\semgrep.exe")
$detectSecrets = & $toTomlPath (Join-Path $toolDirectory "Scripts\detect-secrets.exe")
$ruff = & $toTomlPath (Join-Path $toolDirectory "Scripts\ruff.exe")
$cycloneDx = & $toTomlPath (Join-Path $toolDirectory "Scripts\cyclonedx-py.exe")
$zizmor = & $toTomlPath (Join-Path $toolDirectory "Scripts\zizmor.exe")
$scanCode = & $toTomlPath (Join-Path $scanCodeDirectory "Scripts\scancode.exe")
$osvScanner = & $toTomlPath (Join-Path $binDirectory "osv-scanner.exe")
$trivy = & $toTomlPath $trivyExecutables[0].FullName
$gitleaks = & $toTomlPath $gitleaksExecutables[0].FullName
$truffleHog = & $toTomlPath $truffleHogExecutables[0].FullName
$syft = & $toTomlPath $syftExecutables[0].FullName
$grype = & $toTomlPath $grypeExecutables[0].FullName
$runCodeQl = & $toTomlPath (
    Join-Path $artifactDirectory "Scripts\run-codeql.exe"
)
$pypiAttestations = & $toTomlPath (
    Join-Path $artifactDirectory "Scripts\pypi-attestations.exe"
)
$checkWheelContents = & $toTomlPath (
    Join-Path $artifactDirectory "Scripts\check-wheel-contents.exe"
)
$twine = & $toTomlPath (Join-Path $artifactDirectory "Scripts\twine.exe")
$database = & $toTomlPath $databaseRoot
$trivyDatabase = & $toTomlPath $trivyCache
$grypeDatabase = & $toTomlPath $grypeCache
$rules = & $toTomlPath $rulesPath
$gitleaksRules = & $toTomlPath $gitleaksRulesPath
$truffleHogExcludes = & $toTomlPath $truffleHogExcludesPath
$config = @"
schema_version = "1"
profile = "standard"

[isolation]
network = "deny"
require_attestation = true
execute_target_code = false

[execution]
max_workers = 1
max_output_bytes = 33554432

[policy]
required_scanners = []
block_severities = ["critical", "high"]
incomplete_is_blocking = true

[reports]
include_sanitized_evidence = true

[tools.bandit]
enabled = true
executable = "$bandit"
timeout_seconds = 300

[tools.semgrep]
enabled = true
executable = "$semgrep"
timeout_seconds = 600
rules_path = "$rules"

[tools.detect-secrets]
enabled = true
executable = "$detectSecrets"
timeout_seconds = 300

[tools.osv-scanner]
enabled = true
executable = "$osvScanner"
timeout_seconds = 300
database_path = "$database"

[tools.cyclonedx-py]
enabled = true
executable = "$cycloneDx"
timeout_seconds = 300

[tools.ruff]
enabled = true
executable = "$ruff"
timeout_seconds = 300

[tools.zizmor]
enabled = true
executable = "$zizmor"
timeout_seconds = 300

[tools.scancode]
enabled = true
executable = "$scanCode"
timeout_seconds = 1800

[tools.trivy]
enabled = true
executable = "$trivy"
timeout_seconds = 900
database_path = "$trivyDatabase"

[tools.gitleaks]
enabled = true
executable = "$gitleaks"
timeout_seconds = 900
rules_path = "$gitleaksRules"

[tools.trufflehog]
enabled = true
executable = "$truffleHog"
timeout_seconds = 900
rules_path = "$truffleHogExcludes"

[tools.syft]
enabled = true
executable = "$syft"
timeout_seconds = 600
artifacts_path = "dist"

[tools.grype]
enabled = true
executable = "$grype"
timeout_seconds = 900
database_path = "$grypeDatabase"
artifacts_path = "dist"

[tools.check-wheel-contents]
enabled = true
executable = "$checkWheelContents"
timeout_seconds = 300
artifacts_path = "dist"

[tools.twine]
enabled = true
executable = "$twine"
timeout_seconds = 300
artifacts_path = "dist"

[tools.pypi-attestations]
enabled = true
executable = "$pypiAttestations"
timeout_seconds = 300
artifacts_path = "dist"
provenance_path = "dist"
repository_url = ""

[tools.codeql]
enabled = true
executable = "$runCodeQl"
auxiliary_executable = "codeql"
timeout_seconds = 1800
"@
$configPath = Join-Path $toolDirectory "pysec.native.toml"
[IO.File]::WriteAllText(
    $configPath,
    $config,
    (New-Object Text.UTF8Encoding($false))
)

$versions = [ordered]@{
    bandit = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\bandit.exe"
    )
    semgrep = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\semgrep.exe"
    )
    "detect-secrets" = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\detect-secrets.exe"
    )
    "osv-scanner" = Get-NativeToolVersion (
        Join-Path $binDirectory "osv-scanner.exe"
    )
    ruff = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\ruff.exe"
    )
    "cyclonedx-py" = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\cyclonedx-py.exe"
    )
    zizmor = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\zizmor.exe"
    )
    scancode = Get-NativeToolVersion (
        Join-Path $scanCodeDirectory "Scripts\scancode.exe"
    )
    trivy = Get-NativeToolVersion ($trivyExecutables[0].FullName)
    gitleaks = Get-NativeToolVersion ($gitleaksExecutables[0].FullName)
    trufflehog = Get-NativeToolVersion ($truffleHogExecutables[0].FullName)
    syft = Get-NativeToolVersion ($syftExecutables[0].FullName)
    grype = Get-NativeToolVersion ($grypeExecutables[0].FullName)
    "run-codeql" = (
        "$($bundleManifest.tools.'run-codeql') " +
        "(wrapper; CodeQL CLI and packs separately staged)"
    )
    "check-wheel-contents" = Get-NativeToolVersion (
        Join-Path $artifactDirectory "Scripts\check-wheel-contents.exe"
    )
    twine = Get-NativeToolVersion (
        Join-Path $artifactDirectory "Scripts\twine.exe"
    )
    "pypi-attestations" = Get-NativeToolVersion (
        Join-Path $artifactDirectory "Scripts\pypi-attestations.exe"
    )
}
$installManifest = [ordered]@{
    schema_version = "1"
    installed_at = (Get-Date).ToUniversalTime().ToString("o")
    source_bundle_manifest_sha256 = (
        Get-FileHash -Algorithm SHA256 -LiteralPath $bundleManifestPath
    ).Hash.ToLowerInvariant()
    config = $configPath
    versions = $versions
    packages = @(& $venvPython -m pip freeze --all)
    scancode_packages = @(& $scanCodePython -m pip freeze --all)
    artifact_packages = @(& $artifactPython -m pip freeze --all)
}
$installManifest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $toolDirectory "native-install.json") `
        -Encoding UTF8

Write-Host "Native scanner environment installed without package-index access."
Write-Host "Tool root: $toolDirectory"
Write-Host "Configuration: $configPath"
$versions | Format-Table -AutoSize
