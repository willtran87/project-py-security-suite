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
    "mypy==$($bundleManifest.tools.mypy)",
    "vulture==$($bundleManifest.tools.vulture)",
    "tach==$($bundleManifest.tools.tach)",
    "pylint==$($bundleManifest.tools.pylint)",
    "radon==$($bundleManifest.tools.radon)",
    "reuse[charset-normalizer]==$($bundleManifest.tools.reuse)",
    "flawfinder==$($bundleManifest.tools.flawfinder)",
    "cyclonedx-bom==$($bundleManifest.tools.'cyclonedx-bom')",
    "uv==$($bundleManifest.tools.uv)",
    "zizmor==$($bundleManifest.tools.zizmor)",
    "deptry==$($bundleManifest.tools.deptry)",
    "diff-cover==$($bundleManifest.tools.'diff-cover')",
    "pipdeptree==$($bundleManifest.tools.pipdeptree)",
    "validate-pyproject==$($bundleManifest.tools.'validate-pyproject')",
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
$checkovDirectory = Join-Path $toolDirectory "checkov-env"
& $Python -m venv $checkovDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Creating the Checkov sidecar environment failed."
}
$checkovPython = Join-Path $checkovDirectory "Scripts\python.exe"
& $checkovPython -m pip install --no-index --no-compile `
    --find-links $wheelhouse "checkov==$($bundleManifest.tools.checkov)"
if ($LASTEXITCODE -ne 0) {
    throw "Offline Checkov sidecar installation failed."
}

$binDirectory = Join-Path $toolDirectory "bin"
$databaseRoot = Join-Path $toolDirectory "osv-db"
$thirdPartyRoot = Join-Path $toolDirectory "third-party"
$trivyRoot = Join-Path $thirdPartyRoot "trivy"
$gitleaksRoot = Join-Path $thirdPartyRoot "gitleaks"
$syftRoot = Join-Path $thirdPartyRoot "syft"
$grypeRoot = Join-Path $thirdPartyRoot "grype"
$truffleHogRoot = Join-Path $thirdPartyRoot "trufflehog"
$actionlintRoot = Join-Path $thirdPartyRoot "actionlint"
$conftestRoot = Join-Path $thirdPartyRoot "conftest"
$gitSizerRoot = Join-Path $thirdPartyRoot "git-sizer"
$valeRoot = Join-Path $thirdPartyRoot "vale"
$kubeLinterRoot = Join-Path $thirdPartyRoot "kube-linter"
$hadolintRoot = Join-Path $thirdPartyRoot "hadolint"
$devSkimRoot = Join-Path $thirdPartyRoot "devskim"
$shellCheckRoot = Join-Path $thirdPartyRoot "shellcheck"
$cosignRoot = Join-Path $thirdPartyRoot "cosign"
$nodeRoot = Join-Path $thirdPartyRoot "node"
$nodeToolsRoot = Join-Path $thirdPartyRoot "node-tools"
$powerShellModuleRoot = Join-Path $toolDirectory "powershell-modules"
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
    $actionlintRoot,
    $conftestRoot,
    $gitSizerRoot,
    $valeRoot,
    $kubeLinterRoot,
    $hadolintRoot,
    $devSkimRoot,
    $shellCheckRoot,
    $cosignRoot,
    $nodeRoot,
    $nodeToolsRoot,
    $powerShellModuleRoot,
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
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\actionlint-windows-amd64.zip"
) -DestinationPath $actionlintRoot
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\conftest-windows-amd64.zip"
) -DestinationPath $conftestRoot
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\git-sizer-windows-amd64.zip"
) -DestinationPath $gitSizerRoot
Expand-Archive -LiteralPath (
    Join-Path $bundle "archives\vale-windows-amd64.zip"
) -DestinationPath $valeRoot
& tar.exe -xzf (
    Join-Path $bundle "archives\kube-linter-windows-amd64.tar.gz"
) -C $kubeLinterRoot
if ($LASTEXITCODE -ne 0) {
    throw "Extracting the KubeLinter archive failed."
}
Copy-Item -LiteralPath (Join-Path $bundle "bin\hadolint.exe") `
    -Destination (Join-Path $hadolintRoot "hadolint.exe")
Expand-Archive -LiteralPath (Join-Path $bundle "archives\shellcheck-windows.zip") `
    -DestinationPath $shellCheckRoot
Copy-Item -LiteralPath (Join-Path $bundle "bin\cosign.exe") `
    -Destination (Join-Path $cosignRoot "cosign.exe")
Expand-Archive -LiteralPath (Join-Path $bundle "archives\node-windows-x64.zip") `
    -DestinationPath $nodeRoot
Copy-Item -Path (Join-Path $bundle "node-tools\*") `
    -Destination $nodeToolsRoot -Recurse
Copy-Item -Path (Join-Path $bundle "powershell-modules\*") `
    -Destination $powerShellModuleRoot -Recurse
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) {
    throw "Installing DevSkim requires the .NET 8 SDK on the isolated runner."
}
$dotnetMajor = (& $dotnet.Source --version).Split(".")[0]
if ([int]$dotnetMajor -lt 8) {
    throw "Installing DevSkim requires the .NET 8 SDK or newer."
}
$nugetDirectory = Join-Path $bundle "nuget"
$nugetConfig = Join-Path $toolDirectory "devskim.nuget.config"
$escapedNugetDirectory = [Security.SecurityElement]::Escape($nugetDirectory)
$nugetXml = @"
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="offline-devskim" value="$escapedNugetDirectory" />
  </packageSources>
</configuration>
"@
[IO.File]::WriteAllText(
    $nugetConfig,
    $nugetXml,
    (New-Object Text.UTF8Encoding($false))
)
& $dotnet.Source tool install `
    --tool-path $devSkimRoot `
    --configfile $nugetConfig `
    "Microsoft.CST.DevSkim.CLI" `
    --version $bundleManifest.tools.devskim
if ($LASTEXITCODE -ne 0) {
    throw "Offline DevSkim installation failed."
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
$actionlintExecutables = @(
    Get-ChildItem -LiteralPath $actionlintRoot -Recurse -Filter "actionlint.exe"
)
$conftestExecutables = @(
    Get-ChildItem -LiteralPath $conftestRoot -Recurse -Filter "conftest.exe"
)
$gitSizerExecutables = @(
    Get-ChildItem -LiteralPath $gitSizerRoot -Recurse -Filter "git-sizer.exe"
)
$valeExecutables = @(
    Get-ChildItem -LiteralPath $valeRoot -Recurse -Filter "vale.exe"
)
$kubeLinterExecutables = @(
    Get-ChildItem -LiteralPath $kubeLinterRoot -Recurse -Filter "kube-linter.exe"
)
$hadolintExecutables = @(
    Get-ChildItem -LiteralPath $hadolintRoot -Recurse -Filter "hadolint.exe"
)
$devSkimExecutables = @(
    Get-ChildItem -LiteralPath $devSkimRoot -Filter "devskim.exe"
)
$shellCheckExecutables = @(
    Get-ChildItem -LiteralPath $shellCheckRoot -Recurse -Filter "shellcheck.exe"
)
$cosignExecutables = @(
    Get-ChildItem -LiteralPath $cosignRoot -Recurse -Filter "cosign.exe"
)
$nodeExecutables = @(
    Get-ChildItem -LiteralPath $nodeRoot -Recurse -Filter "node.exe"
)
$pyrightCli = Join-Path $nodeToolsRoot "node_modules\pyright\index.js"
$psscriptAnalyzerModules = @(
    Get-ChildItem -LiteralPath $powerShellModuleRoot -Recurse `
        -Filter "PSScriptAnalyzer.psd1"
)
if (
    $trivyExecutables.Count -ne 1 -or
    $gitleaksExecutables.Count -ne 1 -or
    $syftExecutables.Count -ne 1 -or
    $grypeExecutables.Count -ne 1 -or
    $truffleHogExecutables.Count -ne 1 -or
    $actionlintExecutables.Count -ne 1 -or
    $conftestExecutables.Count -ne 1 -or
    $gitSizerExecutables.Count -ne 1 -or
    $valeExecutables.Count -ne 1 -or
    $kubeLinterExecutables.Count -ne 1 -or
    $hadolintExecutables.Count -ne 1 -or
    $devSkimExecutables.Count -ne 1 -or
    $shellCheckExecutables.Count -ne 1 -or
    $cosignExecutables.Count -ne 1 -or
    $nodeExecutables.Count -ne 1 -or
    $psscriptAnalyzerModules.Count -ne 1 -or
    -not (Test-Path -LiteralPath $pyrightCli)
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
$mypyRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/mypy.ini'))"
)).Trim()
$vultureRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/vulture.toml'))"
)).Trim()
$pylintRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/pylint.ini'))"
)).Trim()
$actionlintRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/actionlint.yaml'))"
)).Trim()
$hadolintRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/hadolint.yaml'))"
)).Trim()
$psscriptAnalyzerRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/psscriptanalyzer.psd1'))"
)).Trim()
$pyrightRulesPath = (& $venvPython -c (
    "from importlib.resources import files; " +
    "print(files('py_security_suite').joinpath('rules/pyrightconfig.json'))"
)).Trim()
$toTomlPath = {
    param([string]$Value)
    return $Value.Replace("\", "/").Replace('"', '\"')
}
$toSha256 = {
    param([Parameter(Mandatory = $true)][string]$Value)
    return (
        Get-FileHash -Algorithm SHA256 -LiteralPath $Value
    ).Hash.ToLowerInvariant()
}
$bandit = & $toTomlPath (Join-Path $toolDirectory "Scripts\bandit.exe")
$semgrep = & $toTomlPath (Join-Path $toolDirectory "Scripts\semgrep.exe")
$detectSecrets = & $toTomlPath (Join-Path $toolDirectory "Scripts\detect-secrets.exe")
$ruff = & $toTomlPath (Join-Path $toolDirectory "Scripts\ruff.exe")
$mypy = & $toTomlPath (Join-Path $toolDirectory "Scripts\mypy.exe")
$deptry = & $toTomlPath (Join-Path $toolDirectory "Scripts\deptry.exe")
$diffCover = & $toTomlPath (Join-Path $toolDirectory "Scripts\diff-cover.exe")
$vulture = & $toTomlPath (Join-Path $toolDirectory "Scripts\vulture.exe")
$tach = & $toTomlPath (Join-Path $toolDirectory "Scripts\tach.exe")
$pylint = & $toTomlPath (Join-Path $toolDirectory "Scripts\pylint.exe")
$radon = & $toTomlPath (Join-Path $toolDirectory "Scripts\radon.exe")
$reuse = & $toTomlPath (Join-Path $toolDirectory "Scripts\reuse.exe")
$pysec = & $toTomlPath (Join-Path $toolDirectory "Scripts\pysec.exe")
$pysecEvidence = & $toTomlPath (
    Join-Path $toolDirectory "Scripts\pysec-evidence.exe"
)
$flawfinder = & $toTomlPath (Join-Path $toolDirectory "Scripts\flawfinder.exe")
$cycloneDx = & $toTomlPath (Join-Path $toolDirectory "Scripts\cyclonedx-py.exe")
$uv = & $toTomlPath (Join-Path $toolDirectory "Scripts\uv.exe")
$zizmor = & $toTomlPath (Join-Path $toolDirectory "Scripts\zizmor.exe")
$scanCode = & $toTomlPath (Join-Path $scanCodeDirectory "Scripts\scancode.exe")
$osvScanner = & $toTomlPath (Join-Path $binDirectory "osv-scanner.exe")
$trivy = & $toTomlPath $trivyExecutables[0].FullName
$gitleaks = & $toTomlPath $gitleaksExecutables[0].FullName
$truffleHog = & $toTomlPath $truffleHogExecutables[0].FullName
$syft = & $toTomlPath $syftExecutables[0].FullName
$grype = & $toTomlPath $grypeExecutables[0].FullName
$actionlint = & $toTomlPath $actionlintExecutables[0].FullName
$conftest = & $toTomlPath $conftestExecutables[0].FullName
$gitSizer = & $toTomlPath $gitSizerExecutables[0].FullName
$vale = & $toTomlPath $valeExecutables[0].FullName
$kubeLinter = & $toTomlPath $kubeLinterExecutables[0].FullName
$hadolint = & $toTomlPath $hadolintExecutables[0].FullName
$devSkim = & $toTomlPath $devSkimExecutables[0].FullName
$shellCheck = & $toTomlPath $shellCheckExecutables[0].FullName
$cosign = & $toTomlPath $cosignExecutables[0].FullName
$node = & $toTomlPath $nodeExecutables[0].FullName
$pyright = & $toTomlPath $pyrightCli
$pyrightRules = & $toTomlPath $pyrightRulesPath
$powerShell = & $toTomlPath (Get-Command powershell.exe).Source
$powerShellModules = & $toTomlPath $powerShellModuleRoot
$psscriptAnalyzerRules = & $toTomlPath $psscriptAnalyzerRulesPath
$checkov = & $toTomlPath $checkovPython
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
$pipdeptree = & $toTomlPath (Join-Path $toolDirectory "Scripts\pipdeptree.exe")
$validatePyproject = & $toTomlPath (
    Join-Path $toolDirectory "Scripts\validate-pyproject.exe"
)
$banditSha256 = & $toSha256 $bandit
$semgrepSha256 = & $toSha256 $semgrep
$detectSecretsSha256 = & $toSha256 $detectSecrets
$ruffSha256 = & $toSha256 $ruff
$mypySha256 = & $toSha256 $mypy
$deptrySha256 = & $toSha256 $deptry
$diffCoverSha256 = & $toSha256 $diffCover
$vultureSha256 = & $toSha256 $vulture
$tachSha256 = & $toSha256 $tach
$pylintSha256 = & $toSha256 $pylint
$radonSha256 = & $toSha256 $radon
$reuseSha256 = & $toSha256 $reuse
$pysecSha256 = & $toSha256 $pysec
$pysecEvidenceSha256 = & $toSha256 $pysecEvidence
$flawfinderSha256 = & $toSha256 $flawfinder
$cycloneDxSha256 = & $toSha256 $cycloneDx
$uvSha256 = & $toSha256 $uv
$zizmorSha256 = & $toSha256 $zizmor
$scanCodeSha256 = & $toSha256 $scanCode
$osvScannerSha256 = & $toSha256 $osvScanner
$trivySha256 = & $toSha256 $trivy
$gitleaksSha256 = & $toSha256 $gitleaks
$truffleHogSha256 = & $toSha256 $truffleHog
$syftSha256 = & $toSha256 $syft
$grypeSha256 = & $toSha256 $grype
$actionlintSha256 = & $toSha256 $actionlint
$conftestSha256 = & $toSha256 $conftest
$gitSizerSha256 = & $toSha256 $gitSizer
$valeSha256 = & $toSha256 $vale
$kubeLinterSha256 = & $toSha256 $kubeLinter
$hadolintSha256 = & $toSha256 $hadolint
$devSkimSha256 = & $toSha256 $devSkim
$shellCheckSha256 = & $toSha256 $shellCheck
$cosignSha256 = & $toSha256 $cosign
$nodeSha256 = & $toSha256 $node
$powerShellSha256 = & $toSha256 $powerShell
$checkovSha256 = & $toSha256 $checkov
$runCodeQlSha256 = & $toSha256 $runCodeQl
$pypiAttestationsSha256 = & $toSha256 $pypiAttestations
$checkWheelContentsSha256 = & $toSha256 $checkWheelContents
$twineSha256 = & $toSha256 $twine
$pipdeptreeSha256 = & $toSha256 $pipdeptree
$validatePyprojectSha256 = & $toSha256 $validatePyproject
$database = & $toTomlPath $databaseRoot
$trivyDatabase = & $toTomlPath $trivyCache
$grypeDatabase = & $toTomlPath $grypeCache
$rules = & $toTomlPath $rulesPath
$gitleaksRules = & $toTomlPath $gitleaksRulesPath
$truffleHogExcludes = & $toTomlPath $truffleHogExcludesPath
$mypyRules = & $toTomlPath $mypyRulesPath
$vultureRules = & $toTomlPath $vultureRulesPath
$pylintRules = & $toTomlPath $pylintRulesPath
$actionlintRules = & $toTomlPath $actionlintRulesPath
$hadolintRules = & $toTomlPath $hadolintRulesPath
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
executable_sha256 = "$banditSha256"
timeout_seconds = 300

[tools.semgrep]
enabled = true
executable = "$semgrep"
executable_sha256 = "$semgrepSha256"
timeout_seconds = 600
rules_path = "$rules"

[tools.detect-secrets]
enabled = true
executable = "$detectSecrets"
executable_sha256 = "$detectSecretsSha256"
timeout_seconds = 300

[tools.osv-scanner]
enabled = true
executable = "$osvScanner"
executable_sha256 = "$osvScannerSha256"
timeout_seconds = 300
database_path = "$database"
maximum_database_age_days = 10

[tools.cyclonedx-py]
enabled = true
executable = "$cycloneDx"
executable_sha256 = "$cycloneDxSha256"
auxiliary_executable = "$uv"
auxiliary_executable_sha256 = "$uvSha256"
timeout_seconds = 300

[tools.ruff]
enabled = true
executable = "$ruff"
executable_sha256 = "$ruffSha256"
timeout_seconds = 300

[tools.ruff-quality]
enabled = true
executable = "$ruff"
executable_sha256 = "$ruffSha256"
timeout_seconds = 300

[tools.ruff-format]
enabled = true
executable = "$ruff"
executable_sha256 = "$ruffSha256"
timeout_seconds = 300

[tools.pylint]
enabled = true
executable = "$pylint"
executable_sha256 = "$pylintSha256"
timeout_seconds = 600
rules_path = "$pylintRules"

[tools.mypy]
enabled = true
executable = "$mypy"
executable_sha256 = "$mypySha256"
timeout_seconds = 600
rules_path = "$mypyRules"

[tools.pyright]
enabled = true
executable = "$node"
executable_sha256 = "$nodeSha256"
timeout_seconds = 600
database_path = "$pyright"
rules_path = "$pyrightRules"

[tools.deptry]
enabled = true
executable = "$deptry"
executable_sha256 = "$deptrySha256"
timeout_seconds = 600

[tools.vulture]
enabled = true
executable = "$vulture"
executable_sha256 = "$vultureSha256"
timeout_seconds = 300
rules_path = "$vultureRules"

[tools.radon]
enabled = true
executable = "$radon"
executable_sha256 = "$radonSha256"
timeout_seconds = 300

[tools.tach]
enabled = true
executable = "$tach"
executable_sha256 = "$tachSha256"
timeout_seconds = 300

[tools.reachability]
enabled = true
executable = "$pysec"
executable_sha256 = "$pysecSha256"
timeout_seconds = 600
minimum_island_loc = 100
discover_framework_roots = true

[tools.coverage]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 300
artifacts_path = ".artifacts/test-evidence/coverage.json"
minimum_coverage_percent = 80.0

[tools.junit]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 300
artifacts_path = ".artifacts/test-evidence/junit.xml"

[tools.hypothesis]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/hypothesis-junit.xml"

[tools.schemathesis]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/schemathesis-junit.xml"

[tools.diff-cover]
enabled = true
executable = "$diffCover"
executable_sha256 = "$diffCoverSha256"
timeout_seconds = 300
artifacts_path = ".artifacts/test-evidence/coverage.xml"
minimum_coverage_percent = 80.0
compare_branch = "origin/main"

[tools.psscriptanalyzer]
enabled = true
executable = "$powerShell"
executable_sha256 = "$powerShellSha256"
timeout_seconds = 600
rules_path = "$psscriptAnalyzerRules"
database_path = "$powerShellModules"

[tools.shellcheck]
enabled = true
executable = "$shellCheck"
executable_sha256 = "$shellCheckSha256"
timeout_seconds = 300

[tools.zizmor]
enabled = true
executable = "$zizmor"
executable_sha256 = "$zizmorSha256"
timeout_seconds = 300

[tools.actionlint]
enabled = true
executable = "$actionlint"
executable_sha256 = "$actionlintSha256"
timeout_seconds = 300
rules_path = "$actionlintRules"

[tools.hadolint]
enabled = true
executable = "$hadolint"
executable_sha256 = "$hadolintSha256"
timeout_seconds = 300
rules_path = "$hadolintRules"

[tools.scancode]
enabled = true
executable = "$scanCode"
executable_sha256 = "$scanCodeSha256"
timeout_seconds = 1800

[tools.trivy]
enabled = true
executable = "$trivy"
executable_sha256 = "$trivySha256"
timeout_seconds = 900
database_path = "$trivyDatabase"

[tools.checkov]
enabled = true
executable = "$checkov"
executable_sha256 = "$checkovSha256"
timeout_seconds = 1200

[tools.gitleaks]
enabled = true
executable = "$gitleaks"
executable_sha256 = "$gitleaksSha256"
timeout_seconds = 900
rules_path = "$gitleaksRules"

[tools.trufflehog]
enabled = true
executable = "$truffleHog"
executable_sha256 = "$truffleHogSha256"
timeout_seconds = 900
rules_path = "$truffleHogExcludes"

[tools.devskim]
enabled = true
executable = "$devSkim"
executable_sha256 = "$devSkimSha256"
timeout_seconds = 900

[tools.flawfinder]
enabled = true
executable = "$flawfinder"
executable_sha256 = "$flawfinderSha256"
timeout_seconds = 600

[tools.reuse]
enabled = true
executable = "$reuse"
executable_sha256 = "$reuseSha256"
timeout_seconds = 600

[tools.syft]
enabled = true
executable = "$syft"
executable_sha256 = "$syftSha256"
timeout_seconds = 600
artifacts_path = "dist"

[tools.grype]
enabled = true
executable = "$grype"
executable_sha256 = "$grypeSha256"
timeout_seconds = 900
database_path = "$grypeDatabase"
maximum_database_age_days = 10
artifacts_path = "dist"

[tools.check-wheel-contents]
enabled = true
executable = "$checkWheelContents"
executable_sha256 = "$checkWheelContentsSha256"
timeout_seconds = 300
artifacts_path = "dist"

[tools.twine]
enabled = true
executable = "$twine"
executable_sha256 = "$twineSha256"
timeout_seconds = 300
artifacts_path = "dist"

[tools.pypi-attestations]
enabled = true
executable = "$pypiAttestations"
executable_sha256 = "$pypiAttestationsSha256"
timeout_seconds = 300
artifacts_path = "dist"
provenance_path = "dist"
repository_url = ""

[tools.cosign]
enabled = true
executable = "$cosign"
executable_sha256 = "$cosignSha256"
timeout_seconds = 300
artifacts_path = "dist"
provenance_path = "dist"
# Configure either public_key_path, or all three keyless trust settings:
# database_path = "security-data/sigstore-trusted-root.json"
# certificate_identity = "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main"
# certificate_oidc_issuer = "https://token.actions.githubusercontent.com"

[tools.scorecard]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "scorecard.json"

[tools.conftest]
enabled = true
executable = "$conftest"
executable_sha256 = "$conftestSha256"
timeout_seconds = 600
# Configure rules_path to an approved local Rego policy directory.

[tools.git-sizer]
enabled = true
executable = "$gitSizer"
executable_sha256 = "$gitSizerSha256"
timeout_seconds = 600

[tools.validate-pyproject]
enabled = true
executable = "$validatePyproject"
executable_sha256 = "$validatePyprojectSha256"
timeout_seconds = 300

[tools.pipdeptree]
enabled = true
executable = "$pipdeptree"
executable_sha256 = "$pipdeptreeSha256"
timeout_seconds = 300
# Configure auxiliary_executable to the approved target-environment Python.

[tools.vale]
enabled = true
executable = "$vale"
executable_sha256 = "$valeSha256"
timeout_seconds = 600
# Configure rules_path to an approved local .vale.ini.

[tools.kube-linter]
enabled = true
executable = "$kubeLinter"
executable_sha256 = "$kubeLinterSha256"
timeout_seconds = 600

[tools.crosshair]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "crosshair.json"

[tools.atheris]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "atheris.json"

[tools.mutmut]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "mutmut.json"

[tools.check-manifest]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "check-manifest.json"

[tools.clamav]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "clamav.json"

[tools.github-attestation]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = "github-attestation.json"

[tools.zap]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/zap.json"

[tools.pytm]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/pytm.json"

[tools.in-toto]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/in-toto.json"

[tools.reproducible-build]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/reproducible-build.json"

[tools.oci-image]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/oci-image.json"

[tools.yara]
enabled = true
executable = "$pysecEvidence"
executable_sha256 = "$pysecEvidenceSha256"
timeout_seconds = 60
artifacts_path = ".artifacts/test-evidence/yara.json"

[tools.codeql]
enabled = true
executable = "$runCodeQl"
executable_sha256 = "$runCodeQlSha256"
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
    mypy = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\mypy.exe"
    )
    deptry = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\deptry.exe"
    )
    "diff-cover" = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\diff-cover.exe"
    )
    vulture = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\vulture.exe"
    )
    tach = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\tach.exe"
    )
    pylint = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\pylint.exe"
    )
    radon = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\radon.exe"
    )
    reuse = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\reuse.exe"
    )
    "pysec-evidence" = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\pysec-evidence.exe"
    )
    flawfinder = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\flawfinder.exe"
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
    actionlint = Get-NativeToolVersion ($actionlintExecutables[0].FullName)
    conftest = Get-NativeToolVersion ($conftestExecutables[0].FullName)
    "git-sizer" = Get-NativeToolVersion ($gitSizerExecutables[0].FullName)
    vale = Get-NativeToolVersion ($valeExecutables[0].FullName)
    "kube-linter" = Get-NativeToolVersion ($kubeLinterExecutables[0].FullName)
    hadolint = Get-NativeToolVersion ($hadolintExecutables[0].FullName)
    devskim = Get-NativeToolVersion ($devSkimExecutables[0].FullName)
    shellcheck = Get-NativeToolVersion ($shellCheckExecutables[0].FullName)
    cosign = Get-NativeToolVersion ($cosignExecutables[0].FullName)
    node = Get-NativeToolVersion ($nodeExecutables[0].FullName)
    pyright = (& $nodeExecutables[0].FullName $pyrightCli --version | Out-String).Trim()
    psscriptanalyzer = (& powershell.exe -NoLogo -NoProfile -NonInteractive `
        -Command (
            "`$env:PSModulePath='$powerShellModuleRoot'; " +
            "Import-Module PSScriptAnalyzer; " +
            "(Get-Module PSScriptAnalyzer).Version.ToString()"
        ) | Out-String).Trim()
    checkov = (& $checkovPython -c (
        "from checkov.main import Checkov; raise SystemExit(Checkov().run())"
    ) --version | Out-String).Trim()
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
    pipdeptree = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\pipdeptree.exe"
    )
    "validate-pyproject" = Get-NativeToolVersion (
        Join-Path $toolDirectory "Scripts\validate-pyproject.exe"
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
    checkov_packages = @(& $checkovPython -m pip freeze --all)
}
$installManifest | ConvertTo-Json -Depth 8 |
    Set-Content -LiteralPath (Join-Path $toolDirectory "native-install.json") `
        -Encoding UTF8

Write-Output "Native scanner environment installed without package-index access."
Write-Output "Tool root: $toolDirectory"
Write-Output "Configuration: $configPath"
$versions | Format-Table -AutoSize
