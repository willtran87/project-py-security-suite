[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Wheel,
    [string]$Wheelhouse = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$wheelPath = (Resolve-Path -LiteralPath $Wheel).Path
if (-not $wheelPath.EndsWith(".whl", [StringComparison]::OrdinalIgnoreCase)) {
    throw "Wheel must identify a .whl file."
}
if (-not $Wheelhouse) {
    $Wheelhouse = Split-Path -Parent $wheelPath
}
$wheelhousePath = (Resolve-Path -LiteralPath $Wheelhouse).Path
$temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$smokeRoot = Join-Path $temporaryRoot ("pysec-wheel-smoke-" + [guid]::NewGuid().ToString("N"))
$resolvedSmoke = [IO.Path]::GetFullPath($smokeRoot)
if (-not $resolvedSmoke.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Smoke-test workspace escaped the system temporary directory."
}

try {
    & $Python -m venv $resolvedSmoke
    if ($LASTEXITCODE -ne 0) { throw "Could not create wheel smoke-test environment." }
    $smokePython = Join-Path $resolvedSmoke "Scripts\python.exe"
    if (-not (Test-Path -LiteralPath $smokePython)) {
        $smokePython = Join-Path $resolvedSmoke "bin/python"
    }
    & $smokePython -m pip install --no-index --find-links $wheelhousePath $wheelPath
    if ($LASTEXITCODE -ne 0) { throw "Offline wheel installation failed." }
    & $smokePython -c "import py_security_suite; print(py_security_suite.__version__)"
    if ($LASTEXITCODE -ne 0) { throw "Installed package import failed." }
    & $smokePython -m py_security_suite schema report-verification-1.0
    if ($LASTEXITCODE -ne 0) { throw "Installed schema export failed." }
    & $smokePython -m py_security_suite list-tools --format json
    if ($LASTEXITCODE -ne 0) { throw "Installed CLI smoke test failed." }
    Write-Output "Offline wheel smoke test passed: $wheelPath"
} finally {
    if (Test-Path -LiteralPath $resolvedSmoke) {
        $verified = [IO.Path]::GetFullPath($resolvedSmoke)
        if (-not $verified.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove an unverified smoke-test path."
        }
        Remove-Item -LiteralPath $verified -Recurse -Force
    }
}
