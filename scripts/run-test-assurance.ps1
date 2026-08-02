[CmdletBinding()]
param(
    [string]$Target = "",
    [string]$Python = "",
    [string]$TestPath = "tests",
    [string]$PropertyTestPath = "",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $Target) {
    $Target = $workspace
}
$targetRoot = (Resolve-Path -LiteralPath $Target).Path
if (-not $Python) {
    $candidate = Join-Path $targetRoot ".venv\Scripts\python.exe"
    if (Test-Path -LiteralPath $candidate) {
        $Python = $candidate
    } else {
        $Python = (Get-Command python -ErrorAction Stop).Source
    }
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $targetRoot ".artifacts\test-evidence"
}
$evidenceRoot = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $evidenceRoot | Out-Null

$previousCoverageFile = $env:COVERAGE_FILE
try {
    $env:COVERAGE_FILE = Join-Path $evidenceRoot ".coverage"
    Push-Location $targetRoot
    try {
        & $Python -m coverage erase
        & $Python -m coverage run --branch -m pytest `
            "--junitxml=$(Join-Path $evidenceRoot 'junit.xml')" $TestPath
        if ($LASTEXITCODE -ne 0) {
            throw "The test assurance lane failed. JUnit evidence was retained."
        }
        & $Python -m coverage json -o (Join-Path $evidenceRoot "coverage.json")
        if ($LASTEXITCODE -ne 0) {
            throw "Generating coverage JSON failed."
        }
        & $Python -m coverage xml -o (Join-Path $evidenceRoot "coverage.xml")
        if ($LASTEXITCODE -ne 0) {
            throw "Generating coverage XML failed."
        }
        if ($PropertyTestPath) {
            & $Python -m pytest -q `
                "--junitxml=$(Join-Path $evidenceRoot 'hypothesis-junit.xml')" `
                $PropertyTestPath
            if ($LASTEXITCODE -ne 0) {
                throw "The property-test assurance lane failed."
            }
        }
    } finally {
        Pop-Location
    }
} finally {
    $env:COVERAGE_FILE = $previousCoverageFile
}

Write-Output "Test assurance evidence written to $evidenceRoot"
