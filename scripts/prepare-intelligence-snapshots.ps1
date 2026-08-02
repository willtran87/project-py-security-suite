[CmdletBinding()]
param(
    [string]$OutputDirectory = "",
    [string]$VexPath = ""
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $workspace ".artifacts\intelligence-snapshots"
}
$output = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $output) {
    $existing = @(Get-ChildItem -LiteralPath $output -Force)
    if ($existing.Count -gt 0) {
        throw "Intelligence output must be new or empty: $output"
    }
} else {
    New-Item -ItemType Directory -Path $output | Out-Null
}

$sources = [ordered]@{
    kev = [ordered]@{
        Uri = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        File = "known_exploited_vulnerabilities.json"
    }
    epss = [ordered]@{
        Uri = "https://epss.cyentia.com/epss_scores-current.csv.gz"
        File = "epss_scores-current.csv.gz"
    }
}

$records = @()
foreach ($entry in $sources.GetEnumerator()) {
    $destination = Join-Path $output $entry.Value.File
    Invoke-WebRequest -Uri $entry.Value.Uri -OutFile $destination -UseBasicParsing
    $item = Get-Item -LiteralPath $destination
    if ($item.Length -le 0 -or $item.Length -gt 134217728) {
        throw "$($entry.Key) snapshot has an invalid size: $($item.Length)"
    }
    if ($entry.Key -eq "kev") {
        $document = Get-Content -LiteralPath $destination -Raw | ConvertFrom-Json
        if ($null -eq $document.vulnerabilities) {
            throw "CISA KEV snapshot does not contain vulnerabilities."
        }
    } else {
        $stream = [IO.File]::OpenRead($destination)
        try {
            $gzip = [IO.Compression.GZipStream]::new(
                $stream,
                [IO.Compression.CompressionMode]::Decompress
            )
            try {
                $reader = [IO.StreamReader]::new($gzip)
                try {
                    $firstLines = @($reader.ReadLine(), $reader.ReadLine()) -join "`n"
                    if ($firstLines -notmatch "cve,epss,percentile") {
                        throw "FIRST EPSS snapshot header is invalid."
                    }
                } finally {
                    $reader.Dispose()
                }
            } finally {
                $gzip.Dispose()
            }
        } finally {
            $stream.Dispose()
        }
    }
    $records += [ordered]@{
        kind = $entry.Key
        file = $entry.Value.File
        source = $entry.Value.Uri
        sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        size_bytes = $item.Length
    }
}

if ($VexPath) {
    $resolvedVex = (Resolve-Path -LiteralPath $VexPath).Path
    $vexItem = Get-Item -LiteralPath $resolvedVex
    if (-not $vexItem.PSIsContainer -and $vexItem.Length -le 134217728) {
        $vexDocument = Get-Content -LiteralPath $resolvedVex -Raw | ConvertFrom-Json
        if ($vexDocument.bomFormat -ne "CycloneDX" -or $null -eq $vexDocument.vulnerabilities) {
            throw "VEX input is not a CycloneDX document with vulnerabilities."
        }
        $destination = Join-Path $output "product-vex.cdx.json"
        Copy-Item -LiteralPath $resolvedVex -Destination $destination
        $records += [ordered]@{
            kind = "vex"
            file = "product-vex.cdx.json"
            source = $resolvedVex
            sha256 = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
            size_bytes = (Get-Item -LiteralPath $destination).Length
        }
    } else {
        throw "VEX input must be a bounded regular file."
    }
}

$manifest = [ordered]@{
    schema_version = "1.0"
    prepared_at = [DateTimeOffset]::UtcNow.ToString("o")
    approval_status = "pending-review"
    snapshots = $records
}
$manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (
    Join-Path $output "intelligence-manifest.json"
) -Encoding utf8
Write-Output "Intelligence snapshots prepared for review: $output"
