[CmdletBinding()]
param(
    [string]$ToolRoot = "",
    [string]$Output = "",
    [string]$SuitePython = ""
)

$ErrorActionPreference = "Stop"
$workspace = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
if (-not $ToolRoot) {
    $ToolRoot = Join-Path $workspace ".pysec-tools"
}
if (-not $Output) {
    $Output = Join-Path $workspace ".artifacts\detection-validation"
}
$toolDirectory = (Resolve-Path -LiteralPath $ToolRoot).Path
$python = if ($SuitePython) {
    (Resolve-Path -LiteralPath $SuitePython).Path
} else {
    Join-Path $toolDirectory "Scripts\python.exe"
}
$config = Join-Path $toolDirectory "pysec.native.toml"
foreach ($required in @($python, $config)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Detection validation requires the installed native suite: $required"
    }
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    "pysec-detection-validation-" + [guid]::NewGuid().ToString("N")
)
$resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$resolvedFixture = [IO.Path]::GetFullPath($fixtureRoot)
if (-not $resolvedFixture.StartsWith(
    $resolvedTemp,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw "Detection fixture escaped the system temporary directory."
}

New-Item -ItemType Directory -Path $resolvedFixture | Out-Null
$validationConfig = "$resolvedFixture.toml"
try {
    # A repository baseline is target-bound and must never be applied to the
    # intentionally separate detection corpus. Keep every other governed
    # setting, including the pinned offline threat-intelligence snapshots.
    $configText = Get-Content -Raw -LiteralPath $config
    $configText = $configText -replace '(?m)^baseline_(path|sha256)\s*=.*\r?\n?', ''
    $configText = $configText -replace (
        '(?m)^(kev|epss|vex|approval)_(path|sha256)\s*=.*\r?\n?'
    ), ''
    $portableToolRoot = $toolDirectory.Replace('\', '/')
    $portableRules = (Join-Path $workspace (
        'src\py_security_suite\rules\python-security.yml'
    )).Replace('\', '/')
    $configText = $configText -replace (
        '(?m)^bundle_root\s*=.*$'
    ), ('bundle_root = "' + $portableToolRoot + '"')
    $configText = $configText -replace (
        '(?m)^rules_path\s*=\s*"src/py_security_suite/rules/python-security.yml"$'
    ), ('rules_path = "' + $portableRules + '"')
    # This corpus measures detector behavior, not advisory freshness. Keep the
    # required OSV control executable while preventing an unrelated snapshot-age
    # rollover from invalidating the SAST/secret positive and negative controls.
    $configText = $configText -replace (
        '(?m)^maximum_database_age_days\s*=\s*10$'
    ), 'maximum_database_age_days = 365'
    [IO.File]::WriteAllText(
        $validationConfig,
        $configText,
        [Text.UTF8Encoding]::new($false)
    )

    $source = @'
import logging
import os
import subprocess

import requests
import sentry_sdk
from fastapi import HTTPException


sentry_sdk.init(send_default_pii=True)


def intentionally_unsafe(user_input: str) -> None:
    eval(user_input)
    subprocess.run(user_input, shell=True)


def intentionally_exposed() -> None:
    token = os.getenv("AUTH_TOKEN")
    logging.error("token=%s", token)
    sentry_sdk.set_context("request", {"token": token})


def intentionally_expose_private_data(user) -> None:
    email = user.email
    logging.info("email=%s", email)
    sentry_sdk.set_user({"email": email})


def intentionally_expose_request_data(request) -> None:
    payload = request.json()
    logging.warning("request=%s", payload)
    sentry_sdk.set_context("request-body", payload)


def intentionally_expose_request_attribute(request) -> None:
    logging.warning("request=%s", request.data)


def intentionally_expose_named_secret(settings, span) -> None:
    span.set_attribute("auth.token", settings.api_key)


def intentionally_expose_runtime_state() -> None:
    logging.debug("runtime=%s", locals())


def intentionally_expose_url_data(user) -> None:
    token = os.getenv("API_KEY")
    requests.get("https://service.invalid/check", params={"access_token": token})
    requests.get("https://service.invalid/profile", params={"email": user.email})


def intentionally_expose_exception() -> None:
    try:
        raise RuntimeError("internal connection detail")
    except RuntimeError as error:
        raise HTTPException(status_code=500, detail=str(error)) from error
'@
    $source += "`n`n" + "pass" + "word = `"PYSEC-DETECTION-VALIDATION-ONLY`"`n"
    Set-Content -LiteralPath (Join-Path $resolvedFixture "vulnerable.py") `
        -Value $source -Encoding UTF8
    @'
import logging
import os


def unsafe_pseudonymization() -> None:
    token = os.getenv("AUTH_TOKEN")
    fingerprint = hash(token)
    logging.warning("credential fingerprint=%s", fingerprint)
'@ | Set-Content -LiteralPath (
        Join-Path $resolvedFixture "transform-review.py"
    ) -Encoding UTF8
    @'
import logging
import os


def unsafe_persistent_context() -> logging.LoggerAdapter:
    token = os.getenv("AUTH_TOKEN")
    return logging.LoggerAdapter(logging.getLogger(__name__), {"token": token})
'@ | Set-Content -LiteralPath (
        Join-Path $resolvedFixture "structured-context.py"
    ) -Encoding UTF8
    @'
import logging
import os

import requests
import sentry_sdk
from fastapi import HTTPException


def redact(value: str | None) -> str:
    return "[REDACTED]"


def allowlist_event(value: object) -> dict[str, str]:
    return {"event": "request-received"}


def before_send(event, hint):
    return allowlist_event(event)


sentry_sdk.init(send_default_pii=False, before_send=before_send)


def greet(name: str) -> str:
    token = os.getenv("AUTH_TOKEN")
    logging.info("credential=%s", redact(token))
    return f"Hello {name}"


def safe_private_log(user) -> None:
    logging.info("email=%s", redact(user.email))


def safe_request_handling(request) -> None:
    payload = allowlist_event(request.json())
    logging.info("event=%s", payload)
    sentry_sdk.set_context("request", payload)


def safe_credential_transport() -> None:
    token = os.getenv("API_KEY")
    requests.get(
        "https://service.invalid/check",
        headers={"Authorization": "Bearer " + str(token)},
        timeout=5,
    )


def safe_exception_response() -> None:
    try:
        raise RuntimeError("internal detail")
    except RuntimeError:
        raise HTTPException(status_code=500, detail="internal-error")


def safe_response_summary(embedding_response) -> None:
    logging.info("dimensions=%s", len(embedding_response.data))
'@ | Set-Content -LiteralPath (Join-Path $resolvedFixture "safe.py") -Encoding UTF8
    @'
OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY
OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST=.*
'@ | Set-Content -LiteralPath (
        Join-Path $resolvedFixture "capture.env"
    ) -Encoding UTF8
    @'
OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=true
'@ | Set-Content -LiteralPath (
        Join-Path $resolvedFixture "legacy.env"
    ) -Encoding UTF8

    $arguments = @(
        "-m", "py_security_suite",
        "scan", $resolvedFixture,
        "--config", $validationConfig,
        "--output", ([IO.Path]::GetFullPath($Output)),
        "--overwrite",
        "--profile", "standard",
        "--network-isolated"
    )
    & $python @arguments
    $scanExit = $LASTEXITCODE
    if ($scanExit -notin @(0, 1)) {
        throw "Detection validation scan was incomplete (exit $scanExit)."
    }

    $report = [IO.Path]::GetFullPath($Output)
    $findingsPath = Join-Path $report "findings.json"
    $manifestPath = Join-Path $report "scan-manifest.json"
    if (-not (Test-Path -LiteralPath $findingsPath) -or
        -not (Test-Path -LiteralPath $manifestPath)) {
        throw "Detection validation did not produce the normalized report."
    }
    $findings = (Get-Content -Raw -LiteralPath $findingsPath |
        ConvertFrom-Json).findings
    $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
    $problemTools = @(
        $manifest.tools | Where-Object {
            $_.status -in @("unavailable", "failed", "timed_out", "parse_error")
        }
    )
    if ($problemTools.Count -gt 0) {
        throw "Detection validation had unhealthy scanners: $($problemTools.tool -join ', ')"
    }

    $requiredTools = @("bandit", "semgrep", "detect-secrets")
    $observedTools = @(
        $findings.sources.tool | Where-Object { $_ } | Select-Object -Unique
    )
    $missingTools = @($requiredTools | Where-Object { $_ -notin $observedTools })
    if ($missingTools.Count -gt 0) {
        throw "Expected detection perspectives were absent: $($missingTools -join ', ')"
    }
    $requiredExposureRules = @(
        "python.sensitive-data-to-log",
        "python.sensitive-data-to-telemetry",
        "python.private-data-to-log",
        "python.private-data-to-telemetry",
        "python.request-data-to-log",
        "python.request-data-to-telemetry",
        "python.sensitive-data-in-url-query",
        "python.private-data-in-url-query",
        "python.exception-detail-to-http-response",
        "python.sentry-default-pii-enabled",
        "python.runtime-state-to-log",
        "config.opentelemetry-genai-content-capture-enabled",
        "config.opentelemetry-genai-content-capture-invalid-mode",
        "config.opentelemetry-broad-http-header-capture"
    )
    $observedRules = @($findings.sources.rule_id | Where-Object { $_ })
    $missingExposureRules = @(
        $requiredExposureRules | Where-Object {
            -not ($observedRules -match ([regex]::Escape($_) + '$'))
        }
    )
    if ($missingExposureRules.Count -gt 0) {
        throw "Expected data-exposure rules were absent: $($missingExposureRules -join ', ')"
    }
    foreach ($expectedPath in @("transform-review.py", "structured-context.py")) {
        $pathFindings = @(
            $findings | Where-Object {
                $_.locations[0].path -eq $expectedPath -and
                $_.sources.rule_id -match 'python\.sensitive-data-to-log$'
            }
        )
        if ($pathFindings.Count -eq 0) {
            throw "Expected hardened logging detection was absent for $expectedPath."
        }
    }
    foreach ($finding in $findings) {
        if (-not $finding.sources -or -not $finding.classifications -or
            -not $finding.locations -or -not $finding.citations -or
            -not $finding.impact -or -not $finding.remediation) {
            throw "A detection fixture finding was not normalized actionably."
        }
    }
    $negativeFindings = @(
        $findings | Where-Object { $_.locations[0].path -eq "safe.py" }
    )
    if ($negativeFindings.Count -gt 0) {
        throw "The safe negative-control fixture produced findings."
    }
    $toolYield = [ordered]@{}
    foreach ($tool in $observedTools) {
        $toolYield[$tool] = @(
            $findings | Where-Object { $tool -in $_.sources.tool }
        ).Count
    }

    $summary = [ordered]@{
        schema_version = "1.0"
        outcome = "pass"
        suite_outcome = $manifest.outcome
        fixture = "python-command-injection-secret-and-data-exposure"
        exposure_rules = $requiredExposureRules
        required_tools = $requiredTools
        observed_tools = $observedTools
        finding_count = @($findings).Count
        expected_perspectives = $requiredTools.Count
        detected_perspectives = $observedTools.Count
        perspective_recall_percent = [Math]::Round(
            100 * $observedTools.Count / $requiredTools.Count,
            2
        )
        actionable_metadata_percent = 100.0
        negative_control_findings = $negativeFindings.Count
        tool_yield = $toolYield
        report = $report
    }
    $summaryPath = Join-Path $workspace ".artifacts\detection-validation-summary.json"
    $summary | ConvertTo-Json -Depth 5 |
        Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Output "Detection validation passed: $summaryPath"
} finally {
    if (Test-Path -LiteralPath $validationConfig) {
        Remove-Item -LiteralPath $validationConfig -Force
    }
    if (Test-Path -LiteralPath $resolvedFixture) {
        Remove-Item -LiteralPath $resolvedFixture -Recurse -Force
    }
}
