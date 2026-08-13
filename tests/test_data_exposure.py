from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from py_security_suite.data_exposure import build_data_exposure_synthesis
from py_security_suite.models import (
    Confidence,
    Finding,
    Location,
    Severity,
    Source,
)
from py_security_suite.report_inspection import read_bundled_schema
from py_security_suite.reports import (
    _markdown_data_exposure_context,
    _render_data_exposure_summary,
    render_sarif,
    render_sonarqube_external_issues,
)


def _finding(
    *,
    path: str = "src/app.py",
    line: int = 6,
    classifications: list[str] | None = None,
    rule_id: str = "python.sensitive-data-to-telemetry",
) -> Finding:
    return Finding(
        finding_id="PYSEC-EXPOSURE",
        fingerprint="sha256:exposure",
        title="Sensitive data may reach telemetry",
        description="A credential-bearing source reaches a telemetry sink.",
        impact="The value can cross a trust boundary.",
        remediation="Minimize and redact the payload.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        area="data-exposure",
        classifications=classifications or ["CWE-201", "CWE-200"],
        locations=[Location(path=path, start_line=line, end_line=line)],
        sources=[
            Source(
                tool="semgrep",
                rule_id=rule_id,
                message="Sensitive flow",
                native_severity="ERROR",
            )
        ],
    )


class DataExposureSynthesisTests(unittest.TestCase):
    def test_inventories_sdk_sinks_without_claiming_a_leak(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src" / "app.py").write_text(
                "import sentry_sdk\n"
                "import requests\n\n"
                "def report(user):\n"
                "    sentry_sdk.set_user(user)\n"
                "    requests.post('https://example.invalid', json=user)\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_app.py").write_text(
                "import logging\nlogging.info('test')\n", encoding="utf-8"
            )
            (root / "pyproject.toml").write_text(
                '[project]\nname = "demo"\nversion = "1"\n'
                'dependencies = ["sentry-sdk>=2", "httpx>=0.28"]\n',
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["exposure_findings"], 0)
        self.assertEqual(result["summary"]["production_sink_surfaces"], 2)
        self.assertEqual(result["summary"]["test_sink_surfaces"], 1)
        self.assertIn(
            "Sentry SDK", {item["sdk"] for item in result["sdk_observations"]}
        )
        self.assertIn("HTTPX", {item["sdk"] for item in result["sdk_observations"]})

    def test_accepts_utf8_bom_without_losing_sink_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "app.py"
            source.write_bytes(b"\xef\xbb\xbfimport logging\nlogging.error('review')\n")

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["parse_errors"], 0)
        self.assertEqual(result["summary"]["production_sink_surfaces"], 1)

    def test_stdout_surface_requires_sensitive_context_hint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "print('ordinary status')\nprint('token', 'synthetic')\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["production_sink_surfaces"], 1)
        self.assertEqual(result["sink_surfaces"][0]["label"], "standard output")

    def test_recognizes_custom_loggers_request_payloads_and_process_streams(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n"
                "import sys\n\n"
                "audit = logging.getLogger(__name__)\n"
                "payload = request.json()\n"
                "audit.info('request payload=%s', payload)\n"
                "sys.stderr.write(api_token)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        labels = {item["label"] for item in result["sink_surfaces"]}
        self.assertIn("request data in structured log", labels)
        self.assertIn("process output stream", labels)

    def test_response_data_is_not_mislabeled_as_http_request_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def summarize(embedding_response):\n"
                "    logging.info('dimensions=%s', len(embedding_response.data))\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(result["summary"]["production_sink_surfaces"], 1)
        self.assertEqual(result["sink_surfaces"][0]["label"], "log.info")

    def test_request_named_data_retains_request_payload_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def audit(incoming_request):\n"
                "    logging.info('payload=%s', incoming_request.data)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(
            result["sink_surfaces"][0]["label"], "request data in structured log"
        )

    def test_propagates_data_classes_and_distinguishes_protection_kind(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\nimport os\n\n"
                "secret = os.getenv('PAYMENT_API_TOKEN')\n"
                "copied = secret\n"
                "logging.error('credential=%s', copied)\n"
                "safe = redact(copied)\n"
                "logging.info('credential=%s', safe)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        unsafe, protected = result["sink_surfaces"]
        self.assertEqual(unsafe["data_classes"], ["credentials", "financial"])
        self.assertEqual(unsafe["review_priority"], "high")
        self.assertEqual(unsafe["protection_status"], "not-observed")
        self.assertIn("no-protection-observed", unsafe["risk_factors"])
        self.assertEqual(protected["protection_status"], "redacted-or-masked")
        self.assertEqual(protected["review_priority"], "medium")

    def test_prioritizes_broad_runtime_state_without_claiming_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def diagnose(settings):\n"
                "    logging.warning('state=%r', vars(settings))\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        surface = result["sink_surfaces"][0]
        self.assertIn("broad-runtime-state", surface["risk_factors"])
        self.assertEqual(surface["review_priority"], "high")
        self.assertEqual(result["summary"]["exposure_findings"], 0)

    def test_local_alias_context_does_not_leak_between_functions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\nimport os\n\n"
                "def load():\n"
                "    value = os.getenv('AUTH_TOKEN')\n"
                "    return value\n\n"
                "def report(value):\n"
                "    logging.info('value=%s', value)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        surface = result["sink_surfaces"][0]
        self.assertEqual(surface["data_classes"], [])
        self.assertEqual(surface["review_priority"], "medium")

    def test_classifies_request_health_and_personal_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import logging\n\n"
                "def audit(request):\n"
                "    patient_email = request.json()\n"
                "    logging.info('diagnosis=%s', patient_email)\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        surface = result["sink_surfaces"][0]
        self.assertEqual(
            surface["data_classes"], ["health", "personal", "request-content"]
        )
        self.assertIn("full-request-content", surface["risk_factors"])
        self.assertEqual(surface["trust_boundary"], "operational-data-plane")

    def test_inventories_query_exception_and_risky_sdk_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\n"
                "import requests\n"
                "import sentry_sdk\n"
                "from fastapi import HTTPException\n\n"
                "sentry_sdk.init(send_default_pii=True, before_send=redact_event)\n"
                "requests.get('https://example.invalid', params={'token': api_token})\n"
                "try:\n"
                "    work()\n"
                "except Exception as error:\n"
                "    raise HTTPException(status_code=500, detail=str(error))\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        by_label = {item["label"]: item for item in result["sink_surfaces"]}
        self.assertTrue(
            by_label["automatic PII collection enabled"]["sanitizer_visible"]
        )
        self.assertIn("sensitive HTTP query parameters", by_label)
        self.assertIn("raw exception in HTTP response", by_label)

    def test_inventories_broad_opentelemetry_header_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\n"
                "os.environ[\n"
                "    'OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST'\n"
                "] = '.*'\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        self.assertEqual(len(result["sink_surfaces"]), 1)
        self.assertEqual(
            result["sink_surfaces"][0]["label"],
            "broad OpenTelemetry HTTP header capture",
        )

    def test_inventories_capture_configuration_outside_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".env").write_text(
                "OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT=SPAN_ONLY\n"
                "OTEL_INSTRUMENTATION_HTTP_CAPTURE_HEADERS_SERVER_REQUEST=.*\n",
                encoding="utf-8",
            )
            (root / "service.toml").write_text(
                'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT = "true"\n',
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        labels = [item["label"] for item in result["sink_surfaces"]]
        self.assertIn("GenAI message content capture enabled", labels)
        self.assertIn("invalid GenAI content-capture mode", labels)
        self.assertIn("broad OpenTelemetry HTTP header capture", labels)
        self.assertEqual(result["summary"]["configuration_review_surfaces"], 3)

    def test_inventories_genai_capture_setdefault_and_putenv(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\n"
                "os.environ.setdefault(\n"
                "    'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT',\n"
                "    'EVENT_ONLY',\n"
                ")\n"
                "os.putenv(\n"
                "    'OTEL_INSTRUMENTATION_GENAI_CAPTURE_MESSAGE_CONTENT',\n"
                "    'true',\n"
                ")\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        labels = {item["label"] for item in result["sink_surfaces"]}
        self.assertIn("GenAI message content capture enabled", labels)
        self.assertIn("invalid GenAI content-capture mode", labels)

    def test_inventories_nested_manifests_requirements_and_cloud_sdks(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "packages" / "worker"
            package.mkdir(parents=True)
            (package / "pyproject.toml").write_text(
                "[project]\nname = 'worker'\nversion = '1'\n"
                "dependencies = ['azure-monitor-opentelemetry>=1']\n"
                "[project.optional-dependencies]\n"
                "observability = ['langfuse>=3']\n",
                encoding="utf-8",
            )
            (root / "requirements-observability.txt").write_text(
                "google-cloud-logging==3.12.1\n",
                encoding="utf-8",
            )
            (package / "app.py").write_text(
                "from google.cloud import logging as cloud_logging\n"
                "import phoenix as px\n"
                "cloud_logging.Client()\n"
                "px.Client()\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        sdks = {item["sdk"] for item in result["sdk_observations"]}
        self.assertIn("Azure Monitor OpenTelemetry", sdks)
        self.assertIn("Langfuse", sdks)
        self.assertIn("Google Cloud Logging", sdks)
        self.assertIn("Arize Phoenix", sdks)

    def test_enriches_supported_finding_with_sdk_and_security_practice(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import os\n"
                "import sentry_sdk\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "sentry_sdk.set_context('request', {'token': token})\n",
                encoding="utf-8",
            )
            finding = _finding(line=5)

            result = build_data_exposure_synthesis(
                root,
                [finding],
                {"graphify.json": {}, "reachability.json": {}},
            )

        assessment = result["finding_assessments"][0]
        self.assertEqual(assessment["sink_family"], "error-monitoring")
        self.assertEqual(assessment["sdk"], "Sentry SDK")
        self.assertEqual(assessment["confidence"], "high")
        self.assertEqual(
            finding.evidence["data_exposure"]["concern"],
            "sensitive-information-in-sent-data",
        )
        self.assertIn(
            "CWE-201", {citation.identifier for citation in finding.citations}
        )

    def test_logging_finding_gets_cwe_and_owasp_citations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import logging\nimport os\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "logging.error('token=%s', token)\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-532", "CWE-200"],
                rule_id="python.sensitive-data-to-log",
            )

            build_data_exposure_synthesis(root, [finding], {})

        identifiers = {citation.identifier for citation in finding.citations}
        self.assertIn("CWE-532", identifiers)
        self.assertIn("OWASP-LOGGING", identifiers)
        self.assertEqual(finding.evidence["data_exposure"]["sink_family"], "logging")

    def test_private_data_keeps_distinct_privacy_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = _finding(
                classifications=["CWE-201", "CWE-359"],
                rule_id="python.private-data-to-telemetry",
            )

            result = build_data_exposure_synthesis(root, [finding], {})

        self.assertEqual(
            finding.evidence["data_exposure"]["concern"], "private-data-exposure"
        )
        self.assertEqual(result["finding_assessments"][0]["data_classes"], ["personal"])
        self.assertIn(
            "CWE-359", {citation.identifier for citation in finding.citations}
        )

    def test_url_query_finding_gets_specific_action_and_citation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import os\nimport requests\n\n"
                "token = os.getenv('API_KEY')\n"
                "requests.get('https://example.invalid', params={'token': token})\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-598", "CWE-200"],
                rule_id="python.sensitive-data-in-url-query",
            )

            result = build_data_exposure_synthesis(root, [finding], {})

        assessment = result["finding_assessments"][0]
        self.assertEqual(assessment["sink_family"], "url-query")
        self.assertEqual(assessment["concern"], "sensitive-data-in-url-query")
        self.assertIn("browser history", assessment["recommended_action"])
        self.assertIn(
            "CWE-598", {citation.identifier for citation in finding.citations}
        )

    def test_inventories_dynamic_sensitive_url_without_static_name_false_positive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text(
                "import os\nimport requests\n\n"
                "token = os.getenv('API_TOKEN')\n"
                "requests.get(f'https://example.invalid/check?token={token}')\n"
                "requests.get('https://example.invalid/tokenize')\n",
                encoding="utf-8",
            )

            result = build_data_exposure_synthesis(root, [], {})

        dynamic, static = result["sink_surfaces"]
        self.assertEqual(dynamic["sink_family"], "url")
        self.assertEqual(dynamic["review_priority"], "high")
        self.assertIn("url-propagation", dynamic["risk_factors"])
        self.assertEqual(static["sink_family"], "network-egress")
        self.assertEqual(static["data_classes"], [])

    def test_ignores_unrelated_quality_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finding = _finding(classifications=["CWE-78"], rule_id="B602")
            finding.area = "logging"

            result = build_data_exposure_synthesis(root, [finding], {})

        self.assertEqual(result["finding_assessments"], [])
        self.assertNotIn("data_exposure", finding.evidence)

    def test_artifact_validates_against_bundled_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = build_data_exposure_synthesis(Path(temporary), [], {})
        schema = json.loads(read_bundled_schema("data-exposure-1.2"))
        Draft202012Validator(schema).validate(result)

    def test_portable_reports_render_exposure_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text(
                "import logging\nimport os\n\n"
                "token = os.getenv('AUTH_TOKEN')\n"
                "logging.error('token=%s', token)\n",
                encoding="utf-8",
            )
            finding = _finding(
                line=5,
                classifications=["CWE-532"],
                rule_id="python.sensitive-data-to-log",
            )
            result = build_data_exposure_synthesis(root, [finding], {})

        summary = "\n".join(_render_data_exposure_summary(result))
        context = "\n".join(_markdown_data_exposure_context(finding))
        sonar = render_sonarqube_external_issues([finding])
        sarif = render_sarif([finding])
        self.assertIn("Sensitive-data exposure", summary)
        self.assertIn("sensitive-information-in-logs", context)
        self.assertIn(
            "Sensitive-data path",
            sonar["issues"][0]["primaryLocation"]["message"],
        )
        self.assertIn("data_exposure", sarif["runs"][0]["results"][0]["properties"])


if __name__ == "__main__":
    unittest.main()
