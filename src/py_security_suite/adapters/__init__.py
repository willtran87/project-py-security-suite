from __future__ import annotations

from .bandit import BanditAdapter
from .codeql import CodeQlAdapter
from .cyclonedx import CycloneDxAdapter
from .detect_secrets import DetectSecretsAdapter
from .gitleaks import GitleaksAdapter
from .grype import GrypeAdapter
from .guarddog import GuardDogAdapter
from .osv import OsvScannerAdapter
from .pysa import PysaAdapter
from .pypi_attestations import PyPiAttestationsAdapter
from .ruff import RuffAdapter
from .scancode import ScanCodeAdapter
from .semgrep import SemgrepAdapter
from .syft import SyftAdapter
from .trufflehog import TruffleHogAdapter
from .trivy import TrivyAdapter
from .twine import TwineAdapter
from .wheel_contents import CheckWheelContentsAdapter
from .zizmor import ZizmorAdapter

ADAPTER_TYPES = {
    "bandit": BanditAdapter,
    "semgrep": SemgrepAdapter,
    "detect-secrets": DetectSecretsAdapter,
    "osv-scanner": OsvScannerAdapter,
    "cyclonedx-py": CycloneDxAdapter,
    "ruff": RuffAdapter,
    "zizmor": ZizmorAdapter,
    "pysa": PysaAdapter,
    "trivy": TrivyAdapter,
    "guarddog": GuardDogAdapter,
    "scancode": ScanCodeAdapter,
    "gitleaks": GitleaksAdapter,
    "trufflehog": TruffleHogAdapter,
    "codeql": CodeQlAdapter,
    "syft": SyftAdapter,
    "grype": GrypeAdapter,
    "check-wheel-contents": CheckWheelContentsAdapter,
    "twine": TwineAdapter,
    "pypi-attestations": PyPiAttestationsAdapter,
}

__all__ = [
    "ADAPTER_TYPES",
    "BanditAdapter",
    "CodeQlAdapter",
    "CycloneDxAdapter",
    "DetectSecretsAdapter",
    "GitleaksAdapter",
    "GrypeAdapter",
    "GuardDogAdapter",
    "OsvScannerAdapter",
    "PysaAdapter",
    "PyPiAttestationsAdapter",
    "RuffAdapter",
    "ScanCodeAdapter",
    "SemgrepAdapter",
    "SyftAdapter",
    "TruffleHogAdapter",
    "TrivyAdapter",
    "TwineAdapter",
    "CheckWheelContentsAdapter",
    "ZizmorAdapter",
]
