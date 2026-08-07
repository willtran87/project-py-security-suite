from __future__ import annotations

from .actionlint import ActionlintAdapter
from .assurance_evidence import (
    AtherisAdapter,
    CheckManifestAdapter,
    ClamAvAdapter,
    CrossHairAdapter,
    GitHubAttestationAdapter,
    InTotoAdapter,
    MutmutAdapter,
    OciImageAdapter,
    PyTmAdapter,
    ReproducibleBuildAdapter,
    YaraAdapter,
    ZapAdapter,
)
from .bandit import BanditAdapter
from .codeql import CodeQlAdapter
from .checkov import CheckovAdapter
from .cosign import CosignAdapter
from .cyclonedx import CycloneDxAdapter
from .detect_secrets import DetectSecretsAdapter
from .deptry import DeptryAdapter
from .diff_cover import DiffCoverAdapter
from .devskim import DevSkimAdapter
from .flawfinder import FlawfinderAdapter
from .gitleaks import GitleaksAdapter
from .grype import GrypeAdapter
from .guarddog import GuardDogAdapter
from .hadolint import HadolintAdapter
from .mypy import MypyAdapter
from .osv import OsvScannerAdapter
from .pylint import PylintAdapter
from .pysa import PysaAdapter
from .psscriptanalyzer import PSScriptAnalyzerAdapter
from .pyright import PyrightAdapter
from .pypi_attestations import PyPiAttestationsAdapter
from .portfolio import (
    ConftestAdapter,
    GitSizerAdapter,
    KicsAdapter,
    KubeLinterAdapter,
    PipdeptreeAdapter,
    ValidatePyprojectAdapter,
    ValeAdapter,
)
from .ruff import RuffAdapter
from .ruff_quality import RuffQualityAdapter
from .ruff_format import RuffFormatAdapter
from .radon import RadonAdapter
from .reachability import ReachabilityAdapter
from .reuse import ReuseAdapter
from .scancode import ScanCodeAdapter
from .semgrep import SemgrepAdapter
from .scorecard import ScorecardAdapter
from .shellcheck import ShellCheckAdapter
from .syft import SyftAdapter
from .tach import TachAdapter
from .test_evidence import (
    CoverageAdapter,
    HypothesisAdapter,
    JUnitAdapter,
    SchemathesisAdapter,
)
from .trivy import TrivyAdapter
from .trufflehog import TruffleHogAdapter
from .twine import TwineAdapter
from .vulture import VultureAdapter
from .wheel_contents import CheckWheelContentsAdapter
from .zizmor import ZizmorAdapter

ADAPTER_TYPES = {
    "bandit": BanditAdapter,
    "semgrep": SemgrepAdapter,
    "detect-secrets": DetectSecretsAdapter,
    "osv-scanner": OsvScannerAdapter,
    "cyclonedx-py": CycloneDxAdapter,
    "ruff": RuffAdapter,
    "ruff-quality": RuffQualityAdapter,
    "ruff-format": RuffFormatAdapter,
    "pylint": PylintAdapter,
    "mypy": MypyAdapter,
    "vulture": VultureAdapter,
    "radon": RadonAdapter,
    "reachability": ReachabilityAdapter,
    "zizmor": ZizmorAdapter,
    "actionlint": ActionlintAdapter,
    "hadolint": HadolintAdapter,
    "pysa": PysaAdapter,
    "trivy": TrivyAdapter,
    "guarddog": GuardDogAdapter,
    "scancode": ScanCodeAdapter,
    "gitleaks": GitleaksAdapter,
    "trufflehog": TruffleHogAdapter,
    "devskim": DevSkimAdapter,
    "flawfinder": FlawfinderAdapter,
    "codeql": CodeQlAdapter,
    "syft": SyftAdapter,
    "tach": TachAdapter,
    "coverage": CoverageAdapter,
    "junit": JUnitAdapter,
    "hypothesis": HypothesisAdapter,
    "schemathesis": SchemathesisAdapter,
    "reuse": ReuseAdapter,
    "grype": GrypeAdapter,
    "check-wheel-contents": CheckWheelContentsAdapter,
    "twine": TwineAdapter,
    "pypi-attestations": PyPiAttestationsAdapter,
    "psscriptanalyzer": PSScriptAnalyzerAdapter,
    "shellcheck": ShellCheckAdapter,
    "deptry": DeptryAdapter,
    "diff-cover": DiffCoverAdapter,
    "checkov": CheckovAdapter,
    "cosign": CosignAdapter,
    "pyright": PyrightAdapter,
    "scorecard": ScorecardAdapter,
    "conftest": ConftestAdapter,
    "kics": KicsAdapter,
    "pipdeptree": PipdeptreeAdapter,
    "git-sizer": GitSizerAdapter,
    "validate-pyproject": ValidatePyprojectAdapter,
    "vale": ValeAdapter,
    "kube-linter": KubeLinterAdapter,
    "crosshair": CrossHairAdapter,
    "atheris": AtherisAdapter,
    "mutmut": MutmutAdapter,
    "oci-image": OciImageAdapter,
    "check-manifest": CheckManifestAdapter,
    "clamav": ClamAvAdapter,
    "github-attestation": GitHubAttestationAdapter,
    "zap": ZapAdapter,
    "pytm": PyTmAdapter,
    "in-toto": InTotoAdapter,
    "reproducible-build": ReproducibleBuildAdapter,
    "yara": YaraAdapter,
}

__all__ = [
    "ADAPTER_TYPES",
    "ActionlintAdapter",
    "AtherisAdapter",
    "BanditAdapter",
    "CheckManifestAdapter",
    "CheckWheelContentsAdapter",
    "CheckovAdapter",
    "ClamAvAdapter",
    "CodeQlAdapter",
    "ConftestAdapter",
    "CosignAdapter",
    "CoverageAdapter",
    "CrossHairAdapter",
    "CycloneDxAdapter",
    "DeptryAdapter",
    "DetectSecretsAdapter",
    "DevSkimAdapter",
    "DiffCoverAdapter",
    "FlawfinderAdapter",
    "GitHubAttestationAdapter",
    "GitSizerAdapter",
    "GitleaksAdapter",
    "GrypeAdapter",
    "GuardDogAdapter",
    "HadolintAdapter",
    "HypothesisAdapter",
    "InTotoAdapter",
    "JUnitAdapter",
    "KicsAdapter",
    "KubeLinterAdapter",
    "MutmutAdapter",
    "MypyAdapter",
    "OciImageAdapter",
    "OsvScannerAdapter",
    "PSScriptAnalyzerAdapter",
    "PipdeptreeAdapter",
    "PyPiAttestationsAdapter",
    "PyTmAdapter",
    "PylintAdapter",
    "PyrightAdapter",
    "PysaAdapter",
    "RadonAdapter",
    "ReachabilityAdapter",
    "ReproducibleBuildAdapter",
    "ReuseAdapter",
    "RuffAdapter",
    "RuffFormatAdapter",
    "RuffQualityAdapter",
    "ScanCodeAdapter",
    "SchemathesisAdapter",
    "ScorecardAdapter",
    "SemgrepAdapter",
    "ShellCheckAdapter",
    "SyftAdapter",
    "TachAdapter",
    "TrivyAdapter",
    "TruffleHogAdapter",
    "TwineAdapter",
    "ValeAdapter",
    "ValidatePyprojectAdapter",
    "VultureAdapter",
    "YaraAdapter",
    "ZapAdapter",
    "ZizmorAdapter",
]
