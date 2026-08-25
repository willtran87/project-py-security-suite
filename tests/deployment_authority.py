from __future__ import annotations

import base64
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from py_security_suite.strict_json import canonical_bytes


def pinned_command_sandbox_environment(
    root: Path, *, prefix: str, allowed_endpoints: list[str]
) -> tuple[dict[str, str], dict[str, object], dict[str, str]]:
    """Return a pinned pass-through launcher contract for protocol tests."""

    launcher = root / f"{prefix.casefold()}-sandbox.py"
    cryptography_site_packages = Path(serialization.__file__).resolve().parents[4]
    if cryptography_site_packages.name not in {"site-packages", "dist-packages"}:
        raise RuntimeError("cryptography package root could not be determined")
    attestor_private = Ed25519PrivateKey.generate()
    attestor_private_bytes = attestor_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    attestor_public_bytes = attestor_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    attestor_key_sha256 = hashlib.sha256(attestor_public_bytes).hexdigest()
    embedded_private = base64.b64encode(attestor_private_bytes).decode("ascii")
    remote_private = Ed25519PrivateKey.generate()
    remote_private_bytes = remote_private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    remote_public_bytes = remote_private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    remote_key_sha256 = hashlib.sha256(remote_public_bytes).hexdigest()
    embedded_remote_private = base64.b64encode(remote_private_bytes).decode("ascii")
    launcher.write_text(
        "import base64,hashlib,json,os,platform,subprocess,sys\n"
        "from datetime import UTC,datetime,timedelta\n"
        f"sys.path.insert(0,{str(cryptography_site_packages)!r})\n"
        "from cryptography.hazmat.primitives import serialization\n"
        f"PRIVATE={embedded_private!r}\n"
        f"REMOTE_PRIVATE={embedded_remote_private!r}\n"
        "canonical=lambda value: json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()\n"
        "child=subprocess.Popen(sys.argv[1:]);returncode=child.wait()\n"
        "subject=json.loads(base64.b64decode(os.environ['PYSEC_PINNED_ATTESTATION_SUBJECT_BASE64']))\n"
        "controls={'network_allowlist_enforced':True,'filesystem_read_only':True,'credentials_isolated':True,'child_process_confined':True}\n"
        "platform_id={'linux':'linux','win32':'win32','darwin':'darwin'}[sys.platform]\n"
        "source={'linux':'linux-procfs-seccomp','win32':'windows-job-object-query','darwin':'macos-sandbox-audit'}[platform_id]\n"
        "measurement={'schema_version':'1.0','platform':platform_id,'child_process_id':child.pid,'child_exit_code':returncode,'kernel_identity_sha256':hashlib.sha256(platform.platform().encode()).hexdigest(),'sandbox_identity_sha256':subject['sandbox_identity_sha256'],'controls':controls}\n"
        "challenge=os.environ['PYSEC_PINNED_ATTESTATION_CHALLENGE_SHA256'];host=hashlib.sha256(platform.node().encode()).hexdigest();pcrs=hashlib.sha256(b'pcr0:pcr7').hexdigest();implementation=hashlib.sha256(b'test-tpm-verifier').hexdigest();quote=canonical({'schema_version':'1.0','format':'tpm2-quote','challenge_sha256':challenge,'host_identity_sha256':host,'pcrs_sha256':pcrs,'secure_boot':True,'measured_boot':True,'claims':{'quote_type':'TPM_ST_ATTEST_QUOTE','hash_algorithm':'sha256','pcr_selection':[0,7],'event_log_sha256':hashlib.sha256(b'test-event-log').hexdigest(),'ak_certificate_chain_sha256':hashlib.sha256(b'test-ak-chain').hexdigest(),'signature_verified':True,'certificate_chain_verified':True,'revocation_checked':True,'event_log_replayed':True,'trust_root_sha256':hashlib.sha256(b'test-root').hexdigest(),'verifier_implementation_sha256':implementation}});remote_subject={'schema_version':'1.0','format':'tpm2-quote','purpose':'sandbox-effective-policy','challenge_sha256':challenge,'host_identity_sha256':host,'organization':'independent-host-attestor','control_plane_sha256':hashlib.sha256(b'test-control-plane').hexdigest(),'implementation_sha256':implementation,'secure_boot':True,'measured_boot':True,'pcrs_sha256':pcrs,'quote_base64':base64.b64encode(quote).decode(),'quote_sha256':hashlib.sha256(quote).hexdigest()}\n"
        "remote_private=serialization.load_pem_private_key(base64.b64decode(REMOTE_PRIVATE),password=None);remote_public=remote_private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo);now=datetime.now(UTC)\n"
        "remote_statement={'schema_version':'1.0','purpose':'sandbox-remote-attestation','subject_sha256':hashlib.sha256(canonical(remote_subject)).hexdigest(),'operation_id':'remote-'+subject['execution_nonce'],'previous_operation_sha256':'','challenge_sha256':os.environ['PYSEC_PINNED_ATTESTATION_CHALLENGE_SHA256'],'trusted_time_sha256':os.environ['PYSEC_SCAN_TIME_CONTEXT_SHA256'],'issued_at':now.isoformat(),'expires_at':(now+timedelta(minutes=5)).isoformat(),'signer_key_sha256':hashlib.sha256(remote_public).hexdigest()}\n"
        "remote_receipt={'schema_version':'1.0','statement':remote_statement,'signature_base64':base64.b64encode(remote_private.sign(canonical(remote_statement))).decode(),'public_key_pem_base64':base64.b64encode(remote_public).decode()}\n"
        "policy={**controls,'measurement_source':source,'measurement_artifact':measurement,'measurement_artifact_sha256':hashlib.sha256(canonical(measurement)).hexdigest(),'remote_attestation':{'subject':remote_subject,'operation_receipt':remote_receipt}}\n"
        "subject.update({'exit_code':returncode,'attestor_process_id':os.getpid(),'policy_observations':policy})\n"
        "private=serialization.load_pem_private_key(base64.b64decode(PRIVATE),password=None)\n"
        "public=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)\n"
        "now=datetime.now(UTC);statement={'schema_version':'1.0','purpose':'pinned-command-effective-policy','subject_sha256':hashlib.sha256(canonical(subject)).hexdigest(),'operation_id':'pinned-'+subject['execution_nonce'],'previous_operation_sha256':'','challenge_sha256':os.environ['PYSEC_PINNED_ATTESTATION_CHALLENGE_SHA256'],'trusted_time_sha256':os.environ['PYSEC_SCAN_TIME_CONTEXT_SHA256'],'issued_at':now.isoformat(),'expires_at':(now+timedelta(minutes=5)).isoformat(),'signer_key_sha256':hashlib.sha256(public).hexdigest()}\n"
        "receipt={'schema_version':'1.0','statement':statement,'signature_base64':base64.b64encode(private.sign(canonical(statement))).decode(),'public_key_pem_base64':base64.b64encode(public).decode()}\n"
        "open(os.environ['PYSEC_PINNED_ATTESTATION_PATH'],'wb').write(canonical({'subject':subject,'operation_receipt':receipt}))\n"
        "raise SystemExit(returncode)\n",
        encoding="utf-8",
    )
    executable_sha256 = hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest()
    mtls_identity = "d" * 64
    launcher_argv = ["-I", str(launcher)]
    sandbox_identity = hashlib.sha256(
        canonical_bytes(
            {
                "launcher_sha256": executable_sha256,
                "launcher_argv": launcher_argv,
                "allowed_endpoints": allowed_endpoints,
                "mtls_identity_sha256": mtls_identity,
            }
        )
    ).hexdigest()
    environment = {
        "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
        f"{prefix}_ALLOWED_ENDPOINTS_JSON": json.dumps(allowed_endpoints),
        f"{prefix}_MTLS_IDENTITY_SHA256": mtls_identity,
        f"{prefix}_SANDBOX_IDENTITY_SHA256": sandbox_identity,
        f"{prefix}_SANDBOX_COMMAND_JSON": json.dumps([sys.executable, *launcher_argv]),
        f"{prefix}_SANDBOX_EXECUTABLE_SHA256": executable_sha256,
        f"{prefix}_EXECUTION_ATTESTATION_KEY_SHA256": attestor_key_sha256,
        f"{prefix}_REMOTE_ATTESTATION_KEY_SHA256": remote_key_sha256,
    }
    context: dict[str, object] = {
        "schema_version": "1.0",
        "executable_sha256": executable_sha256,
        "allowed_endpoints": allowed_endpoints,
        "mtls_identity_sha256": mtls_identity,
        "sandbox_identity_sha256": sandbox_identity,
        "sandbox_executable_sha256": executable_sha256,
        "sandbox_launcher_argv": launcher_argv,
        "effective_policy_attestor_key_sha256": attestor_key_sha256,
        "remote_attestation_key_sha256": remote_key_sha256,
    }
    asset = {
        "path": str(launcher),
        "sha256": hashlib.sha256(launcher.read_bytes()).hexdigest(),
    }
    return environment, context, asset


def operation_receipt(
    subject: object,
    *,
    purpose: str,
    challenge: str = "c" * 64,
    operation_id: str = "operation-1",
    previous_operation_sha256: str = "",
    private_key: Ed25519PrivateKey | None = None,
) -> tuple[dict[str, object], str]:
    """Create a short-lived external-operation receipt for integration tests."""

    private = private_key or Ed25519PrivateKey.generate()
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_sha256 = hashlib.sha256(public_bytes).hexdigest()
    now = datetime.now(UTC)
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "operation_id": operation_id,
        "previous_operation_sha256": previous_operation_sha256,
        "challenge_sha256": challenge,
        "trusted_time_sha256": "e" * 64,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "signer_key_sha256": key_sha256,
    }
    return (
        {
            "schema_version": "1.0",
            "statement": statement,
            "signature_base64": base64.b64encode(
                private.sign(canonical_bytes(statement))
            ).decode("ascii"),
            "public_key_pem_base64": base64.b64encode(public_bytes).decode("ascii"),
        },
        key_sha256,
    )


def effective_policy_attestation(
    failure_domain: dict[str, str],
    *,
    challenge: str = "c" * 64,
    attested_request: dict[str, object] | None = None,
) -> dict[str, object]:
    """Create a portable kernel and remote-attestation fixture."""

    attestor = Ed25519PrivateKey.generate()
    attestor_public = attestor.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    remote = Ed25519PrivateKey.generate()
    sandbox_identity = "9" * 64
    controls = {
        "network_allowlist_enforced": True,
        "filesystem_read_only": True,
        "credentials_isolated": True,
        "child_process_confined": True,
    }
    platform_id = "win32"
    measurement = {
        "schema_version": "1.0",
        "platform": platform_id,
        "child_process_id": 1234,
        "child_exit_code": 0,
        "kernel_identity_sha256": "8" * 64,
        "sandbox_identity_sha256": sandbox_identity,
        "controls": controls,
    }
    quote = canonical_bytes(
        {
            "schema_version": "1.0",
            "format": "tpm2-quote",
            "challenge_sha256": challenge,
            "host_identity_sha256": failure_domain["host_identity_sha256"],
            "pcrs_sha256": "7" * 64,
            "secure_boot": True,
            "measured_boot": True,
            "claims": {
                "quote_type": "TPM_ST_ATTEST_QUOTE",
                "hash_algorithm": "sha256",
                "pcr_selection": [0, 7],
                "event_log_sha256": "5" * 64,
                "ak_certificate_chain_sha256": "6" * 64,
                "signature_verified": True,
                "certificate_chain_verified": True,
                "revocation_checked": True,
                "event_log_replayed": True,
                "trust_root_sha256": "a" * 64,
                "verifier_implementation_sha256": failure_domain[
                    "implementation_sha256"
                ],
            },
        }
    )
    remote_subject = {
        "schema_version": "1.0",
        "format": "tpm2-quote",
        "purpose": "sandbox-effective-policy",
        "challenge_sha256": challenge,
        **failure_domain,
        "secure_boot": True,
        "measured_boot": True,
        "pcrs_sha256": "7" * 64,
        "quote_base64": base64.b64encode(quote).decode(),
        "quote_sha256": hashlib.sha256(quote).hexdigest(),
    }
    remote_receipt, remote_key = operation_receipt(
        remote_subject,
        purpose="sandbox-remote-attestation",
        challenge=challenge,
        operation_id="remote-attestation-fixture",
        private_key=remote,
    )
    policy = {
        **controls,
        "measurement_source": "windows-job-object-query",
        "measurement_artifact": measurement,
        "measurement_artifact_sha256": hashlib.sha256(
            canonical_bytes(measurement)
        ).hexdigest(),
        "remote_attestation": {
            "subject": remote_subject,
            "operation_receipt": remote_receipt,
        },
    }
    subject = {
        "schema_version": "1.0",
        "request_sha256": (
            hashlib.sha256(canonical_bytes(attested_request)).hexdigest()
            if attested_request is not None
            else "1" * 64
        ),
        "command_context_sha256": (
            hashlib.sha256(
                canonical_bytes(attested_request.get("command_context"))
            ).hexdigest()
            if attested_request is not None
            else "2" * 64
        ),
        "execution_nonce": "fixture-execution-nonce",
        "launcher_sha256": "3" * 64,
        "executable_sha256": "4" * 64,
        "attestor_key_sha256": hashlib.sha256(attestor_public).hexdigest(),
        "sandbox_identity_sha256": sandbox_identity,
        "remote_attestation_key_sha256": remote_key,
        "exit_code": 0,
        "attestor_process_id": 1233,
        "policy_observations": policy,
    }
    receipt, _ = operation_receipt(
        subject,
        purpose="pinned-command-effective-policy",
        challenge=challenge,
        operation_id="effective-policy-fixture",
        private_key=attestor,
    )
    return {"subject": subject, "operation_receipt": receipt}


def authority_environment(
    root: Path,
    subject: object,
    *,
    purpose: str,
    prefix: str,
    challenge: str = "c" * 64,
) -> dict[str, str]:
    private = Ed25519PrivateKey.generate()
    public = root / f"{purpose}.authority.pem"
    public.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    key_sha256 = hashlib.sha256(public.read_bytes()).hexdigest()
    now = datetime.now(UTC)
    statement = {
        "schema_version": "1.0",
        "purpose": purpose,
        "subject_sha256": hashlib.sha256(canonical_bytes(subject)).hexdigest(),
        "challenge_sha256": challenge,
        "generation": 1,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=1)).isoformat(),
        "signer_key_sha256": key_sha256,
    }
    receipt = root / f"{purpose}.authority-receipt.json"
    receipt.write_bytes(
        canonical_bytes(
            {
                "schema_version": "1.0",
                "statement": statement,
                "signature_base64": base64.b64encode(
                    private.sign(canonical_bytes(statement))
                ).decode("ascii"),
            }
        )
    )
    return {
        "PYSEC_SCAN_TIME_CHALLENGE_SHA256": challenge,
        "PYSEC_SCAN_TIME_CONTEXT_SHA256": "e" * 64,
        f"{prefix}_RECEIPT_PATH": str(receipt),
        f"{prefix}_RECEIPT_SHA256": hashlib.sha256(receipt.read_bytes()).hexdigest(),
        f"{prefix}_KEY_PATH": str(public),
        f"{prefix}_KEY_SHA256": key_sha256,
        f"{prefix}_MIN_GENERATION": "1",
        f"{prefix}_STATE_PATH": str(root / f"{purpose}.authority-state.sqlite3"),
    }
