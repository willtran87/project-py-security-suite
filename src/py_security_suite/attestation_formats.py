from __future__ import annotations

import base64
import hashlib
import os
from typing import Any, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .strict_json import canonical_bytes, loads as strict_loads


_RAW_REPLAY_FIELDS = {
    "raw_evidence_base64",
    "raw_evidence_sha256",
    "replay_statement",
    "replay_signature_base64",
    "replay_public_key_pem_base64",
    "replay_failure_domain",
}

_VERIFICATION_METHODS = {
    "tpm2-quote": "tpm2-checkquote-and-eventlog-v1",
    "nitro-attestation": "nitro-cose-sign1-chain-v1",
    "sev-snp": "sev-snp-report-signature-v1",
}


class NativeReplayVerifier(Protocol):
    def __call__(
        self,
        *,
        claims: dict[str, Any],
        format_name: str,
        expected_statement: dict[str, Any],
        implementation_sha256: str,
        replay_domain: object,
        replay_key_sha256: str,
        normalized_failure_domain: dict[str, object],
        verification_method: str,
        required: bool,
    ) -> None: ...


def verify_format_evidence(
    payload: bytes,
    *,
    format_name: str,
    challenge_sha256: str,
    host_identity_sha256: str,
    pcrs_sha256: str,
    implementation_sha256: str,
    normalized_authority_key_sha256: str = "",
    normalized_failure_domain: dict[str, object] | None = None,
    native_replay_verifier: NativeReplayVerifier | None = None,
) -> dict[str, Any]:
    """Parse format-specific, verifier-normalized hardware evidence.

    Native TPM/Nitro/SNP decoders are deliberately kept outside the suite's
    trust boundary.  Their retained output is a strict canonical statement
    signed by the pinned remote-attestation authority.  This verifier rejects
    opaque quote bytes and checks the security-relevant fields for each format.
    """

    try:
        value = strict_loads(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("remote attestation evidence is not canonical JSON") from exc
    common = {
        "schema_version",
        "format",
        "challenge_sha256",
        "host_identity_sha256",
        "pcrs_sha256",
        "secure_boot",
        "measured_boot",
        "claims",
    }
    if (
        not isinstance(value, dict)
        or set(value) != common
        or value.get("schema_version") != "1.0"
        or value.get("format") != format_name
        or value.get("challenge_sha256") != challenge_sha256
        or value.get("host_identity_sha256") != host_identity_sha256
        or value.get("pcrs_sha256") != pcrs_sha256
        or value.get("secure_boot") is not True
        or value.get("measured_boot") is not True
        or not isinstance(value.get("claims"), dict)
    ):
        raise ValueError("remote attestation evidence binding is invalid")
    claims = value["claims"]
    if claims.get("verifier_implementation_sha256") != implementation_sha256:
        raise ValueError("remote attestation verifier implementation is detached")
    if format_name == "tpm2-quote":
        _verify_tpm2(claims)
    elif format_name == "nitro-attestation":
        _verify_nitro(claims)
    elif format_name == "sev-snp":
        _verify_sev_snp(claims)
    else:
        raise ValueError("remote attestation format is unsupported")
    _verify_raw_replay(
        claims,
        format_name=format_name,
        challenge_sha256=challenge_sha256,
        host_identity_sha256=host_identity_sha256,
        pcrs_sha256=pcrs_sha256,
        implementation_sha256=implementation_sha256,
        normalized_authority_key_sha256=normalized_authority_key_sha256,
        normalized_failure_domain=normalized_failure_domain,
        native_replay_verifier=native_replay_verifier,
    )
    return value


def _verify_tpm2(claims: dict[str, Any]) -> None:
    if (
        set(claims) - _RAW_REPLAY_FIELDS
        != {
            "quote_type",
            "hash_algorithm",
            "pcr_selection",
            "event_log_sha256",
            "ak_certificate_chain_sha256",
            "signature_verified",
            "certificate_chain_verified",
            "revocation_checked",
            "event_log_replayed",
            "trust_root_sha256",
            "verifier_implementation_sha256",
        }
        or claims.get("quote_type") != "TPM_ST_ATTEST_QUOTE"
        or claims.get("hash_algorithm") != "sha256"
        or not isinstance(claims.get("pcr_selection"), list)
        or not {0, 7}.issubset(set(claims["pcr_selection"]))
        or not _digest(str(claims.get("event_log_sha256") or ""))
        or not _digest(str(claims.get("ak_certificate_chain_sha256") or ""))
        or claims.get("signature_verified") is not True
        or claims.get("certificate_chain_verified") is not True
        or claims.get("revocation_checked") is not True
        or claims.get("event_log_replayed") is not True
        or not _trusted_root("PYSEC_TPM2_ATTESTATION_ROOT_SHA256", claims)
    ):
        raise ValueError("TPM2 quote claims are incomplete")


def _verify_nitro(claims: dict[str, Any]) -> None:
    pcrs = claims.get("pcrs")
    if (
        set(claims) - _RAW_REPLAY_FIELDS
        != {
            "module_id",
            "digest_algorithm",
            "pcrs",
            "certificate_chain_sha256",
            "signature_verified",
            "certificate_chain_verified",
            "revocation_checked",
            "tcb_checked",
            "trust_root_sha256",
            "verifier_implementation_sha256",
        }
        or not _label(claims.get("module_id"))
        or claims.get("digest_algorithm") != "sha384"
        or not isinstance(pcrs, dict)
        or not {"0", "3", "8"}.issubset(pcrs)
        or any(not _sha384(str(pcrs[name])) for name in ("0", "3", "8"))
        or not _digest(str(claims.get("certificate_chain_sha256") or ""))
        or claims.get("signature_verified") is not True
        or claims.get("certificate_chain_verified") is not True
        or claims.get("revocation_checked") is not True
        or claims.get("tcb_checked") is not True
        or not _trusted_root("PYSEC_NITRO_ATTESTATION_ROOT_SHA256", claims)
    ):
        raise ValueError("Nitro attestation claims are incomplete")


def _verify_sev_snp(claims: dict[str, Any]) -> None:
    minimum_tcb = _minimum_tcb()
    if (
        set(claims) - _RAW_REPLAY_FIELDS
        != {
            "report_version",
            "measurement_sha384",
            "chip_id_sha256",
            "reported_tcb",
            "vcek_certificate_sha256",
            "signature_verified",
            "certificate_chain_verified",
            "revocation_checked",
            "tcb_checked",
            "trust_root_sha256",
            "verifier_implementation_sha256",
        }
        or not isinstance(claims.get("report_version"), int)
        or claims["report_version"] < 2
        or not _sha384(str(claims.get("measurement_sha384") or ""))
        or not _digest(str(claims.get("chip_id_sha256") or ""))
        or not isinstance(claims.get("reported_tcb"), int)
        or claims["reported_tcb"] < minimum_tcb
        or not _digest(str(claims.get("vcek_certificate_sha256") or ""))
        or claims.get("signature_verified") is not True
        or claims.get("certificate_chain_verified") is not True
        or claims.get("revocation_checked") is not True
        or claims.get("tcb_checked") is not True
        or not _trusted_root("PYSEC_SEV_SNP_ATTESTATION_ROOT_SHA256", claims)
    ):
        raise ValueError("SEV-SNP attestation claims are incomplete")


def _minimum_tcb() -> int:
    raw = os.environ.get("PYSEC_SEV_SNP_MIN_REPORTED_TCB", "0").strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("SEV-SNP minimum TCB is invalid") from exc
    if value < 0:
        raise ValueError("SEV-SNP minimum TCB is invalid")
    return value


def _verify_raw_replay(
    claims: dict[str, Any],
    *,
    format_name: str,
    challenge_sha256: str,
    host_identity_sha256: str,
    pcrs_sha256: str,
    implementation_sha256: str,
    normalized_authority_key_sha256: str,
    normalized_failure_domain: dict[str, object] | None,
    native_replay_verifier: NativeReplayVerifier | None,
) -> None:
    present = set(claims) & _RAW_REPLAY_FIELDS
    required = os.environ.get("PYSEC_REQUIRE_RAW_ATTESTATION_REPLAY", "").strip() == "1"
    if not present:
        if required:
            raise ValueError("independent raw attestation replay is required")
        return
    if present != _RAW_REPLAY_FIELDS:
        raise ValueError("raw attestation replay fields are incomplete")
    try:
        raw = base64.b64decode(str(claims["raw_evidence_base64"]), validate=True)
        public_bytes = base64.b64decode(
            str(claims["replay_public_key_pem_base64"]), validate=True
        )
        signature = base64.b64decode(
            str(claims["replay_signature_base64"]), validate=True
        )
        public = serialization.load_pem_public_key(public_bytes)
    except (TypeError, ValueError) as exc:
        raise ValueError("raw attestation replay encoding is invalid") from exc
    replay_key = (
        os.environ.get("PYSEC_RAW_ATTESTATION_REPLAY_KEY_SHA256", "").strip().casefold()
    )
    normalized = {
        name: value for name, value in claims.items() if name not in _RAW_REPLAY_FIELDS
    }
    replay_domain = claims["replay_failure_domain"]
    method = _VERIFICATION_METHODS[format_name]
    expected_statement = {
        "schema_version": "1.0",
        "format": format_name,
        "challenge_sha256": challenge_sha256,
        "host_identity_sha256": host_identity_sha256,
        "pcrs_sha256": pcrs_sha256,
        "raw_evidence_sha256": hashlib.sha256(raw).hexdigest(),
        "normalized_claims_sha256": hashlib.sha256(
            canonical_bytes(normalized)
        ).hexdigest(),
        "normalized_authority_key_sha256": normalized_authority_key_sha256,
        "verification_method": method,
        "verifier_executable_sha256": implementation_sha256,
        "verifier_runtime_sha256": str(
            (claims["replay_statement"] or {}).get("verifier_runtime_sha256")
        )
        if isinstance(claims["replay_statement"], dict)
        else "",
        "verifier_configuration_sha256": str(
            (claims["replay_statement"] or {}).get("verifier_configuration_sha256")
        )
        if isinstance(claims["replay_statement"], dict)
        else "",
        "verification_transcript_sha256": str(
            (claims["replay_statement"] or {}).get("verification_transcript_sha256")
        )
        if isinstance(claims["replay_statement"], dict)
        else "",
        "trust_root_sha256": str(normalized.get("trust_root_sha256") or ""),
        "failure_domain": replay_domain,
        "signature_verified": True,
        "certificate_chain_verified": True,
        "revocation_checked": True,
    }
    if (
        not raw
        or claims["raw_evidence_sha256"] != expected_statement["raw_evidence_sha256"]
        or claims["replay_statement"] != expected_statement
        or not _digest(replay_key)
        or not _digest(normalized_authority_key_sha256)
        or replay_key == normalized_authority_key_sha256
        or hashlib.sha256(public_bytes).hexdigest() != replay_key
        or not isinstance(public, Ed25519PublicKey)
        or any(
            not _digest(str(expected_statement[name]))
            for name in (
                "verifier_executable_sha256",
                "verifier_runtime_sha256",
                "verifier_configuration_sha256",
                "verification_transcript_sha256",
                "trust_root_sha256",
            )
        )
        or normalized_failure_domain is None
    ):
        raise ValueError("raw attestation replay binding is invalid")
    try:
        public.verify(signature, canonical_bytes(expected_statement))
    except Exception as exc:
        raise ValueError("raw attestation replay signature is invalid") from exc

    # A signed transcript proves what a verifier claimed it did, but it does not
    # prove native replay. The application layer injects the pinned executor so
    # this format parser remains below command execution in the dependency graph.
    if native_replay_verifier is None:
        raise ValueError("raw attestation replay authority verifier is unavailable")
    native_replay_verifier(
        claims=claims,
        format_name=format_name,
        expected_statement=expected_statement,
        implementation_sha256=implementation_sha256,
        replay_domain=replay_domain,
        replay_key_sha256=replay_key,
        normalized_failure_domain=normalized_failure_domain,
        verification_method=method,
        required=required,
    )


def _trusted_root(variable: str, claims: dict[str, Any]) -> bool:
    claimed = str(claims.get("trust_root_sha256") or "")
    expected = os.environ.get(variable, "").strip().casefold()
    required = (
        os.environ.get("PYSEC_REQUIRE_HARDWARE_ATTESTATION_ROOTS", "").strip() == "1"
    )
    if required and not _digest(expected):
        raise ValueError(f"{variable} is required")
    return _digest(claimed) and (not expected or claimed == expected)


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def _sha384(value: str) -> bool:
    return len(value) == 96 and all(
        character in "0123456789abcdef" for character in value
    )


def _label(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 512
