from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc3161ng  # type: ignore[import-untyped]
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from pyasn1.codec.der import decoder as der_decoder  # type: ignore[import-untyped]
from pyasn1_modules import rfc5035  # type: ignore[import-untyped]

from .strict_json import canonical_bytes


def verify_rfc3161(
    context_path: Path,
    value: object,
    challenge_sha256: str,
    *,
    require_advanced: bool = False,
) -> dict[str, str]:
    v1_required = {
        "format",
        "authority",
        "observed_at",
        "receipt_file",
        "receipt_sha256",
        "signer_certificate_file",
        "signer_certificate_sha256",
        "nonce",
    }
    v2_extra = {
        "certificate_chain_file",
        "certificate_chain_sha256",
        "trust_roots_file",
        "trust_roots_sha256",
        "revocation_file",
        "revocation_sha256",
        "tsa_policy_oid",
        "require_ess_cert_id_v2",
    }
    if not isinstance(value, dict):
        raise TypeError("trusted_time must be an object")
    advanced = set(value) == v1_required | v2_extra
    if set(value) != v1_required and not advanced:
        raise ValueError("trusted_time fields do not match the RFC 3161 contract")
    if require_advanced and not advanced:
        raise ValueError("this operation requires the advanced RFC 3161 trust contract")
    if value.get("format") != "rfc3161":
        raise ValueError("trusted_time format must be rfc3161")
    authority = _text(value.get("authority"), "trusted-time authority", 200)
    receipt_path = _sibling(
        context_path, value.get("receipt_file"), "timestamp receipt"
    )
    certificate_path = _sibling(
        context_path,
        value.get("signer_certificate_file"),
        "timestamp signer certificate",
    )
    receipt = _bounded_bytes(receipt_path, "timestamp receipt", 4 * 1024 * 1024)
    certificate_bytes = _bounded_bytes(
        certificate_path, "timestamp signer certificate", 1024 * 1024
    )
    receipt_sha256 = _match_digest(
        receipt, value.get("receipt_sha256"), "timestamp receipt"
    )
    signer_sha256 = _match_digest(
        certificate_bytes,
        value.get("signer_certificate_sha256"),
        "timestamp signer certificate",
    )
    nonce = _nonce(value.get("nonce"))
    if not _digest(challenge_sha256):
        raise ValueError("challenge_sha256 is invalid")
    try:
        response = rfc3161ng.decode_timestamp_response(receipt)
        token = response["timeStampToken"]
        rfc3161ng.check_timestamp(
            token,
            certificate=certificate_bytes,
            digest=bytes.fromhex(challenge_sha256),
            hashname="sha256",
            nonce=nonce,
        )
        issued_at = rfc3161ng.get_timestamp(token, naive=False).astimezone(UTC)
    except Exception as exc:
        raise ValueError("RFC 3161 timestamp verification failed") from exc
    observed_at = _timestamp(value.get("observed_at"))
    if abs((issued_at - observed_at).total_seconds()) > 1:
        raise ValueError("RFC 3161 timestamp does not match observed_at")
    certificate = _certificate(certificate_bytes)
    try:
        eku = certificate.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage
        ).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("timestamp signer certificate lacks an EKU") from exc
    if ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        raise ValueError(
            "timestamp signer certificate is not authorized for timestamping"
        )
    if (
        not certificate.not_valid_before_utc
        <= issued_at
        <= certificate.not_valid_after_utc
    ):
        raise ValueError("timestamp signer certificate was not valid at issuance")
    trust_sha256 = ""
    revocation_sha256 = ""
    policy_oid = ""
    if advanced:
        chain_bytes = _bounded_bytes(
            _sibling(
                context_path,
                value.get("certificate_chain_file"),
                "timestamp certificate chain",
            ),
            "timestamp certificate chain",
            4 * 1024 * 1024,
        )
        roots_bytes = _bounded_bytes(
            _sibling(
                context_path, value.get("trust_roots_file"), "timestamp trust roots"
            ),
            "timestamp trust roots",
            4 * 1024 * 1024,
        )
        revocation_bytes = _bounded_bytes(
            _sibling(
                context_path,
                value.get("revocation_file"),
                "timestamp revocation snapshot",
            ),
            "timestamp revocation snapshot",
            4 * 1024 * 1024,
        )
        _match_digest(
            chain_bytes,
            value.get("certificate_chain_sha256"),
            "timestamp certificate chain",
        )
        trust_sha256 = _match_digest(
            roots_bytes, value.get("trust_roots_sha256"), "timestamp trust roots"
        )
        revocation_sha256 = _match_digest(
            revocation_bytes,
            value.get("revocation_sha256"),
            "timestamp revocation snapshot",
        )
        chain = _certificates(chain_bytes, "timestamp certificate chain")
        roots = _certificates(roots_bytes, "timestamp trust roots")
        if certificate.fingerprint(hashes.SHA256()) != chain[0].fingerprint(
            hashes.SHA256()
        ):
            raise ValueError(
                "timestamp signer is not the first certificate in its chain"
            )
        _verify_chain(chain, roots, issued_at)
        _verify_revocation(chain, roots, revocation_bytes, issued_at)
        policy_oid = _text(value.get("tsa_policy_oid"), "TSA policy OID", 200)
        if not all(part.isdigit() for part in policy_oid.split(".")):
            raise ValueError("TSA policy OID is invalid")
        if str(token.tst_info["policy"]) != policy_oid:
            raise ValueError("RFC 3161 TSA policy OID does not match")
        _verify_deployment_policy(authority, trust_sha256, policy_oid)
        if value.get("require_ess_cert_id_v2") is not True:
            raise ValueError("RFC 3161 v2 requires ESSCertIDv2")
        _verify_ess_cert_id_v2(token, certificate)
    else:
        _verify_legacy_policy(authority, signer_sha256)
    normalized = {
        "format": "rfc3161",
        "authority": authority,
        "observed_at": observed_at.isoformat(),
        "receipt_sha256": receipt_sha256,
        "signer_certificate_sha256": signer_sha256,
        "nonce_sha256": hashlib.sha256(str(nonce).encode()).hexdigest(),
        "trust_roots_sha256": trust_sha256,
        "revocation_sha256": revocation_sha256,
        "tsa_policy_oid": policy_oid,
    }
    return {
        "trusted_time_sha256": hashlib.sha256(canonical_bytes(normalized)).hexdigest(),
        "trusted_time_observed_at": observed_at.isoformat(),
        "trusted_time_receipt_sha256": receipt_sha256,
        "trusted_time_signer_sha256": signer_sha256,
    }


def _verify_deployment_policy(
    authority: str, root_sha256: str, policy_oid: str
) -> None:
    """Bind evidence-provided PKIX material to deployment-owned trust anchors."""
    pinned_roots = _deployment_values("PYSEC_TSA_ROOT_SHA256", digest=True)
    allowed_policies = _deployment_values("PYSEC_TSA_POLICY_OIDS")
    allowed_authorities = _deployment_values("PYSEC_TSA_AUTHORITIES")
    if root_sha256 not in pinned_roots:
        raise ValueError("timestamp trust root is not deployment-pinned")
    if policy_oid not in allowed_policies:
        raise ValueError("timestamp policy OID is not deployment-approved")
    if authority not in allowed_authorities:
        raise ValueError("timestamp authority is not deployment-approved")


def _verify_legacy_policy(authority: str, signer_sha256: str) -> None:
    pinned_signers = _deployment_values("PYSEC_TSA_SIGNER_SHA256", digest=True)
    allowed_authorities = _deployment_values("PYSEC_TSA_AUTHORITIES")
    if signer_sha256 not in pinned_signers:
        raise ValueError("timestamp signer is not deployment-pinned")
    if authority not in allowed_authorities:
        raise ValueError("timestamp authority is not deployment-approved")


def _deployment_values(name: str, *, digest: bool = False) -> set[str]:
    values = {
        item.strip() for item in os.environ.get(name, "").split(",") if item.strip()
    }
    if not values or (digest and not all(_digest(item) for item in values)):
        raise ValueError(f"{name} deployment policy is unavailable or invalid")
    return values


def _certificates(value: bytes, label: str) -> list[x509.Certificate]:
    try:
        certificates = x509.load_pem_x509_certificates(value)
    except ValueError:
        try:
            certificates = [_certificate(value)]
        except ValueError as exc:
            raise ValueError(f"{label} is invalid") from exc
    if not certificates or len(certificates) > 16:
        raise ValueError(f"{label} must contain 1 to 16 certificates")
    return certificates


def _verify_chain(
    chain: list[x509.Certificate], roots: list[x509.Certificate], issued_at: datetime
) -> None:
    current = chain[0]
    visited: set[bytes] = set()
    for depth in range(16):
        fingerprint = current.fingerprint(hashes.SHA256())
        if fingerprint in visited:
            raise ValueError("timestamp certificate chain contains a cycle")
        visited.add(fingerprint)
        if not current.not_valid_before_utc <= issued_at <= current.not_valid_after_utc:
            raise ValueError("timestamp certificate chain was not valid at issuance")
        trusted = next(
            (
                root
                for root in roots
                if root.fingerprint(hashes.SHA256()) == fingerprint
            ),
            None,
        )
        if trusted is not None:
            _verify_certificate_signature(current, current)
            _verify_ca_constraints(current, max(0, depth - 1))
            return
        candidates = [*chain[1:], *roots]
        issuers = [item for item in candidates if item.subject == current.issuer]
        issuer = _select_issuer(current, issuers)
        if issuer is None:
            raise ValueError(
                "timestamp certificate chain does not reach a trusted root"
            )
        _verify_ca_constraints(issuer, depth)
        _reject_unsupported_path_constraints(issuer)
        _verify_certificate_signature(current, issuer)
        current = issuer
    raise ValueError("timestamp certificate chain exceeds maximum depth")


def _select_issuer(
    certificate: x509.Certificate, candidates: list[x509.Certificate]
) -> x509.Certificate | None:
    if not candidates:
        return None
    try:
        authority_key = certificate.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
    except x509.ExtensionNotFound:
        authority_key = None
    if authority_key is not None:
        matched: list[x509.Certificate] = []
        for candidate in candidates:
            try:
                subject_key = candidate.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value.digest
            except x509.ExtensionNotFound:
                continue
            if subject_key == authority_key:
                matched.append(candidate)
        candidates = matched
    if len(candidates) != 1:
        raise ValueError("timestamp certificate issuer is missing or ambiguous")
    return candidates[0]


def _verify_ca_constraints(certificate: x509.Certificate, ca_below: int) -> None:
    try:
        constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        usage = certificate.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("timestamp issuer lacks CA constraints") from exc
    if not constraints.ca or not usage.key_cert_sign or not usage.crl_sign:
        raise ValueError("timestamp issuer is not authorized as a CA")
    if constraints.path_length is not None and ca_below > constraints.path_length:
        raise ValueError("timestamp certificate path length constraint was exceeded")


def _reject_unsupported_path_constraints(certificate: x509.Certificate) -> None:
    for extension_type in (
        x509.NameConstraints,
        x509.PolicyConstraints,
        x509.InhibitAnyPolicy,
    ):
        try:
            certificate.extensions.get_extension_for_class(extension_type)
        except x509.ExtensionNotFound:
            continue
        raise ValueError(
            "timestamp certificate contains unsupported critical path constraints"
        )


def _verify_certificate_signature(
    certificate: x509.Certificate, issuer: x509.Certificate
) -> None:
    key = issuer.public_key()
    signature_hash = certificate.signature_hash_algorithm
    if signature_hash is None and isinstance(
        key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
    ):
        raise ValueError("timestamp certificate signature hash is unavailable")
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                _signature_hash(signature_hash),
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(_signature_hash(signature_hash)),
            )
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(certificate.signature, certificate.tbs_certificate_bytes)
        else:
            raise ValueError("timestamp certificate key algorithm is unsupported")
    except Exception as exc:
        raise ValueError("timestamp certificate chain signature is invalid") from exc


def _verify_revocation(
    chain: list[x509.Certificate],
    roots: list[x509.Certificate],
    raw: bytes,
    issued_at: datetime,
) -> None:
    try:
        crls = [
            x509.load_pem_x509_crl(block + b"-----END X509 CRL-----\n")
            for block in raw.split(b"-----END X509 CRL-----")
            if b"-----BEGIN X509 CRL-----" in block
        ]
    except ValueError as exc:
        raise ValueError("timestamp revocation snapshot is invalid") from exc
    if not crls:
        try:
            crls = [x509.load_der_x509_crl(raw)]
        except ValueError as exc:
            raise ValueError("timestamp revocation snapshot is invalid") from exc
    issuers = {certificate.subject: certificate for certificate in [*chain[1:], *roots]}
    covered_serials: set[int] = set()
    for crl in crls:
        issuer = issuers.get(crl.issuer)
        if issuer is None:
            continue
        _verify_crl_signature(crl, issuer)
        if crl.last_update_utc > issued_at or (
            crl.next_update_utc is None or crl.next_update_utc < issued_at
        ):
            raise ValueError("timestamp revocation snapshot is not valid at issuance")
        children = [
            certificate for certificate in chain if certificate.issuer == crl.issuer
        ]
        for child in children:
            covered_serials.add(child.serial_number)
            revoked = crl.get_revoked_certificate_by_serial_number(child.serial_number)
            if revoked is not None and revoked.revocation_date_utc <= issued_at:
                raise ValueError("timestamp certificate was revoked at issuance")
    required_serials = {
        certificate.serial_number
        for certificate in chain
        if certificate.subject != certificate.issuer
    }
    if not required_serials.issubset(covered_serials):
        raise ValueError(
            "timestamp revocation snapshot does not cover the full certificate path"
        )


def _verify_crl_signature(
    crl: x509.CertificateRevocationList, issuer: x509.Certificate
) -> None:
    key = issuer.public_key()
    signature_hash = crl.signature_hash_algorithm
    if signature_hash is None and isinstance(
        key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)
    ):
        raise ValueError("timestamp CRL signature hash is unavailable")
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                _signature_hash(signature_hash),
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(_signature_hash(signature_hash)),
            )
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(crl.signature, crl.tbs_certlist_bytes)
        else:
            raise ValueError("timestamp CRL key algorithm is unsupported")
    except Exception as exc:
        raise ValueError("timestamp revocation snapshot signature is invalid") from exc


def _verify_ess_cert_id_v2(token: Any, certificate: x509.Certificate) -> None:
    oid = "1.2.840.113549.1.9.16.2.47"
    signer_info = token.content["signerInfos"][0]
    matching = [
        attribute
        for attribute in signer_info["authenticatedAttributes"]
        if str(attribute[0]) == oid
    ]
    if len(matching) != 1:
        raise ValueError("RFC 3161 timestamp lacks one ESSCertIDv2 attribute")
    try:
        decoded, remainder = der_decoder.decode(
            bytes(matching[0][1][0]), asn1Spec=rfc5035.SigningCertificateV2()
        )
        certs = decoded["certs"]
        cert_id = certs[0]
        algorithm = str(cert_id["hashAlgorithm"]["algorithm"])
        cert_hash = bytes(cert_id["certHash"])
    except Exception as exc:
        raise ValueError("RFC 3161 ESSCertIDv2 is malformed") from exc
    expected = hashlib.sha256(
        certificate.public_bytes(serialization.Encoding.DER)
    ).digest()
    if (
        remainder
        or len(certs) != 1
        or algorithm not in {"", "2.16.840.1.101.3.4.2.1"}
        or cert_hash != expected
    ):
        raise ValueError("RFC 3161 timestamp lacks a matching ESSCertIDv2")


def _signature_hash(value: hashes.HashAlgorithm | None) -> hashes.HashAlgorithm:
    if value is None:
        raise ValueError("signature hash algorithm is unavailable")
    return value


def _sibling(context: Path, value: object, label: str) -> Path:
    name = str(value or "")
    if not name or Path(name).name != name or len(name) > 200:
        raise ValueError(f"{label} file must be a bounded sibling filename")
    return context.resolve().parent / name


def _bounded_bytes(path: Path, label: str, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > maximum:
        raise ValueError(f"{label} must be a bounded regular file")
    return path.read_bytes()


def _match_digest(payload: bytes, expected: object, label: str) -> str:
    digest = str(expected or "")
    if not _digest(digest) or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError(f"{label} SHA-256 does not match")
    return digest


def _certificate(value: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(value)
    except ValueError:
        try:
            return x509.load_der_x509_certificate(value)
        except ValueError as exc:
            raise ValueError("timestamp signer certificate is invalid") from exc


def _nonce(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 < value <= 2**53 - 1
    ):
        raise ValueError("timestamp nonce must be a positive I-JSON integer")
    return value


def _timestamp(value: object) -> datetime:
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("trusted_time observed_at is invalid") from exc
    if result.tzinfo is None:
        raise ValueError("trusted_time observed_at must include a timezone")
    return result.astimezone(UTC)


def _text(value: Any, label: str, maximum: int) -> str:
    result = str(value or "").strip()
    if not result or len(result) > maximum:
        raise ValueError(f"{label} is invalid")
    return result


def _digest(value: str) -> bool:
    return len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )
