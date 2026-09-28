"""Certificate-chain quantum-risk assessment.

X.509 signatures are only as strong as the issuer key that made them.  This
module keeps the single-certificate report deliberately separate from chain
assessment so existing callers retain their stable, per-certificate result.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from arbiter.pki_risk_scoring.certificates import _key_info, load_certificates
from arbiter.pki_risk_scoring.scoring import DEFAULT_CRQC_YEAR, RiskAssessment, RiskLevel, assess_key

_SIGNATURE_OIDS: dict[str, tuple[str, str | None]] = {
    # PKCS#1 RSA signatures.
    "1.2.840.113549.1.1.4": ("RSA", "MD5"),
    "1.2.840.113549.1.1.5": ("RSA", "SHA-1"),
    "1.2.840.113549.1.1.11": ("RSA", "SHA-256"),
    "1.2.840.113549.1.1.12": ("RSA", "SHA-384"),
    "1.2.840.113549.1.1.13": ("RSA", "SHA-512"),
    "1.2.840.113549.1.1.14": ("RSA", "SHA-224"),
    "1.2.840.113549.1.1.10": ("RSA-PSS", None),
    # ANSI X9.62 ECDSA signatures.
    "1.2.840.10045.4.1": ("ECDSA", "SHA-1"),
    "1.2.840.10045.4.3.1": ("ECDSA", "SHA-224"),
    "1.2.840.10045.4.3.2": ("ECDSA", "SHA-256"),
    "1.2.840.10045.4.3.3": ("ECDSA", "SHA-384"),
    "1.2.840.10045.4.3.4": ("ECDSA", "SHA-512"),
    # NIST DSA signatures.
    "1.2.840.10040.4.3": ("DSA", "SHA-1"),
    "2.16.840.1.101.3.4.3.2": ("DSA", "SHA-256"),
    "2.16.840.1.101.3.4.3.3": ("DSA", "SHA-384"),
    "2.16.840.1.101.3.4.3.4": ("DSA", "SHA-512"),
    # RFC 8410 uses a pre-hashed, intrinsic construction rather than a
    # separately selectable digest.
    "1.3.101.112": ("Ed25519", None),
    "1.3.101.113": ("Ed448", None),
}

_HASH_STRENGTH: dict[str, tuple[int, int, RiskLevel, str]] = {
    "MD5": (64, 32, RiskLevel.CRITICAL, "MD5 is broken and must be replaced immediately."),
    "SHA-1": (80, 40, RiskLevel.CRITICAL, "SHA-1 is deprecated and collision-practical; replace immediately."),
    "SHA-224": (224, 112, RiskLevel.MEDIUM, "SHA-224 has a reduced post-quantum margin; prefer SHA-256 or stronger."),
    "SHA-256": (256, 128, RiskLevel.LOW, "SHA-256 retains a 128-bit Grover pre-image margin."),
    "SHA-384": (384, 192, RiskLevel.LOW, "SHA-384 retains a 192-bit Grover pre-image margin."),
    "SHA-512": (512, 256, RiskLevel.LOW, "SHA-512 retains a 256-bit Grover pre-image margin."),
}

_LEVEL_SCORE = {
    RiskLevel.LOW: 5,
    RiskLevel.MEDIUM: 50,
    RiskLevel.HIGH: 75,
    RiskLevel.CRITICAL: 100,
}


def _level_for_score(score: int) -> RiskLevel:
    if score >= 90:
        return RiskLevel.CRITICAL
    if score >= 70:
        return RiskLevel.HIGH
    if score >= 40:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


@dataclass(frozen=True)
class HashAssessment:
    algorithm: str | None
    classical_security_bits: int | None
    quantum_security_bits: int | None
    score: int
    level: RiskLevel
    recommendation: str

    def to_dict(self) -> dict:
        value = asdict(self)
        value["level"] = self.level.value
        return value


@dataclass(frozen=True)
class SignatureReport:
    algorithm: str
    hash_algorithm: str | None
    signing_key: RiskAssessment
    hash: HashAssessment
    score: int
    level: RiskLevel
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm,
            "hash_algorithm": self.hash_algorithm,
            "signing_key": self.signing_key.to_dict(),
            "hash": self.hash.to_dict(),
            "score": self.score,
            "level": self.level.value,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class ChainLinkReport:
    """One certificate in leaf-to-root order.

    ``signature`` is assessed with the issuer certificate's public-key size,
    when the issuer is available in the bundle.  The root's self-signature is
    assessed with its own key.
    """

    subject: str
    issuer: str
    serial: str
    not_after: str
    signer_subject: str
    public_key: RiskAssessment
    signature: SignatureReport
    score: int
    level: RiskLevel

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "not_after": self.not_after,
            "signer_subject": self.signer_subject,
            "public_key": self.public_key.to_dict(),
            "signature": self.signature.to_dict(),
            "score": self.score,
            "level": self.level.value,
        }


@dataclass(frozen=True)
class WeakestLink:
    subject: str
    role: str
    score: int
    level: RiskLevel
    reason: str

    def to_dict(self) -> dict:
        value = asdict(self)
        value["level"] = self.level.value
        return value


@dataclass(frozen=True)
class ChainReport:
    links: list[ChainLinkReport]
    weakest_link: WeakestLink
    score: int
    level: RiskLevel
    longest_lived_not_after: str
    mosca_violated: bool
    recommendation: str

    def to_dict(self) -> dict:
        return {
            "links": [link.to_dict() for link in self.links],
            "weakest_link": self.weakest_link.to_dict(),
            "score": self.score,
            "level": self.level.value,
            "longest_lived_not_after": self.longest_lived_not_after,
            "mosca_violated": self.mosca_violated,
            "recommendation": self.recommendation,
        }


def _signature_info(cert) -> tuple[str, str | None]:
    oid = cert.signature_algorithm_oid.dotted_string
    algorithm, hash_name = _SIGNATURE_OIDS.get(oid, (getattr(cert.signature_algorithm_oid, "_name", None) or oid, None))
    if hash_name is None:
        try:
            signature_hash = cert.signature_hash_algorithm
        except Exception:  # unsupported / intrinsic algorithms have no digest object
            signature_hash = None
        if signature_hash is not None:
            hash_name = signature_hash.name.upper().replace("SHA", "SHA-")
    return algorithm, hash_name


def _hash_assessment(hash_name: str | None) -> HashAssessment:
    if hash_name is None:
        return HashAssessment(
            None, None, None, 5, RiskLevel.LOW, "Signature algorithm has no separately selectable hash."
        )
    details = _HASH_STRENGTH.get(hash_name)
    if details is None:
        return HashAssessment(
            hash_name, None, None, 50, RiskLevel.MEDIUM, "Unrecognised signature hash; review manually."
        )
    classical, quantum, level, recommendation = details
    return HashAssessment(hash_name, classical, quantum, _LEVEL_SCORE[level], level, recommendation)


def _extension_key_identifier(cert, extension_type):
    try:
        return cert.extensions.get_extension_for_class(extension_type).value.key_identifier
    except Exception:
        return None


def _issuer_for(index: int, certificates: list) -> int | None:
    """Find a bundle issuer, preferring a matching authority-key identifier."""
    from cryptography import x509

    child = certificates[index]
    # A self-issued certificate is the trust anchor of this bundle. Do not
    # accidentally join it to another unrelated self-signed certificate that
    # happens to reuse the same distinguished name.
    if child.subject == child.issuer:
        return None
    child_aki = _extension_key_identifier(child, x509.AuthorityKeyIdentifier)
    candidates = [
        candidate_index
        for candidate_index, candidate in enumerate(certificates)
        if candidate_index != index and candidate.subject == child.issuer
    ]
    if not candidates:
        return None
    if child_aki is not None:
        keyed = [
            candidate_index
            for candidate_index in candidates
            if _extension_key_identifier(certificates[candidate_index], x509.SubjectKeyIdentifier) == child_aki
        ]
        if keyed:
            return keyed[0]
    return candidates[0]


def _ordered_paths(certificates: list) -> list[list[int]]:
    parents = {index: _issuer_for(index, certificates) for index in range(len(certificates))}
    parents = {child: parent for child, parent in parents.items() if parent is not None}
    issuers = set(parents.values())
    leaves = [index for index in range(len(certificates)) if index not in issuers]
    paths: list[list[int]] = []
    for leaf in leaves:
        path: list[int] = []
        current: int | None = leaf
        while current is not None and current not in path:
            path.append(current)
            current = parents.get(current)
        paths.append(path)
    return paths


def _link_report(
    cert,
    issuer,
    *,
    chain_expiry: datetime,
    protection_years_after_expiry: float,
    crqc_year: int,
    now: datetime | None,
) -> ChainLinkReport:
    cert_alg, cert_bits = _key_info(cert.public_key())
    cert_risk = assess_key(
        cert_alg,
        cert_bits,
        expires=cert.not_valid_after_utc,
        protection_years_after_expiry=protection_years_after_expiry,
        crqc_year=crqc_year,
        now=now,
    )
    signing_alg, hash_name = _signature_info(cert)
    signer = issuer or cert
    _, signer_bits = _key_info(signer.public_key())
    signing_key = assess_key(
        signing_alg,
        signer_bits,
        expires=chain_expiry,
        protection_years_after_expiry=protection_years_after_expiry,
        crqc_year=crqc_year,
        now=now,
    )
    hash_risk = _hash_assessment(hash_name)
    signature_score = max(signing_key.score, hash_risk.score)
    signature_level = _level_for_score(signature_score)
    if hash_risk.score >= signing_key.score:
        signature_recommendation = hash_risk.recommendation
    else:
        signature_recommendation = signing_key.recommendation
    signature = SignatureReport(
        signing_alg,
        hash_name,
        signing_key,
        hash_risk,
        signature_score,
        signature_level,
        signature_recommendation,
    )
    score = max(cert_risk.score, signature_score)
    return ChainLinkReport(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_after=cert.not_valid_after_utc.isoformat(),
        signer_subject=signer.subject.rfc4514_string(),
        public_key=cert_risk,
        signature=signature,
        score=score,
        level=_level_for_score(score),
    )


def assess_chains(
    data: bytes,
    *,
    protection_years_after_expiry: float = 0.0,
    crqc_year: int = DEFAULT_CRQC_YEAR,
    now: datetime | None = None,
) -> list[ChainReport]:
    """Order PEM/DER certificates into leaf-to-root paths and score each path.

    A bundle may contain unrelated certificate trees; every leaf path is
    returned independently, rather than silently treating the entire bundle as
    one trust chain.
    """
    certificates = load_certificates(data)
    reports: list[ChainReport] = []
    for path in _ordered_paths(certificates):
        path_certs = [certificates[index] for index in path]
        chain_expiry = max(cert.not_valid_after_utc for cert in path_certs)
        links = []
        for index, cert in zip(path, path_certs, strict=True):
            issuer_index = _issuer_for(index, certificates)
            issuer = certificates[issuer_index] if issuer_index is not None else None
            links.append(
                _link_report(
                    cert,
                    issuer,
                    chain_expiry=chain_expiry,
                    protection_years_after_expiry=protection_years_after_expiry,
                    crqc_year=crqc_year,
                    now=now,
                )
            )
        score = max(link.score for link in links)
        level = _level_for_score(score)
        # The key that signs a vulnerable certificate is the operational
        # bottleneck.  Prefer it to the signed leaf when their scores tie.
        weakest = max(links, key=lambda link: link.signature.score)
        if weakest.signature.hash.score >= weakest.signature.signing_key.score:
            weakest_link = WeakestLink(
                weakest.subject,
                "signature hash",
                weakest.signature.hash.score,
                weakest.signature.hash.level,
                weakest.signature.hash.recommendation,
            )
            recommendation = weakest.signature.hash.recommendation
        else:
            weakest_link = WeakestLink(
                weakest.signer_subject,
                "CA key" if weakest.signer_subject != weakest.subject else "root key",
                weakest.signature.signing_key.score,
                weakest.signature.signing_key.level,
                weakest.signature.signing_key.recommendation,
            )
            recommendation = (
                "The CA key is the bottleneck; migrating the leaf alone does not help. "
                + weakest.signature.signing_key.recommendation
            )
        reports.append(
            ChainReport(
                links=links,
                weakest_link=weakest_link,
                score=score,
                level=level,
                longest_lived_not_after=chain_expiry.isoformat(),
                mosca_violated=any(link.signature.signing_key.mosca_violated for link in links),
                recommendation=recommendation,
            )
        )
    return reports
