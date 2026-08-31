from __future__ import annotations

from typing import Any


RESILIENCE_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "NIST-IR-8374-R1",
        "version": "1-2026",
        "kind": "ransomware-risk-management-csf-profile",
        "reference": "https://csrc.nist.gov/pubs/ir/8374/r1/final",
        "evidence": ["risk-assessment.json", "operational-trend.json"],
    },
    {
        "id": "NIST-SP-1800-11",
        "version": "2020",
        "kind": "data-integrity-ransomware-recovery-practice-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/1800/11/final",
        "evidence": ["operational-trend.json", "procedure-assessment.json"],
    },
    {
        "id": "NIST-SP-1800-25",
        "version": "2020",
        "kind": "ransomware-identify-and-protect-practice-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/1800/25/final",
        "evidence": ["control-assessment.json", "risk-assessment.json"],
    },
    {
        "id": "NIST-SP-1800-26",
        "version": "2020",
        "kind": "ransomware-detect-and-respond-practice-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/1800/26/final",
        "evidence": ["operational-trend.json", "procedure-assessment.json"],
    },
    {
        "id": "NIST-SP-800-88-R2",
        "version": "2-2025",
        "kind": "media-sanitization-program-guidance",
        "reference": "https://csrc.nist.gov/pubs/sp/800/88/r2/final",
        "evidence": ["control-assessment.json", "procedure-assessment.json"],
    },
    {
        "id": "IEEE-2883",
        "version": "2022",
        "kind": "storage-sanitization-methods",
        "reference": "https://standards.ieee.org/ieee/2883/10277/",
        "evidence": ["procedure-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "IEEE-2883-1",
        "version": "2025",
        "kind": "storage-sanitization-application-practice",
        "reference": "https://standards.ieee.org/ieee/2883.1/11250/",
        "evidence": ["procedure-assessment.json", "audit-package-verification.json"],
    },
    {
        "id": "NIST-SP-1339",
        "version": "2026",
        "kind": "operational-technology-backup-quick-start-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/1339/final",
        "evidence": ["operational-trend.json", "procedure-assessment.json"],
    },
    {
        "id": "NIST-SP-1800-45",
        "version": "2026",
        "kind": "water-wastewater-ot-remote-access-practice-guide",
        "reference": "https://csrc.nist.gov/pubs/sp/1800/45/final",
        "evidence": ["control-assessment.json", "procedure-assessment.json"],
    },
    {
        "id": "IEC-TS-62443-6-1",
        "version": "2024",
        "kind": "iacs-service-provider-evaluation-methodology",
        "reference": "https://webstore.iec.ch/en/publication/67462",
        "evidence": ["procedure-assessment.json", "benchmark-scorecard.json"],
    },
    {
        "id": "ISO-22361",
        "version": "2022",
        "kind": "crisis-management-guidelines",
        "reference": "https://www.iso.org/standard/50267.html",
        "evidence": ["control-assessment.json", "operational-trend.json"],
    },
    {
        "id": "ISO-22398",
        "version": "2013",
        "kind": "exercise-programme-guidelines",
        "reference": "https://www.iso.org/standard/50294.html",
        "evidence": ["procedure-assessment.json", "operational-trend.json"],
    },
    {
        "id": "NIST-SP-800-221",
        "version": "2023",
        "kind": "enterprise-impact-of-ict-risk",
        "reference": "https://csrc.nist.gov/pubs/sp/800/221/final",
        "evidence": ["risk-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-SP-800-221A",
        "version": "2023",
        "kind": "ict-risk-outcomes-enterprise-risk-portfolio",
        "reference": "https://csrc.nist.gov/pubs/sp/800/221/a/final",
        "evidence": ["risk-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-SP-1347",
        "version": "2026",
        "kind": "csf-informative-reference-and-crosswalk-guidance",
        "reference": "https://csrc.nist.gov/pubs/sp/1347/final",
        "evidence": ["standards-crosswalk.json", "audit-package-verification.json"],
    },
    {
        "id": "NIST-IR-8406",
        "version": "update-1-2023",
        "kind": "liquefied-natural-gas-cybersecurity-framework-profile",
        "reference": "https://csrc.nist.gov/pubs/ir/8406/upd1/final",
        "evidence": ["risk-assessment.json", "domain-assurance.json"],
    },
    {
        "id": "NIST-IR-8473",
        "version": "2023",
        "kind": "electric-vehicle-extreme-fast-charging-csf-profile",
        "reference": "https://csrc.nist.gov/pubs/ir/8473/final",
        "evidence": ["risk-assessment.json", "domain-assurance.json"],
    },
)


RESILIENCE_WATCHLIST: tuple[dict[str, str], ...] = (
    {
        "id": "NIST-SP-800-82-R4",
        "status": "under-development",
        "stage": "pre-draft-policy-observed",
        "reference": "https://csrc.nist.gov/pubs/sp/800/82/r4/pre-draft",
        "reason": "Retain SP 800-82 Rev. 3 as normative until Revision 4 is final, source-pinned, impact-assessed, and approved through governed promotion.",
    },
    {
        "id": "NIST-IR-8183-R2",
        "status": "under-development",
        "stage": "draft-policy-observed",
        "reference": "https://csrc.nist.gov/pubs/ir/8183/r2/draft",
        "reason": "Keep the manufacturing CSF profile revision outside normative claims until NIST publishes a final edition and its CSF 2.0 outcomes are approved.",
    },
    {
        "id": "NIST-SP-1353",
        "status": "under-development",
        "stage": "initial-public-draft-policy-observed",
        "reference": "https://csrc.nist.gov/pubs/sp/1353/ipd",
        "reason": "Treat AI-assisted CSF reporting guidance as informative until final publication and require human-reviewed evidence for all mapping claims.",
    },
    {
        "id": "NIST-IR-8613",
        "status": "under-development",
        "stage": "initial-public-draft-policy-observed",
        "reference": "https://csrc.nist.gov/pubs/ir/8613/ipd",
        "reason": "Keep evolving multi-cloud architecture guidance outside normative claims until a final publication is pinned and approved.",
    },
)


RESILIENCE_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "ransomware-resilience-exercise",
        "version": "nist-ir8374r1-sp1800-11-25-26-2026",
        "kind": "ransomware-identify-protect-detect-respond-recover-and-reconcile-assurance",
        "source": "Final NIST ransomware profile and practice guides with inert encryption, exfiltration, identity, key-loss, restore, reconciliation and clean-control fixtures",
        "languages": ["ransomware", "resilience", "identity", "recovery", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "media-sanitization-verification",
        "version": "nist-sp800-88r2-ieee2883-2883.1-policy-pinned",
        "kind": "clear-purge-destroy-cryptographic-erase-and-residual-data-verification",
        "source": "NIST SP 800-88 Rev. 2 and licensed IEEE 2883/2883.1 criteria with synthetic physical, logical, virtual and cloud-storage fixtures",
        "languages": ["storage", "media", "cloud", "sanitization", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ot-backup-remote-access-recovery",
        "version": "nist-sp1339-sp1800-45-2026",
        "kind": "ot-backup-remote-access-restoration-order-safety-and-reconciliation-assurance",
        "source": "Final NIST OT backup and water/wastewater remote-access guidance with an inert PLC, HMI, historian and engineering-workstation twin",
        "languages": ["ot", "water", "backup", "remote-access", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "iec-62443-service-provider-evaluation",
        "version": "iec-ts62443-6-1-2024-policy-pinned",
        "kind": "repeatable-reproducible-iacs-service-provider-conformity-evaluation",
        "source": "Licensed IEC TS 62443-6-1 and IEC 62443-2-4 criteria with blinded provider evidence, golden decisions, mutations and adjudication fixtures",
        "languages": ["iacs", "service-provider", "assessment", "conformity", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "crisis-exercise-assurance",
        "version": "iso22361-2022-iso22398-2013-policy-pinned",
        "kind": "crisis-leadership-decision-communication-exercise-and-improvement-assurance",
        "source": "Licensed ISO 22361 and ISO 22398 criteria with protected scenarios, injects, decision logs, communications and corrective-action fixtures",
        "languages": ["crisis", "exercise", "leadership", "resilience", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "enterprise-ict-risk-aggregation",
        "version": "nist-sp800-221-221a-2023",
        "kind": "ict-risk-register-enterprise-portfolio-concentration-and-mission-outcome-assurance",
        "source": "NIST SP 800-221/221A with synthetic ICT risk registers, dependencies, correlated loss scenarios, appetite decisions and portfolio oracles",
        "languages": ["risk", "portfolio", "governance", "mission", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "standards-crosswalk-semantic-conformance",
        "version": "nist-sp1347-2026",
        "kind": "directional-versioned-provenance-bound-control-crosswalk-semantic-conformance",
        "source": "Final NIST SP 1347 guidance with positive, negative, stale-version, directionality, overclaim and round-trip crosswalk fixtures",
        "languages": ["crosswalk", "controls", "semantics", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "lng-ev-charging-sector-resilience",
        "version": "nist-ir8406-update1-ir8473-csf2-mapping-policy-pinned",
        "kind": "lng-and-ev-charging-cyber-physical-mission-resilience-and-csf-version-mapping-assurance",
        "source": "Final LNG and EV/XFC CSF 1.1 profiles with governed CSF 2.0 mappings and inert terminal, vessel, charger, cloud, building and utility fixtures",
        "languages": ["lng", "ev", "charging", "critical-infrastructure", "multi"],
        "lane": "authorized-companion",
    },
)


RESILIENCE_PROFILES: dict[str, dict[str, Any]] = {
    "ransomware-resilience": {
        "standards": [
            "NIST-IR-8374-R1",
            "NIST-SP-1800-11",
            "NIST-SP-1800-25",
            "NIST-SP-1800-26",
        ],
        "controls": [
            (
                "NIST-IR-8374-R1",
                "RANSOMWARE-END-TO-END",
                "Bind ransomware governance, assets, identities, data, dependencies, protective controls, detection, response, restoration and business reconciliation to named owners and evidence.",
                ["risk-assessment.json", "operational-trend.json"],
            ),
            (
                "NIST-SP-1800-25",
                "RANSOMWARE-IDENTIFY-PROTECT",
                "Verify authoritative inventory, protected backups, privileged access, segmentation, integrity monitoring and tested protective controls.",
                ["control-assessment.json", "domain-assurance.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-SP-1800-26",
                "RANSOMWARE-RECOVERY-EXERCISE",
                "Replay inert encryption, exfiltration, identity compromise, key loss, detection failure, containment, failover, restore and reconciliation with clean controls and independent recovery verification.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "operational-trend.json"],
            ),
        ],
    },
    "media-sanitization": {
        "standards": ["NIST-SP-800-88-R2", "IEEE-2883", "IEEE-2883-1"],
        "controls": [
            (
                "NIST-SP-800-88-R2",
                "SANITIZATION-PROGRAM",
                "Bind media type, data sensitivity, disposition, clear/purge/destroy method, cryptographic dependencies, custody, verifier, exception and retained certificate.",
                ["control-assessment.json", "audit-package-verification.json"],
            ),
            (
                "IEEE-2883",
                "SANITIZATION-METHOD",
                "Select and validate a medium-specific sanitization method without inferring success from command completion alone.",
                ["procedure-assessment.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "IEEE-2883-1",
                "RESIDUAL-DATA-VERIFY",
                "Execute authorized sanitization against synthetic media, independently sample residual data, validate cryptographic erase prerequisites and retain custody and destruction evidence.",
                "test",
                True,
                ["benchmark-scorecard.json", "procedure-assessment.json"],
            ),
        ],
    },
    "ot-backup-and-remote-access": {
        "standards": ["NIST-SP-1339", "NIST-SP-1800-45", "IEC-62443-3-3"],
        "controls": [
            (
                "NIST-SP-1339",
                "OT-BACKUP-FIDELITY",
                "Inventory and protect PLC, HMI, historian, engineering, identity, certificate, firmware, logic and configuration backups with dependencies and safe restoration order.",
                ["control-assessment.json", "operational-trend.json"],
            ),
            (
                "NIST-SP-1800-45",
                "OT-REMOTE-ACCESS",
                "Enforce identity, approval, least privilege, session isolation, recording, duration, revocation, emergency termination and vendor accountability for OT remote access.",
                ["control-assessment.json", "domain-assurance.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-SP-1339",
                "OT-RESTORE-AND-REMOTE-ACCESS-DRILL",
                "In an inert OT twin, restore dependencies in approved order and replay unauthorized, stale, overprivileged, unrecorded and non-terminating remote sessions without violating safety invariants.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "operational-trend.json"],
            ),
        ],
    },
    "iec-62443-provider-evaluation": {
        "standards": ["IEC-TS-62443-6-1", "IEC-62443-2-4"],
        "controls": [
            (
                "IEC-TS-62443-6-1",
                "EVALUATION-METHOD",
                "Bind evaluator independence, provider scope, licensed criteria, sampling, evidence sufficiency, decision rules, nonconformity grading, reproducibility, adjudication and retest.",
                ["procedure-assessment.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "IEC-TS-62443-6-1",
                "BLINDED-PROVIDER-EVALUATION",
                "Have independent assessors evaluate blinded golden and mutated provider cases; measure agreement, adjudicate material disagreements and prohibit an IEC certification claim.",
                "manual",
                False,
                ["benchmark-scorecard.json", "procedure-assessment.json"],
            ),
        ],
    },
    "crisis-leadership-and-exercises": {
        "standards": ["ISO-22361", "ISO-22398", "ISO-22320"],
        "controls": [
            (
                "ISO-22361",
                "CRISIS-CAPABILITY",
                "Bind crisis authority, strategic objectives, leadership roles, decision rights, stakeholder communications, information quality, ethics and learning to credible scenarios.",
                ["control-assessment.json", "operational-trend.json"],
            ),
        ],
        "procedures": [
            (
                "ISO-22398",
                "CRISIS-EXERCISE",
                "Design, conduct and independently evaluate a protected scenario with timed injects, decision and communication observations, measurable objectives, corrective owners, deadlines and retest.",
                "test",
                True,
                ["benchmark-scorecard.json", "operational-trend.json"],
            ),
        ],
    },
    "enterprise-ict-risk-portfolio": {
        "standards": ["NIST-SP-800-221", "NIST-SP-800-221A", "NIST-CSF"],
        "controls": [
            (
                "NIST-SP-800-221",
                "ICT-ENTERPRISE-RISK",
                "Trace technical ICT risks through business services, shared dependencies, mission outcomes, appetite, tolerance, ownership and enterprise portfolio decisions.",
                ["risk-assessment.json", "domain-assurance.json"],
            ),
            (
                "NIST-SP-800-221A",
                "ICT-RISK-OUTCOMES",
                "Preserve risk identity, assumptions, uncertainty, aggregation rules, concentrations, correlations, treatment state and decision history in machine-readable registers.",
                ["risk-assessment.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-SP-800-221A",
                "RISK-ROLLUP-REPERFORMANCE",
                "Independently reperform risk aggregation and replay hidden common dependencies, correlated loss, stale assumptions, double counting and aggregation-masked high risks.",
                "manual",
                False,
                ["benchmark-scorecard.json", "risk-assessment.json"],
            ),
        ],
    },
    "standards-crosswalk-governance": {
        "standards": ["NIST-SP-1347", "NIST-CSF"],
        "controls": [
            (
                "NIST-SP-1347",
                "CROSSWALK-PROVENANCE",
                "Bind every mapping to source and target editions, identifiers, relationship type, direction, scope, rationale, provenance, reviewer, confidence and approval state.",
                ["standards-crosswalk.json", "audit-package-verification.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-SP-1347",
                "CROSSWALK-SEMANTIC-CONFORMANCE",
                "Validate positive and negative mappings, reject unsupported equivalence and reversed direction, detect stale editions and verify lossless machine-readable round trips.",
                "test",
                False,
                ["benchmark-scorecard.json", "standards-crosswalk.json"],
            ),
        ],
    },
    "lng-and-ev-infrastructure": {
        "standards": ["NIST-IR-8406", "NIST-IR-8473", "NIST-CSF"],
        "controls": [
            (
                "NIST-IR-8406",
                "LNG-MISSION-RESILIENCE",
                "Bind LNG liquefaction, storage, loading, vessel, support, safety and third-party dependencies to prioritized cybersecurity outcomes and safe degraded operation.",
                ["risk-assessment.json", "domain-assurance.json"],
            ),
            (
                "NIST-IR-8473",
                "EV-XFC-ECOSYSTEM",
                "Bind vehicle, charger, site, cloud, payment, building and utility identities, data, commands, dependencies and recovery responsibilities.",
                ["risk-assessment.json", "domain-assurance.json"],
            ),
        ],
        "procedures": [
            (
                "NIST-CSF",
                "CSF1-TO-CSF2-SECTOR-REPLAY",
                "Review the governed CSF 1.1-to-2.0 mapping and exercise cyber-physical failures in inert LNG and EV/XFC twins without claiming the source profiles are native CSF 2.0 baselines.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "procedure-assessment.json"],
            ),
        ],
    },
}


def _adapter(
    benchmark_id: str,
    protocol: str,
    upstream: str,
    license_name: str,
    normalizer: str,
    required_inputs: tuple[str, ...],
    isolation: str,
) -> dict[str, Any]:
    return {
        "benchmark_id": benchmark_id,
        "protocol": protocol,
        "upstream": upstream,
        "acquisition": {
            "immutable_revision_required": True,
            "corpus_digest_required": True,
            "license_digest_required": True,
            "label_authority_digest_required": True,
            "golden_positive_required": True,
            "golden_negative_required": True,
            "signed_provenance_required": True,
            "replay_ledger_required": True,
            "license": license_name,
        },
        "normalizer": normalizer,
        "required_inputs": list(required_inputs),
        "isolation": isolation,
    }


RESILIENCE_ADAPTER_SPECS: tuple[dict[str, Any], ...] = (
    _adapter(
        "ransomware-resilience-exercise",
        "conformance",
        "https://csrc.nist.gov/Projects/ransomware-protection-and-response/publications",
        "US-government-guidance-and-organization-fixture-specific",
        "ransomware-function-outcome-recovery-reconciliation-v1",
        (
            "nist-publication-edition-and-csf-outcome-lock",
            "asset-identity-data-dependency-backup-and-key-manifest",
            "encryption-exfiltration-detection-containment-restore-and-reconciliation-oracles",
            "clean-controls-failure-injections-and-timed-observations",
            "independent-recovery-residue-and-corrective-action-ledger",
        ),
        "no-egress disposable enterprise twin with synthetic data and identities, inert ransomware actions, protected recovery credentials, bounded fault injection, kill switch, deterministic restoration, independent observers and no production disruption or resilience certification claim",
    ),
    _adapter(
        "media-sanitization-verification",
        "conformance",
        "https://csrc.nist.gov/pubs/sp/800/88/r2/final",
        "NIST-and-licensed-IEEE-criteria-media-and-laboratory-specific",
        "media-method-command-residual-verification-custody-v1",
        (
            "nist-ieee-edition-license-and-method-lock",
            "media-data-sensitivity-disposition-and-cryptographic-dependency-map",
            "clear-purge-destroy-command-and-residual-data-oracles",
            "physical-logical-virtual-cloud-failure-and-vendor-claim-cases",
            "custody-sampling-certificate-destruction-and-independent-verification-ledger",
        ),
        "dedicated no-egress media laboratory or approved emulator using synthetic data, test encryption keys and disposable devices, write containment, independent residual-data verification, signed destruction and key-disposal receipts, deterministic cleanup and no product or regulatory certification claim",
    ),
    _adapter(
        "ot-backup-remote-access-recovery",
        "conformance",
        "https://csrc.nist.gov/pubs/sp/1339/final",
        "US-government-guidance-and-OT-laboratory-specific",
        "ot-backup-remote-session-restoration-order-safety-v1",
        (
            "nist-guide-edition-and-architecture-lock",
            "plc-hmi-historian-engineering-identity-certificate-logic-and-config-map",
            "backup-fidelity-session-approval-recording-revocation-and-safety-oracles",
            "corruption-ordering-stale-access-privilege-outage-and-kill-switch-cases",
            "restoration-reconciliation-residue-and-independent-safety-review-ledger",
        ),
        "isolated inert OT and water-sector digital twin with synthetic process values and identities, target-only networking, bounded process effects, emergency stops, no production connectivity, deterministic restoration and no NIST endorsement or sector compliance claim",
    ),
    _adapter(
        "iec-62443-service-provider-evaluation",
        "assessor-agreement",
        "https://webstore.iec.ch/en/publication/67462",
        "licensed-IEC-62443-6-1-and-2-4-criteria-provider-and-assessor-specific",
        "iec62443-provider-evidence-decision-agreement-adjudication-v1",
        (
            "licensed-edition-requirement-method-and-assessor-lock",
            "provider-scope-service-role-applicability-sample-and-evidence-map",
            "golden-decision-sufficiency-nonconformity-and-retest-oracles",
            "omission-substitution-conflict-bias-and-reproducibility-cases",
            "blinded-agreement-adjudication-corrective-action-and-no-certification-ledger",
        ),
        "blinded no-egress assessment workspace with licensed criteria restricted to authorized assessors, protected answer keys, immutable submissions, independent adjudication, deterministic cleanup and no IEC conformity certificate claim",
    ),
    _adapter(
        "crisis-exercise-assurance",
        "assessor-agreement",
        "https://www.iso.org/standard/50267.html",
        "licensed-ISO-22361-22398-criteria-scenario-and-assessor-specific",
        "crisis-objective-inject-decision-communication-improvement-v1",
        (
            "licensed-edition-objective-and-evaluator-lock",
            "scenario-participant-role-decision-right-stakeholder-and-dependency-map",
            "inject-timeline-decision-communication-outcome-and-observation-oracles",
            "ambiguity-overload-misinformation-handoff-delay-and-recovery-cases",
            "blinded-evaluation-corrective-owner-retest-learning-and-no-certification-ledger",
        ),
        "protected exercise environment using synthetic scenarios and records, blinded evaluator observations, separated answer keys, controlled communications, independent adjudication, participant welfare safeguards and no operational emergency or ISO certification claim",
    ),
    _adapter(
        "enterprise-ict-risk-aggregation",
        "assessor-agreement",
        "https://csrc.nist.gov/pubs/sp/800/221/final",
        "US-government-guidance-and-organization-risk-record-specific",
        "ict-risk-register-portfolio-concentration-mission-outcome-v1",
        (
            "nist-publication-edition-risk-model-and-appetite-lock",
            "risk-asset-service-dependency-mission-owner-treatment-and-assumption-map",
            "aggregation-correlation-concentration-tolerance-and-decision-oracles",
            "stale-hidden-duplicate-circular-masked-and-common-cause-cases",
            "independent-reperformance-adjudication-uncertainty-and-decision-ledger",
        ),
        "blinded read-only risk workspace with synthetic registers and mission data, protected portfolio decisions, independent re-performance, immutable submissions, no individual ranking and no enterprise-risk certification claim",
    ),
    _adapter(
        "standards-crosswalk-semantic-conformance",
        "conformance",
        "https://csrc.nist.gov/pubs/sp/1347/final",
        "US-government-guidance-publisher-source-and-licensed-standard-specific",
        "crosswalk-version-direction-relationship-provenance-roundtrip-v1",
        (
            "source-target-edition-license-and-identifier-lock",
            "mapping-direction-relationship-scope-rationale-confidence-and-review-map",
            "positive-negative-partial-narrower-broader-and-no-relationship-oracles",
            "reversal-staleness-overclaim-orphan-cycle-drift-and-roundtrip-cases",
            "machine-readable-diff-review-approval-and-no-equivalence-overclaim-ledger",
        ),
        "no-egress read-only standards workspace with source-pinned public or licensed criteria, protected mapping oracles, independent semantic review, deterministic round trips, immutable diffs and no standards-body endorsement or equivalence claim",
    ),
    _adapter(
        "lng-ev-charging-sector-resilience",
        "conformance",
        "https://csrc.nist.gov/pubs/ir/8406/upd1/final",
        "US-government-guidance-sector-fixture-and-organization-CSF-mapping-specific",
        "lng-ev-cyberphysical-mission-csf-version-resilience-v1",
        (
            "nist-profile-edition-and-csf1-to-csf2-mapping-lock",
            "lng-terminal-vessel-support-ev-charger-cloud-building-utility-and-owner-map",
            "safety-service-payment-command-data-degraded-mode-and-recovery-oracles",
            "identity-command-cloud-communications-power-sensor-and-third-party-failure-cases",
            "mapping-review-restoration-reconciliation-residue-and-no-native-csf2-claim-ledger",
        ),
        "no-egress LNG and EV charging digital twins with synthetic identities payments commands and process values, inert physical models, bounded fault injection, emergency stops, independent safety observers, deterministic restoration, no production connectivity and no sector compliance or CSF 2.0 source-profile claim",
    ),
)


RESILIENCE_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = {
    "ransomware-resilience-exercise": {
        "scalars": {"baseline": "NIST-IR8374R1-SP1800-11-25-26"},
        "sets": {
            "functions": {
                "govern",
                "identify",
                "protect",
                "detect",
                "respond",
                "recover",
            }
        },
        "counts": (
            "systems_evaluated",
            "scenarios_replayed",
            "recovery_points_verified",
        ),
        "required_true": (
            "asset_identity_data_dependency_backup_and_key_scope_bound",
            "encryption_exfiltration_credential_key_detection_and_containment_cases_replayed",
            "offline_immutable_backup_integrity_and_restore_order_verified",
            "business_data_service_identity_and_key_reconciliation_verified",
            "clean_controls_detection_latency_recovery_time_and_data_loss_measured",
            "independent_recovery_residue_corrective_action_and_retest_verified",
        ),
        "required_false": (
            "live_ransomware_or_production_data_used",
            "ransomware_resilience_certification_claimed",
        ),
    },
    "media-sanitization-verification": {
        "scalars": {"baseline": "NIST-SP800-88R2-IEEE2883-2883.1"},
        "sets": {"methods": {"clear", "purge", "destroy", "cryptographic-erase"}},
        "counts": (
            "media_items_evaluated",
            "methods_evaluated",
            "residual_samples_verified",
        ),
        "required_true": (
            "media_type_sensitivity_disposition_method_owner_and_custody_bound",
            "cryptographic_key_scope_strength_wrapping_backup_and_destruction_verified",
            "command_completion_and_independent_residual_data_sampling_separated",
            "physical_logical_virtual_cloud_and_vendor_claim_cases_replayed",
            "exceptions_failed_methods_rework_and_final_disposition_verified",
            "signed_certificate_sampling_provenance_and_independent_review_verified",
        ),
        "required_false": (
            "production_media_or_live_sensitive_data_destroyed",
            "sanitization_product_certification_claimed",
        ),
    },
    "ot-backup-remote-access-recovery": {
        "scalars": {"baseline": "NIST-SP1339-SP1800-45"},
        "sets": {
            "asset_classes": {
                "plc",
                "hmi",
                "historian",
                "engineering-workstation",
                "identity",
                "certificate",
            }
        },
        "counts": (
            "sites_evaluated",
            "assets_restored",
            "remote_access_cases_replayed",
        ),
        "required_true": (
            "asset_logic_firmware_configuration_dependency_owner_and_restore_order_bound",
            "backup_offline_immutability_integrity_freshness_and_change_control_verified",
            "remote_identity_approval_privilege_isolation_recording_duration_and_revocation_verified",
            "corruption_ordering_stale_access_outage_overprivilege_and_kill_switch_cases_replayed",
            "safety_invariants_manual_fallback_restoration_and_reconciliation_verified",
            "independent_ot_safety_review_residue_cleanup_and_retest_verified",
        ),
        "required_false": (
            "production_ot_connected_or_actuated",
            "ot_sector_compliance_or_certification_claimed",
        ),
    },
    "iec-62443-service-provider-evaluation": {
        "scalars": {"baseline": "IEC-TS62443-6-1-2024"},
        "sets": {"assessment_parties": {"first-party", "second-party", "third-party"}},
        "counts": (
            "providers_evaluated",
            "assessors_calibrated",
            "blinded_cases_evaluated",
        ),
        "required_true": (
            "licensed_criteria_provider_scope_service_role_and_applicability_bound",
            "evaluator_competence_independence_conflict_and_authority_verified",
            "sampling_evidence_sufficiency_decision_rule_and_nonconformity_grading_verified",
            "omission_substitution_conflict_bias_and_reproducibility_cases_replayed",
            "inter_assessor_agreement_material_disagreement_and_adjudication_reported",
            "corrective_action_retest_traceability_and_record_integrity_verified",
        ),
        "required_false": (
            "production_provider_service_modified",
            "iec_conformity_or_certification_claimed",
        ),
    },
    "crisis-exercise-assurance": {
        "scalars": {"baseline": "ISO22361-2022-ISO22398-2013"},
        "sets": {
            "exercise_phases": {
                "plan",
                "prepare",
                "conduct",
                "evaluate",
                "improve",
                "retest",
            }
        },
        "counts": (
            "organizations_evaluated",
            "objectives_evaluated",
            "injects_replayed",
        ),
        "required_true": (
            "crisis_authority_roles_decision_rights_objectives_and_stakeholders_bound",
            "scenario_assumptions_inject_timeline_ground_truth_and_observation_plan_verified",
            "leadership_decision_latency_information_quality_ethics_and_communications_measured",
            "ambiguity_overload_misinformation_handoff_delay_and_recovery_cases_replayed",
            "evaluator_independence_participant_welfare_and_data_protection_verified",
            "corrective_owner_deadline_learning_reassessment_and_retest_verified",
        ),
        "required_false": (
            "live_emergency_or_public_communications_used",
            "crisis_management_certification_claimed",
        ),
    },
    "enterprise-ict-risk-aggregation": {
        "scalars": {"baseline": "NIST-SP800-221-221A"},
        "sets": {
            "portfolio_levels": {
                "system",
                "service",
                "business-unit",
                "enterprise",
                "mission",
            }
        },
        "counts": (
            "risk_records_evaluated",
            "dependencies_evaluated",
            "aggregation_cases_replayed",
        ),
        "required_true": (
            "risk_asset_service_dependency_mission_owner_treatment_and_assumption_bound",
            "appetite_tolerance_likelihood_impact_uncertainty_and_time_horizon_verified",
            "aggregation_correlation_concentration_common_cause_and_cascading_loss_verified",
            "stale_hidden_duplicate_circular_double_counted_and_masked_high_risk_cases_replayed",
            "machine_readable_register_lineage_decision_history_and_access_controls_verified",
            "independent_reperformance_disagreement_adjudication_and_reassessment_verified",
        ),
        "required_false": (
            "real_confidential_enterprise_risk_register_used",
            "enterprise_risk_certification_claimed",
        ),
    },
    "standards-crosswalk-semantic-conformance": {
        "scalars": {"baseline": "NIST-SP1347-2026"},
        "sets": {
            "relationship_types": {
                "equivalent",
                "subset",
                "superset",
                "intersects",
                "no-relationship",
            }
        },
        "counts": (
            "standards_evaluated",
            "mappings_evaluated",
            "negative_cases_replayed",
        ),
        "required_true": (
            "source_target_editions_identifiers_licenses_and_provenance_bound",
            "mapping_direction_relationship_scope_rationale_confidence_and_reviewer_verified",
            "positive_negative_partial_narrower_broader_and_no_relationship_oracles_verified",
            "reversal_staleness_overclaim_orphan_cycle_and_semantic_drift_cases_replayed",
            "machine_readable_schema_lossless_roundtrip_diff_and_version_migration_verified",
            "independent_semantic_review_approval_expiry_and_reassessment_verified",
        ),
        "required_false": (
            "unlicensed_normative_text_reproduced",
            "standards_equivalence_or_certification_claimed",
        ),
    },
    "lng-ev-charging-sector-resilience": {
        "scalars": {"baseline": "NIST-IR8406-UPD1-IR8473-CSF2-MAPPING"},
        "sets": {
            "sector_domains": {
                "lng-terminal",
                "lng-vessel",
                "lng-support",
                "ev",
                "charger",
                "cloud",
                "building",
                "utility",
            }
        },
        "counts": (
            "facilities_evaluated",
            "interfaces_evaluated",
            "scenarios_replayed",
        ),
        "required_true": (
            "mission_asset_identity_data_command_dependency_owner_and_safety_scope_bound",
            "csf1_source_outcome_to_csf2_mapping_direction_rationale_and_review_verified",
            "lng_process_storage_loading_vessel_support_and_degraded_operation_verified",
            "ev_charger_cloud_payment_building_utility_and_vehicle_boundaries_verified",
            "identity_command_power_cloud_sensor_communications_and_third_party_failures_replayed",
            "safe_state_service_recovery_reconciliation_residue_and_independent_review_verified",
        ),
        "required_false": (
            "production_lng_or_charging_infrastructure_actuated",
            "native_csf2_profile_or_sector_certification_claimed",
        ),
    },
}


RESILIENCE_BENCHMARK_IDS = frozenset(RESILIENCE_EVIDENCE_CONTRACTS)
RESILIENCE_BENCHMARK_PROTOCOLS = {
    identifier: (
        "assessor-agreement"
        if identifier
        in {
            "iec-62443-service-provider-evaluation",
            "crisis-exercise-assurance",
            "enterprise-ict-risk-aggregation",
        }
        else "conformance"
    )
    for identifier in RESILIENCE_BENCHMARK_IDS
}
