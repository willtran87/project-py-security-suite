from __future__ import annotations

from typing import Any


EMERGING_ASSURANCE_STANDARDS: tuple[dict[str, Any], ...] = (
    {
        "id": "CIS-AWS-FOUNDATIONS",
        "version": "7.0.0",
        "kind": "aws-foundational-secure-configuration-benchmark",
        "reference": "https://www.cisecurity.org/benchmark/amazon_web_services",
        "evidence": ["control-assessment.json", "cloud-attack-paths.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "CIS-AZURE-FOUNDATIONS",
        "version": "6.0.0",
        "kind": "azure-foundational-secure-configuration-benchmark",
        "reference": "https://www.cisecurity.org/benchmark/azure",
        "evidence": ["control-assessment.json", "cloud-attack-paths.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-04",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "CIS-GCP-FOUNDATIONS",
        "version": "5.0.0",
        "kind": "gcp-foundational-secure-configuration-benchmark",
        "reference": "https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
        "evidence": ["control-assessment.json", "cloud-attack-paths.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "CIS-DOCKER",
        "version": "1.8.0",
        "kind": "docker-secure-configuration-benchmark",
        "reference": "https://www.cisecurity.org/benchmark/docker",
        "evidence": ["control-assessment.json", "container-security.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-07",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OWASP-GENAI-RED-TEAMING-GUIDE",
        "version": "1.0-2025-01-23",
        "kind": "generative-ai-red-teaming-methodology",
        "reference": "https://genai.owasp.org/resource/genai-red-teaming-guide/",
        "evidence": ["ai-security.json", "adversarial-campaign.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-01-23",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "IMDA-AI-VERIFY",
        "version": "policy-pinned-2026-08-31",
        "kind": "ai-governance-testing-framework-and-toolkit",
        "reference": "https://www.imda.gov.sg/about-imda/research-and-statistics/sgdigital/tech-pillars/artificial-intelligence",
        "evidence": ["ai-security.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-08-31",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "IMDA-PROJECT-MOONSHOT",
        "version": "open-beta-policy-pinned-2026-08-31",
        "kind": "llm-benchmarking-red-teaming-and-baseline-testing-toolkit",
        "reference": "https://github.com/aiverify-foundation/moonshot",
        "evidence": ["ai-security.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-08-31",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "NCSC-CHECK",
        "version": "scheme-standard-1.1-policy-pinned",
        "kind": "uk-government-and-cni-penetration-testing-assurance-scheme",
        "reference": "https://www.ncsc.gov.uk/schemes/check/scheme-documents",
        "evidence": [
            "external-conformity-assessment.json",
            "penetration-test-assessment.json",
        ],
        "lifecycle": {
            "edition_status": "final",
            "published": "2024-11",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "AIUC-1",
        "version": "q3-2026-2026-07-15",
        "kind": "ai-agent-security-safety-reliability-and-accountability-standard",
        "reference": "https://www.aiuc-1.com/",
        "evidence": ["ai-security.json", "external-conformity-assessment.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2026-07-15",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK",
        "version": "2.0-2019-03-05",
        "kind": "iot-system-component-security-controls-framework",
        "reference": "https://cloudsecurityalliance.org/artifacts/iot-security-controls-framework",
        "evidence": ["control-assessment.json", "standards-crosswalk.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2019-03-05",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "ETSI-EN-304-223",
        "version": "V2.1.1",
        "kind": "baseline-cybersecurity-requirements-for-ai-models-and-systems",
        "reference": "https://www.etsi.org/deliver/etsi_en/304200_304299/304223/02.01.01_60/en_304223v020101p.pdf",
        "evidence": ["ai-security.json", "security-requirements-coverage.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2025-12",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "FIVE-EYES-AGENTIC-AI-GUIDANCE",
        "version": "2026-04-30",
        "kind": "government-agentic-ai-adoption-security-guidance",
        "reference": "https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services",
        "evidence": ["ai-security.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-04-30",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "NSA-MCP-SECURITY-GUIDANCE",
        "version": "2026-05-20",
        "kind": "government-mcp-security-design-guidance",
        "reference": "https://www.nsa.gov/Portals/75/documents/Cybersecurity/CSI_MCP_SECURITY.pdf",
        "evidence": ["ai-security.json", "benchmark-scorecard.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026-05-20",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "CSA-MAESTRO",
        "version": "policy-pinned-2025-02-06",
        "kind": "agentic-ai-layered-threat-modeling-framework",
        "reference": "https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro",
        "evidence": ["threat-model.json", "architecture-evaluation.json"],
        "lifecycle": {
            "edition_status": "policy-pinned",
            "published": "2025-02-06",
            "observed_at": "2026-08-31",
        },
    },
    {
        "id": "OWASP-FIASSE",
        "version": "1.1.0",
        "kind": "framework-for-inherently-adaptive-and-securable-software-engineering",
        "reference": "https://owasp.org/www-project-fiasse/",
        "evidence": ["architecture-evaluation.json", "control-assessment.json"],
        "lifecycle": {
            "edition_status": "final",
            "published": "2026",
            "observed_at": "2026-08-31",
        },
    },
)


EMERGING_ASSURANCE_PROFILES: dict[str, dict[str, Any]] = {
    "cis-cloud-container-hardening": {
        "standards": [
            "CIS-AWS-FOUNDATIONS",
            "CIS-AZURE-FOUNDATIONS",
            "CIS-GCP-FOUNDATIONS",
            "CIS-DOCKER",
            "NIST-SCAP",
        ],
        "controls": [
            (
                "CIS-AWS-FOUNDATIONS",
                "CIS-CLOUD-EDITION-PROFILE-ASSET-AND-RESPONSIBILITY-BINDING",
                "Bind each CIS edition, Level 1 or Level 2 profile, account or tenant hierarchy, region, resource inventory, benchmark recommendation, automated or manual status, cloud responsibility and approved applicability decision to one immutable assessment subject.",
                ["control-assessment.json", "standards-crosswalk.json"],
            ),
            (
                "CIS-DOCKER",
                "CIS-DOCKER-HOST-DAEMON-IMAGE-CONTAINER-AND-ORCHESTRATION-SCOPE",
                "Bind Docker host, daemon, files, images, build pipeline, runtime containers and orchestration features to the release-pinned benchmark; preserve recommendation scoring, non-scored items, manual checks, exceptions and inherited platform responsibility.",
                ["control-assessment.json", "container-security.json"],
            ),
        ],
        "procedures": [
            (
                "CIS-AWS-FOUNDATIONS",
                "CIS-CLOUD-AND-DOCKER-INDEPENDENT-CONFORMANCE-REPLAY",
                "Execute each provider and Docker benchmark independently against version-matched disposable targets; reconcile native and independent observations, challenge manual-check and not-applicable decisions, inject drift and stale exceptions, perform authorized remediation and rollback, and require a clean rescan without aggregating failures away.",
                "automated",
                True,
                ["benchmark-scorecard.json", "control-assessment.json"],
            )
        ],
    },
    "owasp-genai-red-team-assurance": {
        "standards": [
            "OWASP-GENAI-RED-TEAMING-GUIDE",
            "OWASP-AISVS",
            "MITRE-ATLAS",
            "NIST-AI-RMF",
        ],
        "controls": [
            (
                "OWASP-GENAI-RED-TEAMING-GUIDE",
                "GENAI-RED-TEAM-SCOPE-THREAT-MODEL-AUTHORITY-AND-SAFETY",
                "Bind the model, application, agents, tools, data, infrastructure, deployment context, threat actors, objectives, prohibited actions, authorization, rate and cost budgets, safety stop, escalation path and restoration plan before testing.",
                ["ai-security.json", "adversarial-campaign.json"],
            ),
            (
                "OWASP-GENAI-RED-TEAMING-GUIDE",
                "GENAI-RED-TEAM-MODEL-IMPLEMENTATION-INFRASTRUCTURE-AND-RUNTIME-COVERAGE",
                "Require distinct model-evaluation, implementation, infrastructure and runtime-behavior evidence with multi-turn, indirect-injection, retrieval, tool, memory, cross-tenant, exfiltration, privilege, denial-of-wallet and scorer-manipulation cases plus benign-utility retention.",
                ["ai-security.json", "benchmark-scorecard.json"],
            ),
        ],
        "procedures": [
            (
                "OWASP-GENAI-RED-TEAMING-GUIDE",
                "GENAI-RED-TEAM-CAMPAIGN-REPLAY-REMEDIATION-AND-RETEST",
                "Run a preregistered campaign in a no-egress environment with inert tools and synthetic secrets, preserve every prompt, state transition, tool decision and scorer result, independently replay successes and clean controls, verify remediation without unacceptable utility regression and retest the complete affected attack family.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "adversarial-campaign.json"],
            )
        ],
    },
    "imda-ai-verify-moonshot-assurance": {
        "standards": [
            "IMDA-AI-VERIFY",
            "IMDA-PROJECT-MOONSHOT",
            "NIST-AI-RMF",
            "ISO-IEC-42001",
        ],
        "controls": [
            (
                "IMDA-AI-VERIFY",
                "AI-VERIFY-PRINCIPLE-CLAIM-PROCESS-AND-TECHNICAL-TEST-BINDING",
                "Bind all applicable governance principles, declared claims, system role, model and application version, population and use context, process checks, technical tests, thresholds, limitations and accountable owners to the evaluated subject.",
                ["ai-security.json", "external-conformity-assessment.json"],
            ),
            (
                "IMDA-PROJECT-MOONSHOT",
                "MOONSHOT-RUNNER-DATASET-METRIC-SEED-AND-SCORER-PROVENANCE",
                "Pin toolkit, recipes, connectors, datasets, prompts, transformations, model endpoints, sampling parameters, seeds, metrics and scorers; measure contamination, nondeterminism, grader manipulation, refusal and benign utility without treating toolkit output as conformity or safety certification.",
                ["benchmark-scorecard.json", "ai-security.json"],
            ),
        ],
        "procedures": [
            (
                "IMDA-PROJECT-MOONSHOT",
                "AI-VERIFY-MOONSHOT-GOVERNANCE-AND-TECHNICAL-REPLAY",
                "Execute traditional and generative-AI cases as applicable, independently replay process and technical results, challenge fairness, robustness, explainability, safety, security, privacy and data-governance claims across protected strata, repeat stochastic tests and report unsupported principles and uncertainty as gaps.",
                "test",
                True,
                ["benchmark-scorecard.json", "external-conformity-assessment.json"],
            )
        ],
    },
    "ncsc-check-penetration-testing": {
        "standards": ["NCSC-CHECK", "CREST-PENETRATION-TESTING-GUIDE", "PTES"],
        "controls": [
            (
                "NCSC-CHECK",
                "CHECK-PROVIDER-TEAM-CREDENTIAL-SCOPE-AND-AUTHORITY-VALIDATION",
                "Verify the provider and team against a signed, current NCSC registry snapshot; bind customer, system, threat agents, technologies, test types, exclusions, timing, contacts, safety constraints, data handling and written authorization before any active testing.",
                [
                    "external-conformity-assessment.json",
                    "penetration-test-assessment.json",
                ],
            ),
            (
                "NCSC-CHECK",
                "CHECK-METHODOLOGY-EVIDENCE-CUSTODY-REPORT-AND-CLOSURE",
                "Preserve methodology, observations, exploit evidence, severity rationale, affected assets, collateral findings, custody, disclosure, cleanup, recommendations, customer decisions, remediation and retest while separating suite readiness from NCSC provider status or government acceptance.",
                ["penetration-test-assessment.json", "closure-plan.json"],
            ),
        ],
        "procedures": [
            (
                "NCSC-CHECK",
                "CHECK-AUTHORIZED-ENGAGEMENT-INDEPENDENT-REPERFORMANCE",
                "Replay an authorized representative engagement using positive, negative and out-of-scope cases; verify stop conditions, evidence sufficiency, vulnerability reproducibility, complete cleanup, restored service, remediation and independent retest, with production testing permitted only under the customer's explicit authority and safety plan.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "penetration-test-assessment.json"],
            )
        ],
    },
    "aiuc1-agent-assurance": {
        "standards": ["AIUC-1", "ISO-IEC-42001", "NIST-AI-RMF", "OWASP-AISVS"],
        "controls": [
            (
                "AIUC-1",
                "AIUC1-QUARTERLY-EDITION-CAPABILITY-APPLICABILITY-AND-EVIDENCE-BINDING",
                "Bind the quarterly AIUC-1 edition, universal and capability-specific applicability, agent model, tools, data, memory, users, deployment and operating context to mandatory, optional and supplemental controls with technical, legal and operational evidence.",
                ["ai-security.json", "external-conformity-assessment.json"],
            ),
            (
                "AIUC-1",
                "AIUC1-INDEPENDENT-EVAL-FAILURE-PLAN-MONITORING-AND-RECERTIFICATION",
                "Require independent adversarial, harmful-output, hallucination and unsafe-tool evaluations, production monitoring, accountable failure plans, corrective action and quarterly retesting while recording that only the scheme owner can issue an AIUC-1 certificate.",
                ["benchmark-scorecard.json", "operational-trend.json"],
            ),
        ],
        "procedures": [
            (
                "AIUC-1",
                "AIUC1-AGENT-SAFEGUARD-EVALUATION-AND-CHANGE-REPLAY",
                "Test data leakage, prompt injection, unauthorized action, harmful and out-of-scope output, hallucination, unsafe tool calls, privilege boundaries, coding-agent secret handling and runtime containment with clean controls; independently replay fixes and re-evaluate after material model, tool or policy change.",
                "test",
                True,
                ["benchmark-scorecard.json", "ai-security.json"],
            )
        ],
    },
    "csa-iot-controls-alignment": {
        "standards": [
            "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK",
            "NISTIR-8259",
            "ETSI-EN-303-645",
            "UK-PSTI",
        ],
        "controls": [
            (
                "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK",
                "CSA-IOT-SYSTEM-COMPONENT-DATA-FLOW-AND-CONTROL-ALLOCATION",
                "Bind devices, gateways, networks, cloud and mobile services, operators, identities, data flows, trust boundaries, safety dependencies and component control allocations to an immutable IoT system architecture and approved risk context.",
                ["architecture-evaluation.json", "control-assessment.json"],
            ),
            (
                "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK",
                "CSA-IOT-LIFECYCLE-SUPPLIER-UPDATE-RECOVERY-AND-SUPPORT-BOUNDARY",
                "Trace secure defaults, credentials, communications, data protection, logging, vulnerability handling, signed updates, rollback, supplier dependencies, support periods, decommissioning and recovery across device and service lifecycles without substituting a crosswalk for product conformity.",
                ["standards-crosswalk.json", "domain-assurance.json"],
            ),
        ],
        "procedures": [
            (
                "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK",
                "CSA-IOT-COMPONENT-FAILURE-ATTACK-UPDATE-AND-RECOVERY-REPLAY",
                "In an isolated representative IoT laboratory, inject default-credential, unauthorized-device, network-partition, cloud-loss, malicious-update, rollback, data-exposure and supplier-discontinuity cases; verify safe degraded operation, known-good recovery, residue removal and crosswalk semantic preservation.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "domain-assurance.json"],
            )
        ],
    },
    "etsi-ai-cybersecurity-baseline": {
        "standards": [
            "ETSI-EN-304-223",
            "OWASP-AISVS",
            "ISO-IEC-42001",
            "NIST-AI-RMF",
        ],
        "controls": [
            (
                "ETSI-EN-304-223",
                "ETSI-AI-LIFECYCLE-SUBJECT-ROLE-RISK-AND-REQUIREMENT-BINDING",
                "Bind the AI model or system, intended use, lifecycle stage, developer, provider, deployer, operator, downstream integrator, data and model suppliers, assets, threats, risk decisions, applicable principles and requirement-level evidence to one immutable assessment subject.",
                ["ai-security.json", "security-requirements-coverage.json"],
            ),
            (
                "ETSI-EN-304-223",
                "ETSI-AI-SECURE-DESIGN-DEVELOPMENT-DEPLOYMENT-MAINTENANCE-AND-END-OF-LIFE",
                "Trace secure design, data and model integrity, supply chain, infrastructure, access, logging, vulnerability handling, change, incident response, recovery and secure retirement across all five AI lifecycle stages without converting guidance alignment into certification.",
                ["lifecycle-traceability.json", "control-assessment.json"],
            ),
        ],
        "procedures": [
            (
                "ETSI-EN-304-223",
                "ETSI-AI-BASELINE-ADVERSE-LIFECYCLE-AND-INDEPENDENT-REPLAY",
                "Reperform every applicable baseline requirement using positive, negative, boundary and lifecycle-transition cases; inject poisoning, model substitution, unsafe deployment, privilege abuse, monitoring loss, update failure and incomplete retirement, then independently replay remediation and recovery with retained uncertainty and residual risk.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "ai-security.json"],
            )
        ],
    },
    "agentic-adoption-and-containment": {
        "standards": [
            "FIVE-EYES-AGENTIC-AI-GUIDANCE",
            "CSA-MAESTRO",
            "OWASP-AGENTIC-TOP-10",
            "OWASP-AISVS",
        ],
        "controls": [
            (
                "FIVE-EYES-AGENTIC-AI-GUIDANCE",
                "AGENTIC-INCREMENTAL-AUTONOMY-IDENTITY-PRIVILEGE-AND-ACCOUNTABILITY",
                "Introduce autonomy incrementally; bind every agent, user, delegation, tool, data source, memory store and action to authenticated identities, least privilege, current authorization, human approval for high-impact action, complete logging, rollback and accountable ownership.",
                ["ai-security.json", "architecture-evaluation.json"],
            ),
            (
                "CSA-MAESTRO",
                "MAESTRO-LAYER-CROSS-LAYER-TRUST-AND-ATTACK-PATH-MODEL",
                "Model the complete agentic stack by layer, trust boundary and dependency; preserve threats and controls within each layer and adversarial paths that cross model, data, agent framework, tool, identity, infrastructure and ecosystem boundaries.",
                ["threat-model.json", "architecture-evaluation.json"],
            ),
        ],
        "procedures": [
            (
                "FIVE-EYES-AGENTIC-AI-GUIDANCE",
                "AGENTIC-HARNESS-ESCAPE-SUBVERSION-PERSISTENCE-AND-RECOVERY-TEST",
                "In a disposable no-egress evaluator, test attempts to escape or disable the harness, alter policy or scorers, acquire new tools or credentials, cross tenant or agent boundaries, establish persistence, use covert channels, exfiltrate synthetic secrets, evade shutdown and corrupt cleanup evidence; require independent containment, restoration and benign-utility replay.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "adversarial-campaign.json"],
            )
        ],
    },
    "mcp-high-assurance-automation": {
        "standards": [
            "NSA-MCP-SECURITY-GUIDANCE",
            "MCP-SPECIFICATION",
            "OWASP-MCP-SECURITY-CHEAT-SHEET",
            "OWASP-AISVS",
        ],
        "controls": [
            (
                "NSA-MCP-SECURITY-GUIDANCE",
                "MCP-IDENTITY-SESSION-AUTHORITY-CONTEXT-AND-SERIALIZATION-BOUNDARY",
                "Bind client, server, proxy, authorization server, user, agent, session, capability, resource, prompt, tool and task identity; deny ambiguous delegation, validate every serialized message, separate trust domains and prevent context from silently crossing servers, tenants or sessions.",
                ["ai-security.json", "architecture-evaluation.json"],
            ),
            (
                "NSA-MCP-SECURITY-GUIDANCE",
                "MCP-CONTINUOUS-MONITORING-REVOCATION-TEARDOWN-AND-RECOVERY",
                "Continuously monitor discovery, capability and tool changes, reauthorize privileged operations, expire and revoke tokens and tasks, bound resource consumption, preserve audit chains and prove teardown removes sessions, delegated authority, cached context, artifacts and secrets.",
                ["benchmark-scorecard.json", "operational-trend.json"],
            ),
        ],
        "procedures": [
            (
                "NSA-MCP-SECURITY-GUIDANCE",
                "MCP-IMPLICIT-TRUST-CROSS-SERVER-CONTEXT-AND-TASK-PROPAGATION-TEST",
                "Replay confused-deputy, authorization ambiguity, session fixation, cross-server context leakage, schema and serialization abuse, capability drift, task propagation, cancellation race, tool substitution, malicious output and teardown-residue cases against clean controls in an isolated MCP laboratory.",
                "dynamic",
                True,
                ["benchmark-scorecard.json", "ai-security.json"],
            )
        ],
    },
    "fiasse-securability-engineering": {
        "standards": ["OWASP-FIASSE", "OWASP-SAMM", "OWASP-ASVS", "NIST-SSDF"],
        "controls": [
            (
                "OWASP-FIASSE",
                "FIASSE-ISOLATED-INTEGRITY-CANONICAL-PARSING-AND-REQUEST-SURFACE",
                "Require critical decisions to derive from authoritative managed state, canonicalize and validate external input before use, minimize intentional request surfaces, enforce trust-boundary controls and make security-relevant behavior observable to engineers and reviewers.",
                ["architecture-evaluation.json", "control-assessment.json"],
            ),
            (
                "OWASP-FIASSE",
                "FIASSE-MERGE-REVIEW-SECURABILITY-REPORT-AND-ACCOUNTABLE-OVERRIDE",
                "Produce a source- and change-bound securability report for every merge, preserve evidence and uncertainty, identify remediation leverage and architectural friction, and record accountable, expiring overrides without treating an experimental score as proof of security.",
                ["control-assessment.json", "closure-plan.json"],
            ),
        ],
        "procedures": [
            (
                "OWASP-FIASSE",
                "FIASSE-CANONICALIZATION-AUTHORITY-SUBSTITUTION-AND-MERGE-REGRESSION",
                "Mutate equivalent, ambiguous and malformed representations; substitute client-controlled facts for authoritative state; expand request surfaces; remove observability and challenge merge-review overrides, then verify deterministic rejection, actionable evidence and remediation replay while keeping the beta SSEM scorer non-normative.",
                "test",
                False,
                ["benchmark-scorecard.json", "architecture-evaluation.json"],
            )
        ],
    },
}


EMERGING_ASSURANCE_BENCHMARKS: tuple[dict[str, Any], ...] = (
    {
        "id": "cis-aws-foundations-conformance",
        "version": "cis-aws-foundations-7.0.0",
        "kind": "aws-level-profile-automated-manual-and-drift-conformance",
        "source": "CIS AWS Foundations 7.0.0 with recommendation identities, Level 1 and Level 2 profiles, automated and manual methods, approved applicability, drift and rescan fixtures",
        "languages": ["aws", "terraform", "cloudformation", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cis-azure-foundations-conformance",
        "version": "cis-azure-foundations-6.0.0",
        "kind": "azure-level-profile-automated-manual-and-drift-conformance",
        "source": "CIS Microsoft Azure Foundations 6.0.0 with recommendation identities, profiles, automated and manual methods, approved applicability, drift and rescan fixtures",
        "languages": ["azure", "bicep", "terraform", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cis-gcp-foundations-conformance",
        "version": "cis-gcp-foundations-5.0.0",
        "kind": "gcp-level-profile-automated-manual-and-drift-conformance",
        "source": "CIS Google Cloud Platform Foundation 5.0.0 with recommendation identities, profiles, automated and manual methods, approved applicability, drift and rescan fixtures",
        "languages": ["gcp", "terraform", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "cis-docker-conformance",
        "version": "cis-docker-1.8.0",
        "kind": "docker-host-daemon-image-container-and-orchestration-conformance",
        "source": "CIS Docker 1.8.0 with scored and non-scored recommendations, host, daemon, file, image, runtime and orchestration fixtures",
        "languages": ["docker", "container", "linux", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "owasp-genai-red-team-assurance",
        "version": "owasp-genai-red-teaming-guide-1.0",
        "kind": "model-implementation-infrastructure-and-runtime-red-team-assurance",
        "source": "OWASP GenAI Red Teaming Guide 1.0 with preregistered threat-led campaigns, multi-turn and agentic adversarial cases, clean controls, utility retention and remediation replay",
        "languages": ["ai", "llm", "agentic", "red-team", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "imda-ai-verify-moonshot-assurance",
        "version": "ai-verify-moonshot-policy-pinned-2026-08-31",
        "kind": "ai-governance-process-technical-test-benchmark-and-red-team-assurance",
        "source": "Policy-pinned AI Verify framework and Project Moonshot runner with traditional and generative AI fixtures, protected strata, stochastic repetitions, scorer attacks and independent replay",
        "languages": ["ai", "ml", "llm", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "ncsc-check-engagement-assurance",
        "version": "ncsc-check-scheme-standard-1.1-policy-pinned",
        "kind": "provider-team-scope-methodology-evidence-report-and-retest-assurance",
        "source": "NCSC CHECK Scheme Standard 1.1, signed provider and team registry snapshots, representative engagement evidence, safety, cleanup, remediation and retest cases",
        "languages": ["penetration-testing", "uk-government", "cni", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "aiuc1-agent-assurance",
        "version": "aiuc1-q3-2026-2026-07-15",
        "kind": "agent-data-security-safety-reliability-accountability-and-societal-assurance",
        "source": "AIUC-1 Q3 2026 requirements and evidence criteria with agent capability applicability, independent technical evaluations, operational controls and change-triggered retesting",
        "languages": ["ai", "agentic", "coding-agent", "governance", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "csa-iot-controls-conformance",
        "version": "csa-iot-security-controls-framework-2.0",
        "kind": "iot-component-control-allocation-lifecycle-attack-and-recovery-conformance",
        "source": "CSA IoT Security Controls Framework v2 with device, gateway, network, cloud and mobile component allocations, lifecycle evidence, semantic crosswalk and fault fixtures",
        "languages": ["iot", "device", "cloud", "network", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "etsi-ai-cybersecurity-lifecycle-conformance",
        "version": "etsi-en-304-223-v2.1.1",
        "kind": "ai-model-system-lifecycle-baseline-cybersecurity-conformance",
        "source": "ETSI EN 304 223 V2.1.1 requirement-level lifecycle fixtures with stakeholder, applicability, attack, change, recovery and retirement evidence",
        "languages": ["ai", "ml", "llm", "agentic", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "agentic-evaluator-containment-assurance",
        "version": "five-eyes-2026-maestro-policy-pinned",
        "kind": "agentic-harness-escape-cross-layer-containment-and-recovery-assurance",
        "source": "Five Eyes agentic adoption guidance, CSA MAESTRO layer model and organization-approved evaluator escape, subversion, persistence, covert exfiltration and recovery fixtures",
        "languages": ["ai", "agentic", "mcp", "automation", "multi"],
        "lane": "authorized-companion",
    },
    {
        "id": "fiasse-securability-assurance",
        "version": "owasp-fiasse-1.1.0",
        "kind": "securability-canonical-parsing-isolated-integrity-and-merge-review-assurance",
        "source": "OWASP FIASSE 1.1.0 with canonical parsing, authoritative-state, intentional request-surface, transparency, merge-review and override fixtures; SSEM score remains non-normative",
        "languages": ["architecture", "application", "secure-engineering", "multi"],
        "lane": "authorized-companion",
    },
)


EMERGING_ASSURANCE_BENCHMARK_PROTOCOLS = {
    benchmark["id"]: "conformance" for benchmark in EMERGING_ASSURANCE_BENCHMARKS
}

EMERGING_ASSURANCE_LABORATORY_BENCHMARKS = frozenset(
    {
        "owasp-genai-red-team-assurance",
        "imda-ai-verify-moonshot-assurance",
        "ncsc-check-engagement-assurance",
        "aiuc1-agent-assurance",
        "csa-iot-controls-conformance",
        "etsi-ai-cybersecurity-lifecycle-conformance",
        "agentic-evaluator-containment-assurance",
    }
)


_COMMON_ACQUISITION: dict[str, bool] = {
    "immutable_revision_required": True,
    "corpus_digest_required": True,
    "license_digest_required": True,
    "label_authority_digest_required": True,
    "golden_positive_required": True,
    "golden_negative_required": True,
    "signed_provenance_required": True,
    "replay_ledger_required": True,
}


def _adapter(
    benchmark_id: str,
    upstream: str,
    license_name: str,
    normalizer: str,
    required_inputs: list[str],
    isolation: str,
) -> dict[str, Any]:
    return {
        "benchmark_id": benchmark_id,
        "protocol": "conformance",
        "upstream": upstream,
        "acquisition": {**_COMMON_ACQUISITION, "license": license_name},
        "normalizer": normalizer,
        "required_inputs": required_inputs,
        "isolation": isolation,
    }


EMERGING_ASSURANCE_ADAPTER_SPECS: tuple[dict[str, Any], ...] = (
    _adapter(
        "cis-aws-foundations-conformance",
        "https://www.cisecurity.org/benchmark/amazon_web_services",
        "cis-benchmark-terms-and-organization-assessment-record-specific",
        "cis-aws-foundations-7-profile-recommendation-result-v1",
        [
            "benchmark-edition-license-and-recommendation-digest",
            "account-organization-region-resource-and-responsibility-inventory",
            "level-profile-automated-manual-and-applicability-record",
            "native-independent-finding-exception-and-drift-reconciliation",
            "authorized-remediation-rollback-cleanup-and-rescan-ledger",
        ],
        "read-only organization assessment plus disposable accounts with synthetic data, least privilege, explicit remediation authority, deterministic cleanup and no CIS certification claim",
    ),
    _adapter(
        "cis-azure-foundations-conformance",
        "https://www.cisecurity.org/benchmark/azure",
        "cis-benchmark-terms-and-organization-assessment-record-specific",
        "cis-azure-foundations-6-profile-recommendation-result-v1",
        [
            "benchmark-edition-license-and-recommendation-digest",
            "tenant-management-group-subscription-resource-and-responsibility-inventory",
            "level-profile-automated-manual-and-applicability-record",
            "native-independent-finding-exemption-and-drift-reconciliation",
            "authorized-remediation-rollback-cleanup-and-rescan-ledger",
        ],
        "read-only tenant assessment plus disposable subscriptions with synthetic data, least privilege, explicit remediation authority, deterministic cleanup and no CIS certification claim",
    ),
    _adapter(
        "cis-gcp-foundations-conformance",
        "https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
        "cis-benchmark-terms-and-organization-assessment-record-specific",
        "cis-gcp-foundations-5-profile-recommendation-result-v1",
        [
            "benchmark-edition-license-and-recommendation-digest",
            "organization-folder-project-region-resource-and-responsibility-inventory",
            "level-profile-automated-manual-and-applicability-record",
            "native-independent-finding-exception-and-drift-reconciliation",
            "authorized-remediation-rollback-cleanup-and-rescan-ledger",
        ],
        "read-only organization assessment plus disposable projects with synthetic data, least privilege, explicit remediation authority, deterministic cleanup and no CIS certification claim",
    ),
    _adapter(
        "cis-docker-conformance",
        "https://www.cisecurity.org/benchmark/docker",
        "cis-benchmark-terms-and-organization-assessment-record-specific",
        "cis-docker-1.8-host-daemon-image-runtime-result-v1",
        [
            "benchmark-edition-license-and-recommendation-digest",
            "host-daemon-file-image-container-and-orchestration-inventory",
            "scored-nonscored-automated-manual-and-applicability-record",
            "independent-engine-disagreement-exception-and-drift-report",
            "disposable-remediation-rollback-cleanup-and-rescan-ledger",
        ],
        "no-egress disposable Docker hosts and containers with synthetic images, no host device access, deterministic teardown and no CIS certification claim",
    ),
    _adapter(
        "owasp-genai-red-team-assurance",
        "https://genai.owasp.org/resource/genai-red-teaming-guide/",
        "creative-commons-guidance-and-organization-campaign-specific",
        "owasp-genai-campaign-state-tool-utility-result-v1",
        [
            "guide-edition-threat-model-scope-and-authorization-lock",
            "model-application-agent-tool-data-and-infrastructure-manifest",
            "campaign-case-clean-control-and-utility-baseline",
            "prompt-state-tool-scorer-and-independent-replay-transcript",
            "finding-remediation-regression-restoration-and-retest-ledger",
        ],
        "no-egress red-team laboratory with inert allowlisted tools, synthetic secrets and identities, bounded cost, emergency stop, state reset and no OWASP certification or production-safety claim",
    ),
    _adapter(
        "imda-ai-verify-moonshot-assurance",
        "https://github.com/aiverify-foundation/moonshot",
        "open-source-toolkit-framework-and-dataset-specific",
        "ai-verify-moonshot-principle-process-technical-result-v1",
        [
            "framework-toolkit-recipe-connector-and-license-lock",
            "model-application-use-context-population-and-claim-manifest",
            "process-check-dataset-prompt-metric-seed-and-scorer-record",
            "protected-strata-stochastic-contamination-and-manipulation-report",
            "independent-replay-limitation-remediation-and-retest-ledger",
        ],
        "no-egress AI evaluation laboratory with synthetic or licensed datasets, isolated endpoints, inert tools, repeated trials and no IMDA, AI Verify or safety certification claim",
    ),
    _adapter(
        "ncsc-check-engagement-assurance",
        "https://www.ncsc.gov.uk/schemes/check/scheme-documents",
        "uk-crown-copyright-scheme-and-authorized-engagement-record-specific",
        "ncsc-check-provider-scope-engagement-report-result-v1",
        [
            "scheme-standard-provider-registry-and-credential-snapshot",
            "customer-system-threat-technology-test-type-and-authority-scope",
            "method-observation-exploit-severity-and-custody-record",
            "safety-stop-disclosure-collateral-finding-and-cleanup-report",
            "customer-decision-remediation-restoration-and-retest-ledger",
        ],
        "NCSC-assured CHECK engagement when required or an isolated representative laboratory; production access only with explicit customer authority, safety controls and no inferred CHECK provider status or government acceptance",
    ),
    _adapter(
        "aiuc1-agent-assurance",
        "https://www.aiuc-1.com/",
        "public-standard-criteria-and-organization-evaluation-record-specific",
        "aiuc1-q3-2026-agent-control-evaluation-result-v1",
        [
            "quarterly-edition-requirement-control-and-evidence-digest",
            "agent-capability-model-tool-data-memory-user-and-context-manifest",
            "mandatory-optional-supplemental-and-applicability-record",
            "technical-legal-operational-evaluation-and-monitoring-report",
            "failure-plan-corrective-action-change-and-quarterly-retest-ledger",
        ],
        "no-egress agent evaluation laboratory with inert tools, synthetic secrets and identities, bounded authority, independent review and no suite-issued AIUC-1 certificate claim",
    ),
    _adapter(
        "csa-iot-controls-conformance",
        "https://cloudsecurityalliance.org/artifacts/iot-security-controls-framework",
        "creative-commons-framework-and-organization-system-record-specific",
        "csa-iot-v2-component-control-lifecycle-result-v1",
        [
            "framework-edition-license-control-and-guide-digest",
            "device-gateway-network-cloud-mobile-data-flow-and-owner-map",
            "risk-applicability-control-allocation-and-crosswalk-record",
            "credential-network-cloud-update-supplier-and-data-fault-report",
            "safe-degradation-recovery-residue-and-lifecycle-retest-ledger",
        ],
        "no-egress representative IoT laboratory with simulated cloud and network services, synthetic identities and data, no production actuation, emergency stop and no CSA or product certification claim",
    ),
    _adapter(
        "etsi-ai-cybersecurity-lifecycle-conformance",
        "https://www.etsi.org/deliver/etsi_en/304200_304299/304223/02.01.01_60/en_304223v020101p.pdf",
        "ETSI-document-license-and-organization-requirement-fixture-specific",
        "etsi-en-304223-stakeholder-lifecycle-requirement-result-v1",
        [
            "etsi-edition-license-requirement-and-implementation-guide-digest",
            "ai-model-system-use-role-supplier-asset-and-lifecycle-boundary",
            "principle-requirement-applicability-control-and-evidence-map",
            "poisoning-substitution-privilege-monitoring-update-and-retirement-cases",
            "independent-replay-remediation-recovery-residual-risk-and-retest-ledger",
        ],
        "no-egress representative AI lifecycle laboratory with synthetic models data identities suppliers and services, bounded resources, emergency stop, per-case reset, signed destruction evidence and no ETSI certification or legal-conformity claim",
    ),
    _adapter(
        "agentic-evaluator-containment-assurance",
        "https://www.cyber.gov.au/business-government/secure-design/artificial-intelligence/careful-adoption-of-agentic-ai-services",
        "Five-Eyes-government-guidance-CSA-framework-and-organization-holdout-specific",
        "agentic-evaluator-layer-escape-containment-recovery-result-v1",
        [
            "five-eyes-guidance-maestro-layer-and-threat-model-digests",
            "agent-user-tool-data-memory-session-authority-and-impact-map",
            "harness-policy-scorer-network-storage-secret-and-shutdown-boundary",
            "escape-subversion-persistence-covert-channel-exfiltration-and-evasion-cases",
            "independent-containment-cleanup-restoration-utility-and-retest-ledger",
        ],
        "nested no-egress disposable agent evaluator with an outer enforcement boundary inaccessible to the agent, synthetic identities secrets tools and services, deny-by-default capabilities, out-of-band kill switch, resource budgets, per-case immutable reset, residue scan and signed destruction receipt",
    ),
    _adapter(
        "fiasse-securability-assurance",
        "https://owasp.org/www-project-fiasse/",
        "CC-BY-SA-4.0-framework-and-organization-engineering-evidence-specific",
        "fiasse-securability-principle-merge-review-result-v1",
        [
            "fiasse-1.1.0-release-principle-reference-and-license-digest",
            "architecture-trust-boundary-critical-decision-and-request-surface-map",
            "canonical-parsing-authoritative-state-transparency-and-observability-evidence",
            "merge-change-securability-finding-override-owner-and-expiry-record",
            "mutation-independent-review-remediation-regression-and-reassessment-ledger",
        ],
        "read-only source and architecture assessment workspace with synthetic canonicalization and authority-substitution fixtures, blinded independent review, no production mutation and no claim that SSEM beta scores prove security",
    ),
)


def _contract(
    scalar_name: str,
    scalar_value: str,
    set_name: str,
    set_values: set[str],
    counts: tuple[str, str, str],
    required_true: tuple[str, ...],
    required_false: tuple[str, str],
) -> dict[str, Any]:
    return {
        "scalars": {scalar_name: scalar_value},
        "sets": {set_name: set_values},
        "counts": counts,
        "required_true": required_true,
        "required_false": required_false,
    }


_CIS_TRUE = (
    "edition_license_profile_source_and_recommendation_digests_bound",
    "subject_inventory_responsibility_applicability_and_exception_scope_bound",
    "automated_manual_scored_and_nonscored_result_semantics_preserved",
    "native_and_independent_observations_disagreement_and_drift_reconciled",
    "authorized_remediation_rollback_cleanup_and_rescan_verified",
    "independent_replay_false_pass_and_stale_exception_cases_completed",
)
_CIS_FALSE = (
    "not_assessed_unknown_or_not_applicable_treated_as_pass",
    "cis_certification_or_universal_security_claimed",
)


EMERGING_ASSURANCE_EVIDENCE_CONTRACTS: dict[str, dict[str, Any]] = {
    "cis-aws-foundations-conformance": _contract(
        "benchmark",
        "CIS-AWS-FOUNDATIONS-7.0.0",
        "sections",
        {"identity", "storage", "logging", "monitoring", "networking"},
        ("recommendations_evaluated", "manual_checks_replayed", "drift_cases_detected"),
        _CIS_TRUE,
        _CIS_FALSE,
    ),
    "cis-azure-foundations-conformance": _contract(
        "benchmark",
        "CIS-AZURE-FOUNDATIONS-6.0.0",
        "sections",
        {
            "identity",
            "security-services",
            "storage",
            "database",
            "logging-monitoring",
            "networking",
            "compute",
        },
        ("recommendations_evaluated", "manual_checks_replayed", "drift_cases_detected"),
        _CIS_TRUE,
        _CIS_FALSE,
    ),
    "cis-gcp-foundations-conformance": _contract(
        "benchmark",
        "CIS-GCP-FOUNDATIONS-5.0.0",
        "sections",
        {
            "organization-policy",
            "identity",
            "logging-monitoring",
            "networking",
            "compute-storage-database",
        },
        ("recommendations_evaluated", "manual_checks_replayed", "drift_cases_detected"),
        _CIS_TRUE,
        _CIS_FALSE,
    ),
    "cis-docker-conformance": _contract(
        "benchmark",
        "CIS-DOCKER-1.8.0",
        "sections",
        {
            "host",
            "daemon",
            "daemon-files",
            "images-build",
            "container-runtime",
            "orchestration",
        },
        ("recommendations_evaluated", "manual_checks_replayed", "drift_cases_detected"),
        _CIS_TRUE,
        _CIS_FALSE,
    ),
    "owasp-genai-red-team-assurance": _contract(
        "method",
        "OWASP-GENAI-RED-TEAMING-GUIDE-1.0",
        "assessment_domains",
        {
            "model-evaluation",
            "implementation-testing",
            "infrastructure-assessment",
            "runtime-behavior",
        },
        (
            "campaign_cases_executed",
            "successful_attacks_replayed",
            "remediations_retested",
        ),
        (
            "subject_threat_model_authority_prohibitions_budget_and_stop_conditions_bound",
            "model_application_agent_tool_data_infrastructure_and_context_scope_bound",
            "multi_turn_indirect_retrieval_tool_memory_tenant_and_resource_cases_executed",
            "prompt_state_tool_decision_scorer_and_utility_evidence_preserved",
            "independent_replay_clean_control_restoration_and_disclosure_verified",
            "remediation_attack_family_retest_and_benign_utility_regression_verified",
        ),
        (
            "production_or_third_party_target_attacked_without_explicit_authority",
            "owasp_certification_vulnerability_free_or_complete_attack_coverage_claimed",
        ),
    ),
    "imda-ai-verify-moonshot-assurance": _contract(
        "framework",
        "IMDA-AI-VERIFY-MOONSHOT-2026-08-31",
        "principles",
        {
            "transparency",
            "explainability",
            "reproducibility",
            "safety",
            "security",
            "robustness",
            "fairness",
            "data-governance",
            "accountability",
            "human-agency",
            "inclusive-societal-environmental-wellbeing",
        },
        (
            "process_checks_evaluated",
            "technical_tests_repeated",
            "protected_strata_evaluated",
        ),
        (
            "framework_toolkit_recipe_connector_dataset_and_license_digests_bound",
            "subject_use_context_population_claim_threshold_and_owner_scope_bound",
            "process_and_technical_result_semantics_limitations_and_uncertainty_preserved",
            "seed_sampling_metric_scorer_contamination_and_nondeterminism_reproduced",
            "protected_strata_clean_control_and_scorer_manipulation_cases_replayed",
            "independent_replay_remediation_retest_and_crosswalk_loss_verified",
        ),
        (
            "unsupported_or_untested_principle_treated_as_satisfied",
            "imda_ai_verify_legal_conformity_or_ai_safety_certification_claimed",
        ),
    ),
    "ncsc-check-engagement-assurance": _contract(
        "scheme",
        "NCSC-CHECK-SCHEME-STANDARD-1.1",
        "engagement_phases",
        {
            "provider-qualification",
            "scoping",
            "testing",
            "reporting",
            "cleanup",
            "remediation-retest",
        },
        ("systems_tested", "findings_reperformed", "remediations_retested"),
        (
            "scheme_provider_team_registry_credential_validity_and_revocation_bound",
            "customer_system_threat_technology_test_type_exclusion_and_authority_scope_bound",
            "method_observation_exploit_severity_evidence_custody_and_disclosure_preserved",
            "safety_stop_collateral_finding_data_handling_cleanup_and_restoration_verified",
            "customer_decision_remediation_retest_and_residual_risk_trace_verified",
            "independent_reperformance_false_positive_and_out_of_scope_cases_completed",
        ),
        (
            "active_test_exceeded_customer_authority_or_safety_boundary",
            "suite_readiness_represented_as_ncsc_provider_status_or_government_acceptance",
        ),
    ),
    "aiuc1-agent-assurance": _contract(
        "standard",
        "AIUC1-Q3-2026-2026-07-15",
        "domains",
        {
            "data-privacy",
            "security",
            "safety",
            "reliability",
            "accountability",
            "society",
        },
        (
            "controls_evaluated",
            "technical_evaluations_repeated",
            "material_changes_retested",
        ),
        (
            "quarterly_edition_requirement_control_evidence_and_crosswalk_digests_bound",
            "agent_capability_model_tool_data_memory_user_deployment_and_context_scope_bound",
            "mandatory_optional_supplemental_applicability_and_evidence_semantics_preserved",
            "adversarial_harmful_hallucination_tool_privilege_and_coding_agent_cases_replayed",
            "monitoring_failure_plan_corrective_action_and_quarterly_retest_verified",
            "independent_evaluation_change_trigger_and_recurring_validity_review_verified",
        ),
        (
            "not_applicable_or_failed_control_treated_as_pass",
            "suite_or_unapproved_assessor_issued_aiuc1_certificate_claimed",
        ),
    ),
    "csa-iot-controls-conformance": _contract(
        "framework",
        "CSA-IOT-SECURITY-CONTROLS-FRAMEWORK-2.0",
        "components",
        {
            "devices",
            "gateways",
            "networks",
            "cloud-services",
            "mobile-applications",
            "operators",
        },
        ("controls_allocated", "adverse_cases_executed", "recovery_cases_replayed"),
        (
            "framework_guide_license_control_and_crosswalk_digests_bound",
            "component_identity_data_flow_trust_safety_owner_and_risk_scope_bound",
            "applicability_allocation_shared_responsibility_and_semantic_loss_preserved",
            "credential_network_cloud_update_rollback_supplier_and_data_cases_executed",
            "safe_degradation_known_good_recovery_residue_and_decommissioning_verified",
            "independent_replay_exception_expiry_lifecycle_change_and_retest_verified",
        ),
        (
            "production_device_or_physical_process_actuated_without_explicit_authority",
            "crosswalk_or_suite_result_represented_as_csa_or_product_certification",
        ),
    ),
    "etsi-ai-cybersecurity-lifecycle-conformance": _contract(
        "standard",
        "ETSI-EN-304-223-V2.1.1",
        "lifecycle_stages",
        {"design", "development", "deployment", "maintenance", "end-of-life"},
        (
            "requirements_evaluated",
            "adverse_lifecycle_cases_executed",
            "remediations_retested",
        ),
        (
            "edition_license_requirement_implementation_guide_and_source_digests_bound",
            "subject_use_stakeholder_supplier_asset_threat_and_lifecycle_scope_bound",
            "principle_requirement_applicability_control_evidence_and_exception_semantics_preserved",
            "poisoning_substitution_privilege_monitoring_update_recovery_and_retirement_cases_replayed",
            "independent_replay_disagreement_residual_risk_remediation_and_retest_verified",
            "cleanup_restoration_change_trigger_and_end_of_life_residue_verified",
        ),
        (
            "untested_or_not_applicable_requirement_treated_as_satisfied",
            "suite_result_represented_as_etsi_certification_or_legal_conformity",
        ),
    ),
    "agentic-evaluator-containment-assurance": _contract(
        "guidance",
        "FIVE-EYES-AGENTIC-AI-2026-04-30",
        "attack_classes",
        {
            "harness-escape",
            "policy-subversion",
            "scorer-manipulation",
            "privilege-escalation",
            "cross-agent-boundary",
            "persistence",
            "covert-exfiltration",
            "shutdown-evasion",
            "cleanup-corruption",
        },
        (
            "adversarial_cases_executed",
            "containment_events_independently_replayed",
            "restoration_cases_verified",
        ),
        (
            "guidance_maestro_layer_threat_model_corpus_and_source_digests_bound",
            "agent_user_tool_data_memory_session_authority_impact_and_prohibition_scope_bound",
            "outer_harness_policy_scorer_network_storage_secret_shutdown_and_cleanup_boundary_bound",
            "escape_subversion_escalation_persistence_covert_exfiltration_evasion_and_corruption_cases_executed",
            "out_of_band_containment_immutable_reset_residue_scan_and_destruction_verified",
            "independent_replay_false_containment_benign_utility_restoration_and_retest_verified",
        ),
        (
            "agent_reached_production_or_third_party_system_without_explicit_authority",
            "containment_result_represented_as_proof_of_agent_safety_or_complete_attack_coverage",
        ),
    ),
    "fiasse-securability-assurance": _contract(
        "framework",
        "OWASP-FIASSE-1.1.0",
        "principles",
        {
            "securability",
            "isolated-integrity",
            "canonical-parsing",
            "transparency",
            "boundary-control",
            "intentional-request-surface",
            "least-astonishment",
            "actionable-security-intelligence",
        },
        (
            "critical_decisions_evaluated",
            "merge_reviews_replayed",
            "mutations_detected",
        ),
        (
            "release_principle_reference_license_and_source_digests_bound",
            "architecture_boundary_critical_decision_request_surface_and_change_scope_bound",
            "canonicalization_authoritative_state_transparency_observability_and_exception_evidence_preserved",
            "ambiguous_input_authority_substitution_surface_expansion_and_observability_loss_cases_replayed",
            "merge_report_override_owner_expiry_remediation_and_regression_trace_verified",
            "independent_review_disagreement_reassessment_and_non_normative_score_boundary_verified",
        ),
        (
            "raw_tool_output_or_unreviewed_score_treated_as_actionable_assurance",
            "ssem_beta_or_suite_result_represented_as_security_certification",
        ),
    ),
}


EMERGING_ASSURANCE_WATCHLIST: tuple[dict[str, str], ...] = (
    {
        "id": "NCSC-CYAS-MVP",
        "status": "scheme-in-development-mvp",
        "stage": "minimum-viable-product-policy-observed",
        "reference": "https://www.ncsc.gov.uk/schemes/cyber-adversary-simulation-cyas/introduction",
        "reason": "Retain as non-normative until NCSC publishes a stable scheme standard and provider lifecycle; do not infer CyAS assurance from CHECK, CBEST, TIBER-EU or internal red-team evidence.",
    },
    {
        "id": "COSAI-MCP-SECURITY-GUIDANCE",
        "status": "guidance-crosswalk-candidate",
        "stage": "published-guidance-semantic-delta-review",
        "reference": "https://www.coalitionforsecureai.org/wp-content/uploads/2026/03/model-context-protocol-security-1.pdf",
        "reason": "Monitor as a source crosswalk to the maintained MCP security benchmark; promote only when distinct testable requirements, version governance and semantic-delta evidence justify a separate normative profile.",
    },
    {
        "id": "EU-CRA-M606-HARMONISED-STANDARDS",
        "status": "under-development",
        "stage": "41-standard-program-publication-and-ojeu-monitoring",
        "reference": "https://digital-strategy.ec.europa.eu/en/policies/cra-standardisation",
        "reason": "Track all 41 requested horizontal and vertical standards, but do not claim presumption of conformity until the applicable final harmonised standard is cited in the Official Journal of the European Union and promoted through signed semantic-delta review.",
    },
    {
        "id": "ETSI-CRA-17-VERTICAL-DRAFT-STANDARDS",
        "status": "public-enquiry",
        "stage": "final-drafts-not-harmonised",
        "reference": "https://www.etsi.org/newsroom/press-releases/etsi-launches-approval-process-for-17-european-standards-supporting-the-cyber-resilience-act/",
        "reason": "The 17 ETSI EN 304 xxx verticals are public-enquiry drafts; retain only compatibility fixtures and lifecycle observations until approval, publication, OJEU citation and governed source pinning are complete.",
    },
    {
        "id": "OWASP-AIVSS",
        "status": "pre-stable",
        "stage": "v0.8-experimental-scoring",
        "reference": "https://aivss.owasp.org/aiuc-aivss-crosswalk",
        "reason": "Evaluate AI-specific scoring experimentally, preserve CVSS and SSVC as the normative prioritization baseline, and prohibit automatic risk acceptance or release gates until AIVSS reaches a stable release and is empirically calibrated against outcomes.",
    },
)
