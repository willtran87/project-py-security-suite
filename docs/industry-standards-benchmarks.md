# Industry standards and benchmarks

Last reviewed: 2026-08-31

The suite keeps five assurance layers separate so that a catalog reference is
never mistaken for test execution or certification:

1. a versioned standards registry and evidence-surface crosswalk;
2. repository-owned control objectives with explicit evidence requirements;
3. policy-pinned assessment procedures with execution and authorization proof;
4. source-retained CVSS v4 and SSVC prioritization; and
5. measured, corpus-bound benchmark scorecards and regression deltas.

Every artifact states its claim boundary. The outputs support engineering and
assurance workflows; they do not grant certification, authorization to test, or
proof that an application is vulnerability-free.

## Coverage

`standards-crosswalk.json` registers 663 version-explicit references:

- verification and test methods: OWASP ASVS 5.0, MASVS 2.1, TCASVS 5.0.1, WSTG
  4.2, MASTG 2.0, SCVS 1.0, and AITG 1.0;
- lifecycle, controls, assessment, and governance: NIST SSDF 1.1, CSF 2.0,
  SP 800-53 release 5.2, SP 800-53A release 5.2, SP 800-115, SP 800-161r1,
  OWASP SAMM 2.1, OpenSSF OSPS Baseline 2026.08.28, CIS Controls 8.1, CIS Benchmarks,
  NIST SCAP 1.4, and CSA CCM 4.1;
- configuration, adversarial and AI assurance: CIS AWS Foundations 7.0.0,
  Azure Foundations 6.0.0, GCP Foundations 5.0.0 and Docker 1.8.0; OWASP
  GenAI Red Teaming Guide 1.0; policy-pinned AI Verify and Project Moonshot;
  NCSC CHECK 1.1; conditional AIUC-1 Q3 2026; and CSA IoT Security Controls
  Framework 2.0;
- weaknesses, attacks, defenses, and prioritization: CWE Top 25, OWASP Top 10,
  OWASP API Top 10, CAPEC, MITRE ATT&CK, MITRE ATLAS, MITRE D3FEND, FIRST
  CVSS 4.0, and CISA SSVC;
- AI risk and management: OWASP LLM Top 10, NIST AI RMF, NIST AI 600-1,
  ISO/IEC 42001, ISO/IEC 23894, and the emerging OWASP APTS reference; and
- quality and architecture: ISO/IEC 25010, ISO/IEC 5055, ISO/IEC 25023,
  ISO/IEC/IEEE 42010, and CISQ quality measures;
- enterprise, privacy, and product response: ISO/IEC 27001, 27002, 27034-1,
  27701, 29147, and 30111; NIST Privacy Framework 1.0 and SP 800-61r3; and
- supply-chain and conditional regulatory profiles: NIST SP 800-204D and
  SP 800-218A, SLSA 1.2, ISO/IEC 18974 and 5230, SPDX 3.0/ISO 5962, EU CRA,
  PCI DSS 4.0.1, PCI Secure Software 2.x, NIST SP 800-171r3, and SOC 2 TSC;
- open-source production and delivery assurance: OpenSSF OSS-CRS and
  CRSBench, Security Insights 1.0.0, GUAC 1.0, policy-pinned gittuf and Package
  Analysis, OWASP Kubernetes Top 10 2025, OWASP CI/CD Top 10 v1, and SBOMit
  build-observed dependency attestations. Pre-final project surfaces remain
  policy-pinned and cannot be presented as normative certification criteria;
- control-knowledge and sector assurance: policy-pinned OWASP OpenCRE and
  OpenSSF Gemara joined to OSCAL 1.2.2 for provenance-preserving control and
  evidence interchange; the Bank of England CBEST Implementation Guide 2024
  for conditional UK financial threat-led testing; and OCP S.A.F.E. plus
  OCP SOLID 1.0 for independent hardware, firmware, source, physical-interface,
  supply-chain and recovery appraisal;
- capability, cloud, product, privacy, and service assurance: DOE C2M2 2.1;
  FINOS Common Cloud Controls Core v2025.10; NCSC CRT Assurance Principles and
  Claims 1.0 and CRTF Scheme Standard 1.1; the UK Software Security Code of
  Practice 1.0; NIST PRAM with final NISTIR 8062; and a policy-pinned,
  organization-licensed ITIL 4 criteria snapshot. Each remains subject to its
  publisher, license, applicability, assessment-authority, and certification
  boundaries;
- specialized application and cloud-native assurance: OWASP Mobile Top 10
  2024, OWASP Smart Contract Top 10 2026, and the policy-pinned CNCF Cloud
  Native Security Controls Catalog with its NIST SP 800-53 Rev. 5 mapping;
- embedded, stateful-application, and software-factory assurance: MITRE EMB3D
  2.0.2, OWASP Business Logic Abuse Top 10 2025 second release, and CNCF
  Software Supply Chain Best Practices v2 with SSDF, SLSA, and S2C2F mappings;
- identity, protocols, cloud, and zero trust: NIST SP 800-63-4, RFC 9700,
  WebAuthn, OpenID FAPI, ISO/IEC 27017/27018, NIST SP 800-190, and NIST
  SP 800-207/207A;
- identity lifecycle and continuous access: SCIM RFC 7643/7644 plus cursor
  pagination RFC 9865 and SCIM security events RFC 9967; OpenID SSF, CAEP, and
  RISC 1.0 Final; and a policy-pinned stable SPIFFE specification snapshot;
- authorization and federation interoperability: final OpenID AuthZEN
  Authorization API 1.0, OpenID Federation 1.1, and OpenID Federation for
  OpenID Connect 1.1, with PDP/PEP decision boundaries, entity statements,
  trust-chain and metadata-policy resolution, key lifecycle, downgrade and
  certification-claim controls;
- identity-management architecture and practice: ISO/IEC 24760 Parts 1, 2,
  and 3:2025 across identity concepts, identifiers and attributes, people,
  organizations, devices and software, reference architecture, privacy,
  federation, assurance and complete identity lifecycle closure;
- AI/ML artifact supply chain: OpenSSF Model Signing 1.0 and CycloneDX 1.7
  ML-BOM/model-card structures, with integrity and inventory claims explicitly
  separated from model safety, fairness, quality, and fitness;
- cryptography and resilience: FIPS 140-3, FIPS 203/204/205, NIST
  SP 800-131A, RFC 9325, ISO 22301, and NIST SP 800-34;
- recovery, sanitization, crisis, and enterprise-risk depth: NIST IR 8374 Rev. 1,
  SP 1800-11/25/26, SP 800-88 Rev. 2, IEEE 2883/2883.1, SP 1339,
  SP 1800-45, IEC TS 62443-6-1, ISO 22361/22398, NIST SP 800-221/221A,
  and SP 1347 mapping governance;
- specialized LNG and EV/XFC resilience: NIST IR 8406 Update 1 and IR 8473,
  retained as CSF 1.1 source profiles with explicit, reviewed CSF 2.0 mapping
  rather than silently relabeled as native CSF 2.0 publications;
- EU digital obligations: GDPR, NIS2, DORA, and the EU AI Act; and
- conditional product and sector assurance: NISTIR 8259/8259A/8259B, ETSI
  EN 303 645, IEC 62443-4-1/4-2, ISO/SAE 21434, UNECE R155/R156, IEC 62304,
  IEC 81001-5-1, FDA medical-device guidance, FedRAMP, CMMC, and NIST
  SP 800-171A;
- water, emergency communications, international GxP, transit, incident and
  gas-SCADA depth: AWWA J100-21, G430-24 and G440-22; EPA water cybersecurity
  assessment guidance; NENA NG-SEC 040.2-2024, REF-012.1-2025 and i3; TIA-102
  P25 and DHS P25 CAP; EU GMP Annex 11, WHO TRS 1033 Annex 4 and PIC/S PI
  041-1; final NIST IR 8576; ISO 22320:2018; and supplemental AGA Report 12
  Part 1 criteria;
- medical-device depth: ANSI/AAMI SW96:2023, IEC 80001-1:2021, IEC TR
  60601-4-5:2021, and final IMDRF N60/N70/N73 lifecycle, legacy-device and
  SBOM guidance with patient-safety and regulatory-claim boundaries;
- physical AI and autonomous products: ISO 21448:2022, ISO/PAS 8800:2024,
  ISO 34502:2022, and UL 4600 Edition 3 safety cases, operational design
  domains, deterministic scenarios, degradation and safe fallback;
- critical code and attested computing: licensed MISRA C:2023 and MISRA
  C++:2023 criteria plus TCG attestation, AMD SEV-SNP, Intel TDX and Arm CCA
  policy-pinned evidence joined to final RATS/EAT roles and semantics;
- voting and critical sectors: EAC VVSG 2.0 with Test Assertions 1.4, IEC
  62645:2019 and TR 63486:2024 nuclear assurance, CLC/TS 50701 railway
  cybersecurity, and NASA-STD-8739.8B space software assurance and IV&V;
- machine-readable security exchange and assessment: OASIS SARIF, CSAF,
  STIX, and TAXII; ISO/IEC 20153; ECMA-424; NIST OSCAL; and OpenVEX;
- certification, secure coding, and verification: Common Criteria ISO/IEC
  15408 and 18045, Sigma, SEI CERT C/C++/Java, MISRA C, ISO/IEC TS 17961,
  ISO/IEC TR 24772, exact ISO/IEC/IEEE 29119 Parts 1:2022, 2:2021,
  3:2021, 4:2021, and 5:2024, and ISO/IEC 20246;
- systems, safety, and sector engineering: NIST SP 800-160 volumes 1 and 2,
  SP 800-37, SP 800-55 volumes 1 and 2, ISO/IEC 27005, IEC 61508, ISO 26262,
  ISO 14971, RTCA DO-326A/DO-356A, NISTIR 8425, and ETSI TS 103 701;
- AI, privacy, and zero-trust engineering: NIST AI 100-2, ISO/IEC 42005 and
  24029, ISO 31700, ISO/IEC 29100, NIST SP 800-82 and SP 1800-35, and the CISA
  Zero Trust Maturity Model; and
- update-system assurance: The Update Framework (TUF) and Uptane 2.1.0 for
  Director/Image repositories, ECU verification, rollback protection, secure
  time, key compromise, and recovery;
- system planning, Internet, network, logging, and storage security: NIST
  SP 800-18r2 and SP 800-92 plus ISO/IEC 27014, 27032, the 27033 series, and
  ISO/IEC 27040:2024;
- privacy data lifecycle: NIST SP 800-188 and ISO/IEC 27555/27559 for governed
  deletion, de-identification, re-identification risk, and measurable review;
- harmonized accessibility testing: W3C ACT Rules Format 1.1 alongside WCAG
  2.2, with ACT rules retained as informative test procedures rather than
  substituted for WCAG conformance;
- evaluator and conformity-assessment integrity: ISO/IEC 17025, 17020, and
  17065 for competence, impartiality, consistent operation, and bounded
  certification decisions;
- complete industrial and energy operations: IEC 62443-2-1, 2-4, 3-2, and
  3-3, NERC CIP, and NISTIR 7628 in addition to product-development and
  component requirements;
- healthcare and airborne software: the HIPAA Security Rule, NIST SP 800-66,
  policy-pinned HITRUST evidence, and RTCA DO-178C/330/331/332/333 alongside
  DO-326A/356A;
- evaluation, incident, and privacy-impact processes: ISO/IEC 25040/25041,
  ISO/IEC 27035 parts 1-3, ISO/IEC/IEEE 23612, and ISO/IEC 29134;
- federal hardening: policy-pinned DISA STIG and SRG releases; and
- supply-chain identity and threat modeling: in-toto Attestation Framework,
  DSSE, CPE 2.3, SWID, package URL, OSV and CVE interchange schemas, and the
  maintained OWASP Threat Modeling guidance;
- software and systems lifecycle, requirements, architecture, and process:
  ISO/IEC/IEEE 12207, 15288, 29148, 42020, and 42030 plus ISO/IEC 33020 and
  ISO/IEC TS 33061;
- comprehensive weakness and exploit intelligence: the complete MITRE CWE
  catalog, FIRST EPSS, and the CISA Known Exploited Vulnerabilities catalog;
- supplier, signing, and attestation assurance: ISO/IEC 27036 parts 1-4,
  Sigstore, SLSA verifier conformance, and IETF RATS/EAT RFC 9334/9711;
- AI lifecycle, data, and empirical evaluation: ISO/IEC 5338, ISO/IEC 5259
  parts 1-5 plus TR 5259-6:2026 data-quality visualization guidance, NIST AI
  700-2 ARIA, and UK AISI Inspect; and
- HPC and AI infrastructure security: NIST SP 800-223 reference architecture,
  threats and posture plus the final SP 800-234 sixty-control HPC overlay;
- sector operations: IEC 62443-2-3 patch management, RTCA DO-355A joined to
  SAE ARP5150B/ARP5151B in-service safety assessment, IACS UR E26/E27 maritime
  resilience, and SWIFT CSCF 2026 annual independent assessment; and
- space-mission communications security: CCSDS 350.1-G-3/350.7-G-2 threat and
  planning guidance, 351.0-M-1 security architecture, 352.0-B-2 algorithms,
  355.0-B-2/355.1-B-1 link security and extended procedures, 356.0-B-1 network
  adaptation, and 357.0-B-1 authentication credentials;
- organizational maturity: OWASP DSOVS, OWASP DSOMM 5.0.2, TMMi 2.0, and
  policy-pinned licensed BSIMM and CMMI Development evidence;
- AI quality and conformity: ISO/IEC 42006:2025, ISO/IEC 25059:2023,
  ISO/IEC TR 24027:2021, ISO/IEC TR 24028:2020, and CSA AICM 1.1;
- independent cloud and automation assurance: CSA STAR, OASIS CACAO 2.0,
  OpenC2 1.0, and OCSF; and
- vulnerability disclosure, product regulation, and detection evaluation:
  NIST SP 800-216, UK PSTI, ETSI EN 18031, and MITRE ATT&CK Evaluations.
- cloud-native API, service-mesh, and data protection: NIST SP 800-228 Update 1,
  SP 800-204/204B/204C, SP 800-233, and NISTIR 8505;
- transparent and consumer-side software supply chains: IETF SCITT RFC
  9942/9943, OpenSSF S2C2F, and the NTIA SBOM Minimum Elements;
- agentic and AI testing: OWASP Agentic Top 10 2026, ISO/IEC TR 29119-11,
  and ISO/IEC TS 42119-2;
- API and runtime semantics: OpenAPI 3.1.1, AsyncAPI 3.0.0, the September
  2025 GraphQL specification, JSON Schema 2020-12, and policy-pinned
  OpenTelemetry semantic conventions 1.44.0;
- vulnerability operations and regional resilience: RFC 9116, NIST SP
  800-40r4, NCSC CAF 4.0, Cyber Essentials 3.3, ASD Essential Eight, and
  CISA Cross-Sector CPGs; and
- architecture, privacy, and sector conformance: SEI ATAM, ISO/IEC TS 27560,
  ISO 24089, IEC 62351, and UL 2900;
- current SBOM, enhanced CUI, and developer verification: CISA-led 2026 SBOM
  Minimum Elements, NIST SP 800-172r3/172Ar3, SP 800-53B release 5.2.0,
  and NISTIR 8397;
- cryptographic lifecycle and agility: NIST SP 800-57 parts 1-3, SP 800-227,
  and CSWP 39 Update 1;
- continuous monitoring and ICT continuity: NIST SP 800-137/137A, NISTIR
  8212, ISO/IEC 27004:2016, and ISO/IEC 27031:2025;
- digital forensics: ISO/IEC 27037, 27041, 27042, and 27043 plus NIST
  SP 800-86; and
- inclusive quality: WCAG 2.2, EN 301 549 V3.2.1, and revised Section 508.
- lightweight cryptography and weakness analysis: NIST SP 800-232 Ascon and
  NIST SP 800-231 Bugs Framework;
- IoT security and privacy lifecycle: ISO/IEC 27400:2022, 27402:2023,
  27403:2024, and 27404:2025; and
- threat-led testing and e-discovery: TIBER-EU 2025 plus ISO/IEC 27050-1:2019
  through 27050-4, applied only when the organization selects those domains;
- audit, assessment, and certification integrity: ISO 19011:2026, ISO/IEC
  27007:2020, ISO/IEC TS 27008:2019, ISO/IEC 27006-1:2024, ISO/IEC
  17021-1, and ISO/IEC 17029;
- evaluator competence: ISO/IEC 19896 parts 1-3 for general security
  conformance, cryptographic-module, and Common Criteria evaluator roles;
- application-security governance: the published ISO/IEC 27034 Parts 1, 2,
  3, 5, 5-1, 6, and 7, with deleted Part 4 excluded and future revisions
  retained on the non-normative watchlist;
- firmware, authorization policy, and service-mesh assurance: NIST SP
  800-193, SP 800-192, SP 800-204A, and TCG TPM 2.0 Library v185;
- differential privacy and measurable quality: NIST SP 800-226 plus ISO/IEC
  25012, 25019, 25020, 25024, and 25030 and ISO/IEC TS 25052 Parts 1 and 2
  for quality-in-use and cloud-service quality measurement;
- enterprise risk and product properties: ISO 31000:2018, IEC 31010:2019,
  CISA Secure by Design, and the 2025 Product Security Bad Practices guidance;
- protocol and reproducibility conformance: TLS 1.3 RFC 8446, its operational
  profile RFC 8996, and the Reproducible Builds environment-variation test
  protocol;
- device identity, telecom, and workforce assurance: TCG DICE Attestation
  Architecture 1.2, ISO/IEC 27011:2024, NIST SP 800-181r1, and NICE Framework
  Components 2.2.0;
- independent security-test governance: AMTSO Testing Protocol Standard 1.3,
  the CREST penetration-testing guide, and PTES; and
- operational outcomes and sector controls: the DORA five software-delivery
  metrics, ISO 27799:2025 for health information, and ISO/IEC 27019:2024 for
  energy utilities; and
- structured assurance, integrity-scaled V&V, cryptographic modules,
  biometrics, service management, and proficiency testing: ISO/IEC/IEEE
  15026-2:2022 and 15026-4:2021, OMG SACM 2.3, IEEE 1012-2024, current CMVP
  scheme evidence, ISO/IEC 19790:2025 and 24759:2025, ISO/IEC 17825:2024 and
  20085 Parts 1 and 2, ISO/IEC 19795-1:2021 and 30107 Parts 3 and 4,
  ISO/IEC 20000-1 with Amendment 1:2024, ISO/IEC 27013 with Amendment 1:2024,
  and ISO/IEC 17043:2023.
- lifecycle, quality, and enterprise risk completion: ISO/IEC/IEEE 24748-1:2024,
  15289:2019, 16085:2021, and 90003:2018; ISO/IEC 25002:2024, 25021:2012,
  25022:2016, and 25051:2014; and NIST SP 800-30r1 and SP 800-39;
- current privacy, data, and AI governance: ISO/IEC 29100:2024, 29151:2026,
  27557:2022, TR 27550:2019, 38505-1:2026, 22989:2022, 23053:2022, and
  38507:2022; and
- protective architecture and practical review guidance: ISO 22340:2024,
  OWASP Code Review Guide 2.0, the policy-pinned 2026 OWASP Cornucopia
  Companion Edition, and CIS/SAFECode Secure by Design 1.1;
- enterprise cyber-risk integration: the complete NIST IR 8286 Revision 1
  series for risk identification, estimation, prioritization, response,
  governance roll-up, and business-impact analysis, plus CIS RAM 2.2;
- SQuaRE governance and differentiated AI benchmarking: ISO/IEC 25001:2014,
  confirmed in 2026, and ISO/IEC TR 42106:2026;
- AI data, transparency, explanation, control, bias, and safety: ISO/IEC
  8183:2023, 12792:2025, TS 6254:2025, TS 8200:2024, TS 12791:2024, and
  TR 5469:2024; and
- licensed enterprise governance and architecture: COBIT 2019, TOGAF 10th
  Edition with Technical Corrigendum 1, ArchiMate 3.2, and Open FAIR 2.0,
  represented only through identifiers and organization-supplied licensed
  requirement digests;
- AI application verification, quality, use cases, and ethical engineering:
  OWASP AISVS 1.0, ISO/IEC TS 25058:2024, ISO/IEC TR 24030:2024 and
  27563:2023, and IEEE 7000/7001/7002/7003/7009;
- current AI and agentic cybersecurity engineering: ETSI EN 304 223 V2.1.1,
  OWASP LLM Top 10 2026, Five Eyes Careful Adoption of Agentic AI Services,
  NSA MCP Security Design Considerations, policy-pinned CSA MAESTRO, and OWASP
  FIASSE 1.1.0, with guidance and certification boundaries kept distinct;
- product certification and federal procurement assurance: the EUCC scheme
  with its 2025 amendment and the policy-pinned CISA Secure Software
  Development Attestation common form;
- organizational IT, quality, and CSF profile governance: ISO/IEC 38500:2024,
  ISO 9001:2026, ISO/IEC 27000:2026, and NIST SP 1301; and
- privacy operationalisation and PET engineering: ISO/IEC 27561:2024,
  ISO/IEC TS 27564:2025, and ISO/IEC 27565:2026 zero-knowledge-proof guidance;
- agent-tool protocol security: the stable MCP 2025-11-25 protocol revision
  plus a date-pinned OWASP MCP Security Cheat Sheet, with authorization,
  capability, tool, resource, prompt, task, sampling, and proxy boundaries;
- provider-native cloud posture: AWS Foundational Security Best Practices 1.0,
  Microsoft Cloud Security Benchmark v1, and the reviewed Google Cloud
  Enterprise Foundations Blueprint, supplementing CSA, CIS, and ISO controls;
- operational response maturity and memory safety: FIRST CSIRT Services
  Framework 2.1, PSIRT Services Framework 1.1 and PSIRT Maturity, plus the
  CISA memory-safe roadmap and buffer-overflow guidance;
- organizational AI impact and resilience: IEEE 2863-2026, IEEE 7010-2020,
  ISO 22316:2017, and ISO/TS 22317:2021; and
- project and ISMS implementation practices: OpenSSF Best Practices Badge
  criteria, ISO/IEC 27003:2017, and ISO/IEC TS 27022:2021.
- interoperable agent-to-agent security: A2A Protocol 1.0.0 identity,
  Agent Card, transport, task, message, artifact, streaming, webhook, and
  delegated-authorization boundaries, kept separate from MCP tool-protocol
  assurance;
- IoT platform evaluation and composition: GlobalPlatform SESIP 1.2 and
  EN 17927:2023 security-functional, assurance, evaluation, certification,
  composition, vulnerability, change, and expiry evidence;
- controlled threat-information exchange and incident analysis: FIRST TLP 2.0,
  FIRST IEP 2.0, and policy-pinned VERIS 1.3.6 label, redistribution,
  deidentification, schema, provenance, and analytic-equivalence controls;
- stable web runtime defenses: W3C CSP Level 2 and Subresource Integrity 1.0
  policy enforcement, integrity, redirect, CORS, substitution, multi-policy,
  reporting, fallback, and cross-browser evidence;
- regulated financial and cloud assurance: the DORA Level 2 technical acts for
  ICT risk, incident classification/reporting, provider registers, and TLPT;
  the current FFIEC Development, Acquisition, and Maintenance, Architecture,
  Infrastructure, and Operations, and Information Security booklets; and BSI
  C5:2020 cloud-control attestation; and
- consumer-IoT labeling: FCC 24-26 Cyber Trust Mark product, laboratory,
  applicant, QR, registry, renewal, withdrawal, and anti-forgery boundaries.
- digital credentials and financial-grade identity: W3C Verifiable Credentials
  Data Model 2.0, Data Integrity 1.0, Bitstring Status List 1.0, final OpenID4VP,
  OpenID4VCI, HAIP, and FAPI 2.0 profile, attacker model, and message signing.
  The OpenID4VP/OpenID4VCI/HAIP suites are recorded as complete and open for
  self-certification as of 2026-08-07, while certification remains an external
  OpenID Foundation decision;
- operational cloud and Kubernetes hardening: CISA SCuBA Microsoft 365 and
  Google Workspace baselines plus CIS Kubernetes Benchmark 2.0.1;
- privacy, runtime, and analysis-method assurance: LINDDUN PRO privacy threat
  modeling and independently scored SAST, DAST, IAST, and RASP evidence;
- conditional industry schemes: GSMA NESAS 3.0 with product-applicable 3GPP
  SCAS, VDA ISA 6.0.3/TISAX, PCI MPoC/P2PE, and C2PA 2.4 content credentials;
- platform firmware and hardware integrity: NIST SP 800-147/147B client and
  server update protection, SP 800-193 resiliency, SP 1800-34 acquired-device
  provenance and integrity, CSWP 45 threat/sensitivity metrics, CSWP 52
  bus-based monitoring, and TPM measured boot;
- native Kubernetes workload enforcement: version-pinned Kubernetes 1.36 Pod
  Security Standards and Admission across privileged, baseline, restricted,
  enforce, audit and warn behavior in addition to CIS Kubernetes 2.0.1;
- payment device, key and authentication assurance: PCI PIN Security, PTS POI
  7.0, 3DS Core and EMV 3DS 2.3.1.1 joined to existing MPoC and P2PE coverage;
- regional financial resilience: APRA CPS 230/CPS 234 and policy-pinned MAS
  Technology Risk Management for critical operations, technology risk,
  material providers, incidents, recovery and regulatory-claim boundaries;
- space-software product assurance: ECSS-E-ST-40C and ECSS-Q-ST-80C Rev.2
  engineering, criticality, lifecycle, reuse, anomaly, independent product
  assurance, delivery and acceptance evidence; and
- cross-organization sharing and competence: ISO/IEC 27010, ISO/IEC TR 27016
  and ISO/IEC 27021 for information-sharing communities, economic decisions,
  role competence, calibration and reassessment;
- semiconductor fabrication: SEMI E187/E188/E191 equipment hardening,
  malware-free delivery and service, device-status reporting and recovery;
- pipeline operations: API Standard 1164 third-edition IAC architecture,
  essential-function protection, manual operation, incident response and
  state-reconciled recovery;
- regulated life sciences and criminal justice: FDA 21 CFR Part 11 and
  licensed GAMP 5 computerized-system/data-integrity assurance plus FBI CJIS
  Security Policy 6.1 CJI boundary, identity, encryption, audit, cloud, mobile
  and incident controls;
- automotive and process assurance: Automotive SPICE PAM 4.0 and its
  cybersecurity PAM plus IEC 61511 SIS lifecycle and IEC TR 63069
  safety-security interaction;
- cyber-physical facilities: BACnet Secure Connect, ISO 10218 industrial
  robots, ANSI/RIA R15.08 mobile robots, ISO/IEC 22237 data-centre facilities
  and resilience KPIs, and ANSI/TIA-942-C physical infrastructure.

`mapping_status=evidence-surface-present` means only that a related artifact
exists. Taxonomy versions marked `policy-pinned` must be selected and approved
by the organization rather than silently floating to a network release.
The crosswalk also carries a non-normative publication watchlist. Draft NIST
SSDF 1.2, NIST SP 800-154, and ISO/IEC 25000-22 remain quarantined while the
final NIST SSDF 1.1 and ISO/IEC 25022:2016 baselines remain normative. ISO/IEC 27090,
NIST Privacy Framework 1.1, ISO/IEC 42119 parts 3, 7, and 8, the next ISO/IEC
27004 and ISO 31000 editions, EN 301 549 V4, TCG DICE 1.3, and draft
ISO/IEC/IEEE 29119-14, the next ISO/IEC/IEEE 15026-4 edition, and IEEE P1012
remain outside normative claims until final publication, version pinning, and
legal review. ISO/IEC 42105 human oversight and ISO/IEC 24970 AI logging also
remain watch items at final-draft status. OWASP ISVS stays on the watchlist while its
public page exposes conflicting release-candidate and final-release labels;
the suite does not infer a stable edition from that ambiguity.
ISO/IEC 42007 and NIST IR 8596 remain draft AI conformity and Cyber AI Profile
inputs, and the next ISO/IEC TR 24030 edition remains a new project. MLCommons
AILuminate Agentic and Multimodal remain non-normative watch items until each
has an immutable released corpus, evaluator, scoring method, and split contract.
The EU CRA M/606 program and its 17 ETSI vertical public-enquiry drafts are
tracked without presumption-of-conformity claims until applicable standards are
final, published, cited in the OJEU, source-pinned, and promoted by signed
semantic review. OWASP AIVSS 0.8 remains experimental and cannot replace CVSS
or SSVC, drive automatic risk acceptance, or become a release gate.
The MCP 2026 release candidate, MCSB v2 preview, W3C VC Data Model 2.1,
OpenID4VP 1.1, VDA ISA 2027, next ISO/IEC 27003 edition,
ISO 22316 revision, CSP Level 3, Subresource Integrity 2, Trusted Types, and
draft BSI TR-03183 Parts 1 and 3 are also quarantined. The retired FFIEC
Cybersecurity Assessment Tool is explicitly excluded from current FFIEC
claims. ISO/IEC 27009 is deliberately
excluded because ISO withdrew the 2020 edition; the suite does not preserve a
withdrawn sector-extension standard merely to increase catalog breadth.
ISO/IEC 27091 remains at ISO final-draft stage 50.00, the OWASP Client-Side Top
10 page still presents candidate risks, and the VulnGym and SecVulEval research
artifacts remain preprint or under-review inputs. All four are quarantined until
stable publication, immutable corpus and evaluator contracts, license review,
and human promotion; no research-preview score contributes to assurance.
OWASP SCSVS 0.0.1 remains an explicitly initial alpha draft. Its taxonomy may
inform research mappings, but only the final OWASP Smart Contract Top 10 and
pinned SmartBugs/stateful fixtures contribute to current assurance.
SPDX 3.1 remains a release candidate while SPDX 3.0 is the stable normative
baseline. OWASP Benchmark for Python 0.1 is retained as a research preview;
the maintained OWASP Benchmark contract remains pinned to the mature Java 1.2
corpus until Python has a stable oracle, release, and compatibility contract.
NIST SP 800-239 remains an Initial Public Draft, while final SP 800-223 and
SP 800-234 are normative. OpenEoX Core Schema 1.0 remains CSD01 and CSAF 2.1
remains an OASIS Committee Specification Draft 02 work product; the suite keeps CSAF 2.0 and
existing lifecycle controls normative until final publication, compatibility
testing, licensed review where applicable, and human promotion.
NCSC CyAS remains an in-development MVP and CoSAI MCP Security remains a
semantic-delta crosswalk candidate. Neither can contribute to normative
assurance or silently duplicate the maintained CHECK, CBEST, TIBER-EU, MCP or
GenAI red-team profiles until publisher maturity, distinct testable criteria
and governed human promotion are demonstrated.

Standards lifecycle governance is fail closed. Optional
`standards-lifecycle-evidence.json` input must provide, for every promoted
catalog, a publisher source digest, signed-snapshot digest, change-report
digest, observation time, edition status, approver identity, approval time, and
explicit human approval. `lifecycle_governance.complete` remains false until
every registered catalog passes. The curated entries retain publication,
observation, and supersession metadata where verified; notably, the 2021 NTIA
SBOM document is historical and points to the final CISA-led 2026 v2.1
replacement; the 2025 public-comment draft is not a normative entry.

## Controls and assessment procedures

Copy [the policy 1.3 example](../examples/industry-assurance-policy-1.3.example.json) to
`security/industry-assurance-policy.json`. Policy schema 1.3 supports selectable
assurance packs, custom `controls` and `procedures`, and exact protocol-specific
benchmark thresholds. Frozen 1.0 through 1.2 policies remain readable.
The strict parser accepts only known standard identifiers, unique identities,
bounded text and collections, and safe report-local JSON artifact names.

`assurance-profile-registry.json` exposes 233 built-in packs:

| Pack | Coverage |
|---|---|
| `enterprise-security` | ISO/IEC 27001, 27002, and 27034-1 |
| `privacy` | ISO/IEC 27701 and NIST Privacy Framework |
| `psirt-incident` | ISO/IEC 29147/30111 and NIST SP 800-61r3 |
| `software-supply-chain` | NIST SP 800-204D, SLSA, OpenChain, and SPDX |
| `ai-development` | NIST SP 800-218A, AI RMF, AITG, and ATLAS |
| `eu-cra` | Product security, component, support, and vulnerability handling |
| `payment-software` | PCI DSS and PCI Secure Software |
| `federal-cui` | NIST SP 800-171 and assessment procedures |
| `service-organization` | SOC 2 TSC and NIST CSF evidence surfaces |
| `control-knowledge-interoperability` | Immutable OpenCRE graph and Gemara/OSCAL schema identity, mapping provenance, conflict quarantine, semantic loss reports and independently adjudicated round trips |
| `uk-financial-cbest-assurance` | CBEST entity and important-service scope, threat intelligence, qualified providers, control-group safety, detection/response timelines, remediation, retest and no-supervisory-approval boundaries |
| `ocp-safe-hardware-firmware-assurance` | OCP S.A.F.E./SOLID source, firmware, hardware, debug, physical-interface, secure-update, supply-chain, laboratory independence, report provenance and recovery evidence |
| `c2m2-capability-maturity` | C2M2 2.1 IT/OT domains, objectives, practices, maturity indicators, evidence, disagreement, prioritized investment, outcomes and longitudinal reassessment |
| `finos-common-cloud-controls` | Release-pinned FINOS CCC capabilities, threats, controls and assessment requirements across providers with responsibility, OSCAL, drift and semantic-loss evidence |
| `ncsc-product-cyber-resilience-testing` | CRT principle-claim-argument-evidence chains, public-interface adverse cases, essential behavior, recovery and qualified independent-facility boundaries |
| `nist-pram-privacy-risk-assessment` | Data actions, problematic data actions, individual impacts, populations, likelihood, uncertainty, prioritization, engineering responses and reassessment |
| `itil4-service-management-alignment` | Licensed ITIL 4 service-value and practice criteria joined to ISO 20000/27013 change, incident, problem, supplier, continuity and improvement outcomes |
| `cis-cloud-container-hardening` | Separate AWS 7.0.0, Azure 6.0.0, GCP 5.0.0 and Docker 1.8.0 profile, recommendation, automated/manual, applicability, exception, drift, remediation and rescan evidence |
| `owasp-genai-red-team-assurance` | Threat-led model, implementation, infrastructure and runtime campaigns with multi-turn/indirect/tool/memory attacks, clean controls, utility retention, restoration and family-level retest |
| `imda-ai-verify-moonshot-assurance` | Eleven AI Verify governance principles plus Moonshot recipe, dataset, metric, seed, scorer, stochastic, protected-strata, contamination and replay evidence |
| `ncsc-check-penetration-testing` | Current provider/team registry and credential validation, customer authority, engagement methodology, evidence custody, safety, cleanup, remediation and retest for UK government/CNI use |
| `aiuc1-agent-assurance` | Q3 2026 agent capability applicability, data/privacy, security, safety, reliability, accountability and society controls with recurring independent technical evaluation and issuer-only certification boundary |
| `csa-iot-controls-alignment` | IoT device, gateway, network, cloud, mobile and operator control allocation with data-flow, lifecycle, supplier, update, degraded-operation, recovery and crosswalk semantics |
| `etsi-ai-cybersecurity-baseline` | EN 304 223 stakeholder, supplier, asset, threat, requirement and evidence trace across design, development, deployment, maintenance and end of life |
| `agentic-adoption-and-containment` | Five Eyes incremental autonomy and privilege guidance plus MAESTRO cross-layer threat paths and explicit harness escape, subversion, persistence, covert-channel, shutdown and cleanup attacks |
| `mcp-high-assurance-automation` | NSA-informed MCP principal/session/delegation identity, context separation, serialization, revocation, task propagation, teardown and lifecycle monitoring |
| `fiasse-securability-engineering` | FIASSE canonical parsing, isolated integrity, intentional request surfaces, transparency and evidence-bound merge review with non-normative SSEM scoring |
| `identity-protocol-security` | Digital identity, OAuth BCP, WebAuthn, and FAPI conformance |
| `authorization-decision-interoperability` | AuthZEN 1.0 PDP/PEP decision, metadata, capability, cache, batch, outage, confusion, draft-exclusion, and no-certification controls |
| `openid-federation-security` | Federation 1.1 entity statements, trust paths, metadata policies, OIDC binding, rollover, expiry, adversarial chains, and explicit early-suite status |
| `hpc-ai-infrastructure-security` | SP 800-223 architecture and threat posture plus complete SP 800-234 control-overlay tailoring, shared-resource isolation, performance and recovery evidence |
| `identity-management-framework` | ISO/IEC 24760:2025 concepts, reference architecture, people/organization/device/software identity lifecycle, privacy, federation and assessor boundaries |
| `medical-device-cybersecurity-depth` | SW96, IEC 80001-1/60601-4-5 and IMDRF risk, capability, clinical responsibility, SBOM, legacy support and patient-safety evidence |
| `autonomous-physical-ai-safety` | ISO 21448/PAS 8800/34502 and UL 4600 ODD, AI-element, scenario, degradation, fallback, safety-case and update evidence |
| `critical-c-cpp-coding-assurance` | Licensed MISRA C/C++ editions, compiler/target matrices, runtime corroboration, deviation governance and independent adjudication |
| `cross-vendor-confidential-computing-attestation` | RATS/EAT and SEV-SNP/TDX/CCA evidence, endorsements, TCB status, revocation, replay, semantic boundaries and fail-closed secret release |
| `voting-system-assurance` | VVSG 2.0 security, software independence, auditability, accessibility, laboratory authority and jurisdiction claim boundaries |
| `critical-sector-safety-security` | Nuclear, rail and space hazards, essential functions, safety-security interaction, digital-twin failures, degraded operation, recovery and independent assurance |
| `space-mission-communications-security` | CCSDS mission threats, reference architecture, cryptography, credentials, SDLS protocol and security-association lifecycle with forged/replayed traffic, link faults, safe recovery and no-flight-certification boundaries |
| `stateful-smart-contract-assurance` | Multi-transaction EVM exploits, economic invariants, governance, proxies, oracles, bridges, clean controls and alpha-SCSVS exclusion |
| `national-security-system-authorization` | CNSSI 1253 Revision 5 categorization, baselines, overlays and ODPs plus DoD RMF roles, assessment, authorization, POA&M and monitoring boundaries |
| `operational-zero-trust-implementation` | NSA 2026 Primer, Discovery and Phase One/Two activities across seven pillars plus identity-aware microsegmentation, session revocation, fail-closed behavior and recovery |
| `healthcare-operational-resilience-depth` | HICP 2023 and HPH CPG ransomware, identity, clinical continuity, ePHI, biomedical/facility dependencies, downtime, restoration and patient-safety outcomes |
| `aircraft-system-development-safety-assurance` | ARP4754B/ARP4761A aircraft functions, architecture, DAL allocation, FHA/PSSA/SSA, common causes, DO-178C/330/326A trace and assessor boundaries |
| `accredited-laboratory-operating-assurance` | ILAC P9/P10/P14/P15 proficiency, traceability, uncertainty, competence, impartiality and corrective action layered over ISO/IEC 17025/17020/17065 |
| `maritime-operational-cyber-risk-depth` | IMO MSC-FAL.1/Circ.3/Rev.3 governance-through-recovery, safety management, ship/shore/port/supplier dependencies, degraded operation and recovery |
| `empirical-assurance-benchmark-calibration` | Independently labeled CWE and exploit holdouts, formal-tool disagreement, blinded process/supplier assessment, and incident/privacy longitudinal outcomes |
| `water-sector-cyber-resilience` | AWWA/EPA mission risk, treatment and distribution invariants, OT controls, manual operation, public-health coordination and independently reviewed recovery |
| `public-safety-emergency-communications` | NENA NG911 security and i3 message semantics plus P25 identity, keys, conformance, interoperability, failover and live-traffic exclusion |
| `global-gxp-computerised-system-assurance` | EU, WHO and PIC/S lifecycle validation, ALCOA+ records and metadata, audit trails, continuity, migration, inspection reconstruction and regulatory-claim boundaries |
| `transit-cybersecurity-resilience` | Final NIST IR 8576 CSF outcomes across multimodal IT/OT, safety, degraded operations, service continuity, passenger communications and recovery |
| `emergency-incident-coordination` | ISO 22320 command authority, information quality, decisions, resources, interoperable communications, handoffs, demobilization and after-action closure |
| `gas-scada-cryptographic-resilience` | AGA/API/IEC endpoint, channel and key identity; forgery/replay/downgrade/rollover tests; manual operation; latency; and reconciled recovery |
| `cloud-container-zero-trust` | Cloud responsibility, container lifecycle, workload identity, and CIS configuration |
| `cryptography-pqc` | Cryptographic inventory, approved modules, TLS, PQC transition, and algorithm conformance |
| `operational-resilience` | Continuity, contingency planning, recovery objectives, and exercised restoration |
| `ransomware-resilience` | IR 8374 Rev. 1 and SP 1800-11/25/26 governance-through-recovery, inert encryption/exfiltration cases, identity and key loss, restored-service evidence and business-data reconciliation |
| `media-sanitization` | SP 800-88 Rev. 2 and IEEE 2883/2883.1 method selection, cryptographic erase prerequisites, custody, residual-data sampling, failed-method rework and signed disposition evidence |
| `ot-backup-and-remote-access` | SP 1339 and SP 1800-45 PLC/HMI/historian/configuration backup fidelity, safe restoration order, remote-session approval, recording, revocation and emergency termination |
| `iec-62443-provider-evaluation` | IEC TS 62443-6-1 evaluator competence, independence, evidence sufficiency, sampling, repeatability, nonconformity grading, agreement, adjudication and retest |
| `crisis-leadership-and-exercises` | ISO 22361/22398 authority, strategic decision rights, protected exercise design, injects, communications, independent observation, corrective ownership and retest |
| `enterprise-ict-risk-portfolio` | SP 800-221/221A technical-to-mission risk trace, shared dependencies, appetite/tolerance, correlated and concentration risk, machine-readable registers and independent roll-up replay |
| `standards-crosswalk-governance` | SP 1347 source/target edition, direction, relationship, scope, provenance, confidence, semantic-drift, round-trip and false-equivalence controls |
| `lng-and-ev-infrastructure` | IR 8406/8473 LNG and EV/XFC dependencies, cyber-physical resilience and explicitly reviewed CSF 1.1-to-2.0 mapping boundaries |
| `eu-digital-regulation` | GDPR, NIS2, DORA, AI Act, and CRA applicability and evidence |
| `iot-consumer` | IoT manufacturer, device capability, support, and consumer-product baselines |
| `ot-industrial` | Industrial secure development, component controls, and zone/conduit assessment |
| `automotive` | Automotive cybersecurity engineering, management, and secure software updates |
| `medical-device` | Medical software lifecycle, safety-security verification, SBOM, and FDA evidence |
| `federal-cloud-defense` | FedRAMP OSCAL, CMMC, CUI controls, and independent assessment objectives |
| `systems-risk-measurement` | Trustworthy systems engineering, cyber resiliency, risk management, and measurement traceability |
| `security-data-interoperability` | SARIF, CSAF, STIX/TAXII, OpenVEX, OSCAL, and CycloneDX schema and semantic exchange |
| `product-certification` | Common Criteria security targets, evaluation evidence, and claimed-scope validation |
| `detection-threat-intelligence` | Sigma detections, ATT&CK behavior, STIX/TAXII exchange, and controlled detection validation |
| `secure-coding` | CERT C/C++/Java, MISRA C, and ISO language-security rule conformance |
| `software-testing-vv` | Exact ISO/IEC/IEEE 29119 process, documentation, technique, and keyword-driven test evidence plus ISO/IEC 20246 work-product review |
| `safety-security` | IEC 61508, ISO 26262, ISO 14971, and avionics safety/security co-engineering |
| `specialized-target-validation` | Mobile, cloud, smart-contract, IoT, and protocol-specific adversarial targets |
| `ai-robustness-impact` | AI impact assessment, robustness testing, measurement, and residual-risk evidence |
| `privacy-by-design` | Privacy principles, privacy-by-design lifecycle controls, and data-flow validation |
| `zero-trust-implementation` | Zero-trust maturity, workload identity, OT boundaries, and implementation validation |
| `independent-evaluator-assurance` | ISO/IEC 17025/17020/17065 method competence, impartiality, traceability, and certification boundaries |
| `ot-system-operations` | IEC 62443 asset owner/provider programs, system risk and security levels, NERC CIP, and smart-grid controls |
| `healthcare-security` | HIPAA ePHI safeguards, NIST SP 800-66 mappings, and licensed HITRUST evidence |
| `airborne-software-assurance` | DO-178C lifecycle objectives, DO-330 tool qualification, and model/OO/formal-method supplements |
| `federal-configuration-hardening` | Version-pinned DISA STIG/SRG and SCAP release deltas, applicability adjudication, automated/manual agreement, exception expiry, remediation rollback and longitudinal drift |
| `software-quality-evaluation` | ISO/IEC 25001/25040/25041 quality-requirements planning, evaluation design, execution, rating, limitations, and evaluator viewpoint |
| `incident-management` | ISO/IEC 27035 and ISO/IEC/IEEE 23612 preparation-through-recovery and software-incident traceability |
| `privacy-impact-assessment` | ISO/IEC 29134 PIA scope, stakeholder, impact, treatment, approval, and negative-scenario evidence |
| `supply-chain-identity` | in-toto/DSSE subject integrity and lossless CPE, SWID, purl, OSV, and CVE identities |
| `threat-model-quality` | Assets, boundaries, assumptions, threats, abuse paths, mitigations, tests, residual risk, and drift |
| `software-lifecycle-traceability` | Requirements-through-retirement evidence with bidirectional requirement coverage |
| `architecture-evaluation-process` | Stakeholder concerns, quality scenarios, risk paths, decisions, corroboration, and independent review |
| `software-process-capability` | Evidence-bounded capability levels across requirements, implementation, verification, release, response, operations, and improvement |
| `comprehensive-weakness-mapping` | Full CWE release and abstraction-policy mapping rather than Top-25-only coverage |
| `exploit-prioritization-validation` | Point-in-time EPSS/KEV outcome calibration with future-data exclusion and operational budget metrics |
| `ai-lifecycle-data-evaluation` | AI lifecycle, data quality, bias, transparency, explainability, robustness, supervised-learning evaluation, and repeatable empirical benchmarking |
| `supplier-relationship-assurance` | Supplier agreements, component/service monitoring, ICT supply-chain controls, and cloud-chain accountability |
| `software-signing-conformance` | Sigstore and SLSA verifier trust-root, identity-policy, subject, and negative-case conformance |
| `remote-attestation-assurance` | RATS/EAT evidence, endorsement, appraisal, freshness, verifier, and relying-party boundaries |
| `ot-patch-management` | IEC 62443 disclosure, patch qualification, distribution, compensating controls, and deployment evidence |
| `continuing-airworthiness-security` | DO-355A joined to ARP5150B/ARP5151B service signals, safety-security impact, aircraft effectivity, corrective action, field effectiveness and recurrence |
| `maritime-cyber-resilience` | IACS UR E26/E27 ship and onboard-system lifecycle, recovery, update, and conformance evidence |
| `financial-messaging-security` | SWIFT CSCF 2026 architecture, annual delta, applicability, significant-change, bounded reliance, control operation, remediation, retest and independent-assessment evidence |
| `devsecops-maturity` | OWASP DSOVS and DSOMM evidence-backed maturity with blinded reassessment |
| `test-maturity` | TMMi 2.0 test-process maturity and independent rating calibration |
| `ai-conformity-quality` | AI quality, bias, trustworthiness, AICM controls, and independent conformity evidence |
| `security-automation-interoperability` | CACAO, OpenC2, and OCSF round-trip and semantic conformance |
| `cloud-independent-assurance` | CSA STAR/CAIQ scope, assessor independence, validity, and shared responsibility |
| `federal-vulnerability-disclosure` | NIST SP 800-216 disclosure governance and end-to-end exercise evidence |
| `consumer-product-regulation` | UK PSTI and ETSI EN 18031 applicability and product conformity evidence |
| `detection-product-evaluation` | MITRE ATT&CK Evaluations ingestion with technique-level authorized replay |
| `external-maturity-comparison` | Licensed BSIMM/CMMI evidence and governed, anonymized cohort comparison |
| `cloud-native-api-assurance` | NIST API lifecycle, microservices, service-mesh, DevSecOps, and cloud-native data protection |
| `supply-chain-transparency-consumer` | SCITT statements and receipts, S2C2F dependency consumption, and SBOM minimum elements |
| `ai-agentic-testing` | OWASP agentic risks and ISO risk-based, stochastic AI test design |
| `vulnerability-intake-patch-operations` | RFC 9116 intake plus enterprise inventory-to-verification patch management |
| `runtime-contract-interoperability` | OpenAPI, AsyncAPI, GraphQL, JSON Schema, and OpenTelemetry semantic conformance |
| `uk-cyber-resilience` | NCSC CAF essential-function outcomes and Cyber Essentials technical controls |
| `australian-essential-eight` | Evidence-backed maturity across all eight ASD mitigations |
| `cisa-cross-sector-cpg` | Prioritized cross-sector outcomes and sampled effectiveness evidence |
| `automotive-software-update` | ISO 24089 and UNECE R156 update engineering, negative cases, and recovery |
| `identity-lifecycle-continuous-access` | SCIM schema/protocol/cursor/security-event lifecycle plus final SSF/CAEP/RISC transmitter, receiver, replay, subject, stream, and revocation evidence |
| `workload-identity-federation` | Stable SPIFFE Workload API, X.509/JWT SVID, node/workload attestation, selector isolation, trust-bundle rotation/revocation, and federation evidence |
| `ai-ml-artifact-supply-chain` | OpenSSF Model Signing 1.0 and CycloneDX 1.7 ML-BOM/model-card schemas, vectors, manifests, signer identity, provenance, roundtrip, omission, and tamper cases |
| `automotive-secure-update-protocol` | Uptane 2.1.0 Director/Image repositories, full/partial ECU verification, POUF, secure time, rollback/freeze/mix-and-match, compromise, and recovery |
| `open-source-criticality-prioritization` | Reproducible OpenSSF Criticality Score inputs, aliases, freshness, missing/stale/outlier sensitivity, temporal calibration, and context-only use |
| `energy-product-security` | IEC 62351 power-protocol security and UL 2900 product test assurance |
| `modern-sbom-assurance` | CISA-led 2026 v2.1 minimum elements with author-signature, format/version, component hash/license, multi-format negative conformance, and historical NTIA traceability |
| `enhanced-cui-assurance` | NIST SP 800-172r3/172Ar3 requirements, procedures, 53B baselines, OSCAL, and independent assessment |
| `developer-verification-minimums` | NISTIR 8397 minimum technique coverage with seeded effectiveness challenge |
| `cryptographic-key-agility` | Key lifecycle, KEM behavior, PQC discovery, transition, downgrade, rollover, and recovery |
| `continuous-security-monitoring` | ISCM strategy, measurement, operations, program assessment, and blinded assessor agreement |
| `ict-continuity-readiness` | ISO/IEC 27031:2025 dependencies, recovery objectives, disruption exercises, and improvement |
| `digital-forensics-readiness` | Digital-evidence custody, method fitness, analysis reproducibility, and incident integration |
| `accessibility-quality` | WCAG 2.2, EN 301 549, and Section 508 mixed automated/manual conformance |
| `audit-assessment-integrity` | Audit program, independence, sampling, technical control assessment, findings, and reperformance integrity |
| `security-evaluator-competence` | Role-bound ISO/IEC 19896 qualification, impartiality, blinded calibration, drift, and adjudication |
| `application-security-governance` | Complete published ISO/IEC 27034 framework, management, ASC exchange, and assurance-prediction validation |
| `firmware-hardware-trust` | NIST client/server update protection, acquired-device provenance, hardware weakness metrics, bus monitoring, protect/detect/recover, TPM measured boot, event-log replay, attestation and recovery testing |
| `differential-privacy-engineering` | Explicit privacy definitions, budgets, composition, hazards, accounting, utility, and reproducible implementation evaluation |
| `data-quality-engineering` | SQuaRE quality requirements, models, measures, reference data, uncertainty, and repeatable decision rules |
| `quality-in-use-cloud` | ISO/IEC 25019 and 25052 context, cloud quality model, measures, workloads, uncertainty, and decisions |
| `enterprise-risk-techniques` | ISO 31000 governance plus IEC 31010 technique selection, multi-method comparison, sensitivity, and blinded calibration |
| `secure-by-design-product` | CISA secure-default product properties and negative tests for prohibited or high-risk bad practices |
| `tls-protocol-assurance` | TLS 1.3 state-machine, alert, certificate, extension, replay, downgrade, and interoperability conformance |
| `reproducible-build-assurance` | Independent rebuilds across controlled time, path, user, locale, ordering, parallelism, and builder variations |
| `malware-protection-validation` | AMTSO-governed transparent evaluation using harmless EICAR, inert fixtures, clean negatives, isolation, and restoration |
| `confidential-computing-attestation` | DICE layered identity joined to TPM and RATS/EAT evidence, freshness, mutation, and verifier decisions |
| `telecommunications-security` | ISO/IEC 27011 telecom scope, shared responsibility, network/service controls, evidence, and recovery |
| `cyber-workforce-assurance` | Current NICE task, knowledge, and skill coverage with qualifications, separation of duties, drift, and succession |
| `penetration-testing-governance` | CREST/PTES/NIST authorization, scope, safety, methodology, evidence, cleanup, remediation, retest, and closure |
| `software-delivery-outcomes` | Independently recomputed DORA five-metric outcomes with immutable events, bounded scopes, uncertainty, and anti-gaming controls |
| `structured-assurance-case` | ISO 15026 claim-argument-evidence integrity and SACM 2.3 machine-readable exchange with semantic mutation testing |
| `integrity-level-vv` | IEEE 1012 integrity-scaled system, software, hardware, interface, reuse, COTS, and independent V&V |
| `cmvp-cryptographic-module` | Scheme-pinned FIPS 140-3/CMVP evidence, guidance, referenced-edition, prerequisite, and certificate-status validation |
| `international-cryptographic-module` | ISO/IEC 19790:2025 and 24759:2025 module claims, vendor evidence, calibrated tests, faults, and optional non-invasive testing |
| `biometric-identity-assurance` | ISO biometric comparison and PAD design with locked thresholds, demographic strata, attack instruments, and confidence bounds |
| `integrated-service-security-management` | ISO/IEC 20000-1 and 27013 service, change, configuration, supplier, incident, continuity, and ISMS integration |
| `interlaboratory-proficiency` | ISO/IEC 17043 blinded round-robin agreement, reference accuracy, bias, drift, adjudication, and corrective action |
| `enterprise-cyber-risk-integration` | NIST IR 8286 risk records, estimation, prioritization, roll-up, business impact, CIS RAM attack paths, and optional licensed quantitative risk |
| `enterprise-architecture-governance` | Licensed COBIT, TOGAF, ArchiMate, and Open FAIR governance, model semantics, decision traceability, and risk sensitivity |
| `ai-benchmark-governance` | ISO/IEC TR 42106 differentiated AI benchmarking with complexity, context, strata, uncertainty, metamorphic stability, and bounded claims |
| `ai-application-security-verification` | OWASP AISVS Level 1-3 applicability, AI asset/data/model/tool/memory traceability, bounded authority, and adversarial requirement conformance |
| `responsible-ai-system-assurance` | ISO AI quality/use-case evaluation plus IEEE ethical design, measurable transparency, privacy process, bias, and fail-safe validation |
| `eucc-product-certification` | EUCC scheme, laboratory and certification authority, product/certificate identity, vulnerability management, and assurance continuity |
| `federal-software-attestation` | CISA producer/product scope, authorized signatory, SSDF evidence, exceptions, release binding, expiry, and re-attestation |
| `it-quality-governance` | ISO/IEC 38500 governing-body direction and ISO 9001/90003 quality-management evidence with blinded assessor challenge |
| `nist-csf-profile-management` | CSF 2.0 current and target profiles, traceable gaps/actions, valid identifiers, priorities, exceptions, and reassessment |
| `privacy-engineering-pets` | Privacy operationalisation and model validation plus adversarial zero-knowledge-proof implementation and composition evidence |
| `mcp-protocol-security` | MCP schema, lifecycle, capability, OAuth, task, tool, prompt, resource, sampling, consent, proxy, and adversarial containment evidence |
| `cloud-provider-native-security` | AWS FSBP, MCSB v1, and Google Enterprise Foundations inventory, posture, exception, drift, attack-path, cleanup, and rescan evidence |
| `incident-response-service-maturity` | FIRST CSIRT/PSIRT mandate, constituency, service catalog, operational outcomes, maturity, exercise, assessor agreement, and improvement |
| `memory-safety-engineering` | Unsafe-code and FFI inventory, production hardening, static/sanitizer/fuzz evidence, exception governance, and risk-prioritized migration |
| `organizational-ai-governance-impact` | IEEE 2863 governing-body process and IEEE 7010 stakeholder well-being impact, indicators, monitoring, adjudication, and improvement |
| `organizational-resilience-bia` | ISO 22316/22317 dependency and impact analysis, tolerances, RTO/RPO, degraded operation, restoration, reconciliation, and reassessment |
| `open-source-project-assurance` | OpenSSF baseline/metal criteria with evidence-bound answers, freshness, independent sampling, recomputation, and bounded badge claims |
| `isms-implementation-process` | ISO/IEC 27003 implementation guidance and ISO/IEC TS 27022 process capability with assessor calibration and certification boundaries |
| `a2a-protocol-security` | A2A 1.0 Agent Card and endpoint binding, principal-to-skill/task/artifact authority, transport equivalence, OAuth, webhook/stream containment, quotas, and teardown evidence |
| `sesip-iot-platform-evaluation` | SESIP 1.2 and EN 17927 target, profile, assurance-level, composition, certificate, vulnerability, change, evaluator, laboratory, and claim-boundary evidence |
| `threat-intelligence-handling` | FIRST TLP/IEP labeling and redistribution plus VERIS incident classification, policy resolution, round trips, deidentification, audit, and downgrade resistance |
| `web-platform-defense` | CSP2 and SRI1 browser policy, integrity, origin, redirect, CORS, reporting, fallback, substitution, and cross-engine validation |
| `dora-level2-financial-resilience` | DORA ICT-risk, incident classification/reporting, provider-register, and authorized TLPT technical-standard conformance |
| `ffiec-banking-technology` | Current FFIEC DAM, AIO, and Information Security handbook assessment with blinded examiner agreement and retired-CAT exclusion |
| `bsi-c5-cloud-assurance` | C5 cloud-service boundary, control design/operation, customer responsibility, deviations, assessor independence, and attestation-versus-certification precision |
| `us-cyber-trust-mark` | FCC consumer-IoT boundary, recognized-laboratory evidence, application authority, QR/registry integrity, renewal, withdrawal, and mark-overclaim resistance |
| `digital-credential-security` | W3C VC/Data Integrity/status plus final OpenID4VP, OpenID4VCI, HAIP, and issuer-wallet-verifier evidence |
| `federal-saas-hardening` | CISA SCuBA M365/GWS tenant inventory, read-only assessment, exception, remediation, and drift evidence |
| `kubernetes-hardening-conformance` | CIS Kubernetes 2.0.1 plus version-pinned Pod Security Standards and Admission levels, modes, OS semantics, exemptions, bypass, remediation and rescan evidence |
| `privacy-threat-modeling` | LINDDUN data-flow, threat-tree, misuse-case, mitigation, blinded-review, and residual-risk evidence |
| `ast-modality-effectiveness` | Matched SAST/DAST/IAST effectiveness plus separately governed RASP prevention evidence |
| `telecom-equipment-assurance` | NESAS development-process and product-applicable 3GPP SCAS laboratory assurance |
| `tisax-automotive-information-assurance` | VDA ISA/TISAX scope, maturity, assessor independence, follow-up, sharing, and label boundaries |
| `content-provenance-authenticity` | C2PA manifest, claim, ingredient, signature, trust, tamper, and truth-claim boundaries |
| `payment-acceptance-security` | PCI MPoC/P2PE/PIN/PTS POI/3DS plus EMV 3DS across payment flows, PIN and key blocks, HSMs, devices, ACS/DS/3DS Servers, laboratories, tamper and validation-claim boundaries |
| `space-software-product-assurance` | ECSS engineering and product-assurance lifecycle, criticality, traceability, independence, reuse/COTS, supplier, coverage, anomaly, configuration, delivery and acceptance evidence |
| `regional-financial-technology-resilience` | APRA CPS 230/234 and MAS TRM applicability, critical operations, tolerances, providers, technology risk, incidents, recovery, board oversight and regulatory-claim boundaries |
| `secure-information-sharing-and-competence` | ISO cross-organization sharing agreements and handling, TLP/IEP enforcement, economic decision evidence, role competence, assessor agreement, drift and reassessment |
| `semiconductor-equipment-cybersecurity` | SEMI E187/E188/E191 equipment hardening, malware-free integration, service custody, status reporting, monitoring and known-good recovery |
| `pipeline-control-system-cybersecurity` | API 1164 pipeline IAC architecture, essential functions, remote access, manual control, safety invariants, detection, recovery and reconciliation |
| `gxp-computerized-system-data-integrity` | 21 CFR Part 11 records, audit trails, electronic signatures, validation, retention, inspection copies and licensed GAMP 5 lifecycle practice |
| `criminal-justice-information-security` | CJIS 6.1 CJI boundaries, agreements, personnel, identity, encryption, audit, mobile/cloud safeguards, incidents and sanitization |
| `automotive-process-capability-assurance` | Automotive SPICE 4.0 process outcomes, work products, capability attributes, cybersecurity traceability and blinded assessor calibration |
| `process-industry-functional-safety-security` | IEC 61511 SIF/SIL/SRS lifecycle, proof testing, safe states and IEC 62443 safety-security dependency analysis |
| `building-automation-secure-connect` | BACnet/SC node, hub, certificate, authorization, segmentation, legacy gateway, failover, safe fallback and recovery assurance |
| `industrial-robotics-safety-security` | ISO 10218 fixed/collaborative robot cells and RIA R15.08 mobile robots across modes, zones, stops, speed, routes and cyber-induced hazards |
| `data-centre-facility-resilience` | ISO/IEC 22237 and TIA-942-C facility classification, power, cooling, cabling, fire, physical security, monitoring, resilience KPIs and recovery |
| `fedramp-20x-continuous-assurance` | Final 2026 Classes A-C rules, security goals, measures, KSIs, independent validation, persistent packages, continuous monitoring, and agency-decision boundaries |
| `fido2-authenticator-assurance` | CTAP 2.2, WebAuthn, MDS 3.1, transport, user verification, authenticator metadata, recovery, and certification-claim boundaries |
| `eudi-wallet-assurance` | eIDAS 2, consolidated implementing acts, ARF 3.0.0/FCAF wallet, issuer, relying-party, privacy, trust-list, and lifecycle conformance |
| `hitrust-assessment-assurance` | Licensed HITRUST CSF 11.8.0 e1/i1/r2 scope, factors, maturity, assessor independence, corrective action, validity, and certification boundaries |
| `pci-software-security-framework` | PCI Secure Software 2.0 and Secure SLC 1.1 product, SDK, module, sensitive-asset, change, annual-attestation, and listing boundaries |
| `nis2-implementation-assurance` | NIS2 Implementing Regulation 2024/2690 and ENISA guidance applicability, technical measures, effectiveness, incidents, suppliers, and notification boundaries |
| `supplier-due-diligence` | NIST SP 1326 supplier identity, ownership, provenance, dependencies, authoritative sources, contract decisions, monitoring, exit, and deception testing |
| `software-assurance-maturity` | OWASP SAMM 2.1 activity-quality evidence, blinded assessor agreement, roadmaps, reassessment, privacy-safe cohort comparison, and sample limitations |
| `autonomous-vulnerability-research` | OSS-CRS/CRSBench source-bound challenges, protected holdouts, repeated trials, independently replayed PoVs and patches, functional tests, budgets, and confidence bounds |
| `open-source-security-metadata-graph` | Security Insights repository identity/freshness plus GUAC cross-format identity, provenance, query, and loss-bounded round-trip conformance |
| `forge-independent-source-integrity` | gittuf trusted roots, delegated policy, threshold authority, reference state, transparency log, rollback protection, and recovery |
| `malicious-package-behavior` | Package Analysis feed identity, disposable sandbox behavior, protected labels, clean controls, evasion cases, and destruction evidence |
| `cloud-native-delivery-risk-taxonomies` | Exact OWASP Kubernetes and CI/CD Top 10 coverage with design/runtime evidence and one safe negative mutation per risk identifier |
| `build-observed-sbom-assurance` | SBOMit/in-toto filesystem, process, and network observations reconciled with declared SBOMs, builder/source/subject binding, and omission/tamper cases |
| `real-world-vulnerability-generalization` | PrimeVul, DiverseVul, and CVEfixes label audit, fix replay, deduplication, contamination analysis, and project/chronological holdouts |
| `mobile-risk-taxonomy-assurance` | OWASP Mobile Top 10:2024 mapped to MASVS, MASTG, source/binary identity, disposable devices, and behavioral fixtures |
| `smart-contract-security-assurance` | OWASP Smart Contract Top 10:2026, SCWE/SCSTG mappings, SmartBugs, economic invariants, inert exploit replay, and local-chain cleanup |
| `cloud-native-lifecycle-control-assurance` | CNCF develop/distribute/deploy/runtime controls, NIST mappings, architecture evidence, CIS/Kubernetes reconciliation, and safe mutations |
| `repository-level-vulnerability-context` | ReposVul and VulEval repository snapshots, untangled fixes, multi-granularity labels, dependency context, task-separated scores, and project/time holdouts |
| `embedded-device-threat-assurance` | EMB3D 2.0.2 device properties, threats, mitigations, STIX identity, residual risk, and mapping mutations |
| `business-logic-abuse-assurance` | OWASP Business Logic Abuse Top 10 state, transition, concurrency, quota, artifact-lifetime, authority, and termination invariants |
| `cncf-supply-chain-practices-assurance` | CNCF v2 producer, consumer, and operator responsibilities across source, build, distribution, deployment, and operation |
| `public-vulnerable-application-testing` | Pinned Juice Shop, WebGoat, crAPI, and ASTF targets with authoritative labels, clean routes, state reset, identity separation, and no-egress replay |
| `statistical-fuzzing-evaluation` | FuzzBench, Magma, and ClusterFuzzLite with matched resources, repeated trials, raw observations, crash replay, deduplication, and uncertainty |
| `sbom-build-truth-validation` | Declared SBOMs reconciled with resolver, build, installed-artifact, and container-layer truth across ecosystems and known-unknown cases |
| `architecture-fitness-validation` | Architecture rules, history, ownership, decisions, and six seeded fitness mutations with blinded adjudication and drift detection |

Applicability must be explicit. A selected pack expands into evidence-backed
controls and procedures; an applicable planned procedure remains incomplete.
Copyrighted standards content is not redistributed: organizations can add their
licensed requirement-level catalogs through the existing custom policy surface.

An applicable control is `satisfied` only when every named artifact exists and
does not declare itself incomplete. An applicable procedure additionally needs:

- `execution=executed`;
- every named artifact to be complete; and
- explicit authorization proof when `authorization_required=true`.

Procedure outcomes distinguish `planned`, `evidence-gap`,
`authorization-gap`, `satisfied`, and `not-applicable`. Production and release
profiles become incomplete when an enforced applicable control or procedure is
not satisfied. Static evidence cannot masquerade as a completed penetration or
dynamic test.

## Foundational evidence assessments

Nine strict, schema-validated artifacts turn broad standards references into
reviewable engineering evidence. They are generated on every run and fail
closed when an input is absent or declares itself incomplete:

| Artifact | Governed claim |
|---|---|
| `lifecycle-traceability.json` | Seven life-cycle stages are evidenced; the source is digest-bound; applicable requirements have bidirectional evidence and end-to-end graph reachability; directional links, verified change-impact samples, and independent approval are complete |
| `architecture-evaluation.json` | Stakeholder concerns, quality attributes, risk paths, decisions, structural corroboration, and independent review are present |
| `process-capability-assessment.json` | Seven process dimensions reach at least bounded level 2; level 3 additionally requires independent audit-package verification |
| `prioritization-calibration.json` | At least 100 point-in-time observations use pinned EPSS, KEV, corpus, and outcome snapshots with no future leakage and report calibration, recall-at-budget, effort, and KEV response time |
| `maturity-model-assessment.json` | Applicable DSOVS, DSOMM, TMMi, BSIMM, and CMMI ratings bind scope, method, evidence, report, assessor competence, independence, review count, and domains |
| `security-automation-interoperability.json` | Selected STIX/TAXII, CACAO/OpenC2/OCSF, SCITT/COSE receipt, OpenAPI/AsyncAPI/GraphQL/JSON Schema, and OpenTelemetry versions, schemas, fixtures, positive/negative cases, round trips, semantic equivalence, authority, and replay protection are complete |
| `external-conformity-assessment.json` | Applicable AI, cloud, disclosure, product, detection, and licensed normative assessments bind scope, method, report, assessor, validity, authority, and applicability basis; assessor credentials require an immutable registry snapshot, issuer and scheme, active validity window, signature validation, and revocation check |
| `assurance-case-assessment.json` | ISO 15026/SACM claims, defeaters, evidence, relationships, scope binding, freshness, confidence, graph semantics, round-trip validity, and independent approval are complete |
| `threat-model-assessment.json` | The source-bound asset/component/flow/boundary graph has exact references and risk arithmetic; sensitive crossings are protected; mitigated threats have verified controls and passing negative tests; assumptions, acceptances, change triggers, and independent review are current |

The four extended assessments consume deliberately separate evidence inputs:
`maturity-model-evidence.json`, `security-automation-evidence.json`, and
`external-conformity-evidence.json`, plus
[`structured-assurance-case.json`](../examples/structured-assurance-case.example.json).
Threat-model semantics consume the separate
[`threat-model-evidence.json`](../examples/threat-model-evidence.example.json)
contract so scanner-derived topology cannot silently substitute for reviewed
assets, attack steps, risk decisions, mitigation proof, or approval.
Lifecycle semantics similarly consume
[`lifecycle-traceability-evidence.json`](../examples/lifecycle-traceability-evidence.example.json)
and reject dangling, duplicate, reverse-stage, orphaned, source-unbound, or
incompletely propagated relationships rather than inferring traceability from
artifact presence.
The structured case is intentionally strict: it requires SACM 2.3 schema,
semantic, and round-trip validation; unique claims and evidence; digest-bound
subjects; fresh verified evidence; acyclic support; resolved defeaters; no
contradictory edge semantics; policy confidence; and at least two independent
reviewers. Evidence rows use policy-selected model,
protocol, or scheme identifiers and SHA-256-bind the scope, method, fixtures,
evidence, and report. Assessor records require an identity, independence claim,
and competency digest; maturity ratings require two reviewers and explicit
domains; automation records require positive and negative cases plus round-trip
and semantic-equivalence results; external assessments require an assessment
date and written applicability basis. Unknown source fields are not copied into
the governed outputs, reducing accidental disclosure from assessor workpapers.

These are readiness indicators, not ISO certification, an architecture approval,
or proof that the prioritization model generalizes beyond its pinned evaluation
window and population.

## OSCAL lifecycle package

The suite emits seven OSCAL 1.2.2 JSON models:

| Artifact | Role |
|---|---|
| `oscal-catalog.json` | Repository-scoped control and procedure catalog |
| `oscal-profile.json` | Selected catalog profile |
| `oscal-component-definition.json` | Suite component implementation claims |
| `oscal-system-security-plan.json` | Digest-bound system and implementation boundary |
| `oscal-assessment-plan.json` | Planned controls and assessment subject |
| `oscal-assessment-results.json` | Observations and evidence gaps |
| `oscal-poam.json` | Gap remediation or continuous reassessment work |

The generated model set has been checked against NIST's official OSCAL 1.2.2
complete JSON Schema for empty and representative enforced policies. Repository
artifact validation also enforces the model root, UUID, metadata, and exact
OSCAL version. These are interoperable engineering records, not assessor
signatures or an authority-to-operate decision.

## CVSS v4 and SSVC

`standardized-prioritization.json` keeps native scanner severity separate from
standardized prioritization. A CVSS v4 record is `scored` only when a complete
`CVSS:4.0/...` vector and bounded score came from retained evidence. CycloneDX
1.7 VEX `CVSSv4` ratings are normalized into that source evidence. Missing or
invalid ratings remain explicitly unscored; native severity is never converted
into a fabricated vector.

SSVC is `decided` only when exploitation, automatability, technical impact,
mission prevalence, and the source outcome are all available and valid. KEV or
reproduction evidence may supply exploitation context, but cannot manufacture a
complete decision tree or outcome.

## Benchmark registry

`benchmark-registry.json` includes 282 families:

| Family | Purpose | Execution lane |
|---|---|---|
| Governed holdout | Native signed effectiveness corpus | Core verified report |
| OWASP Benchmark | SAST/DAST true- and false-positive cases | Disposable companion |
| NIST SARD/Juliet | Multi-language static-analysis cases | Disposable companion |
| OWASP Juice Shop | Web DAST behavior | Disposable companion |
| OWASP WebGoat | Web DAST lessons | Disposable companion |
| OWASP crAPI | API authorization and business-logic behavior | Disposable companion |
| OWASP API Security Testing Framework 2.0.1 | REST, GraphQL, gRPC, mTLS, authorization, and LLM-assisted API testing across crAPI, VAmPI, DVGA, and a clean target | Disposable no-egress API laboratory |
| CyberSecEval 4 | LLM cybersecurity behavior | Disposable companion |
| MLCommons AILuminate | AI safety and security behavior | Disposable companion |
| Organization holdout | Pinned real-world Python cases | Disposable companion |
| Python CVE pairs | Vulnerable and patched real-world revisions | Disposable companion |
| IaC holdout | Terraform, CloudFormation, and Kubernetes misconfigurations | Disposable companion |
| Container/Kubernetes holdout | Image and orchestration hardening cases | Disposable companion |
| Secret-detection holdout | Synthetic/revoked positives and clean negatives | Disposable companion |
| SBOM/SCA holdout | Component graph and advisory accuracy | Disposable companion |
| Malicious-package holdout | Inert malicious-package behavior | Disposable companion |
| Fuzzing crash holdout | Seeded defects, crashes, and deduplication | Disposable companion |
| Agentic-security holdout | Tool abuse, prompt injection, and exfiltration | Disposable companion |
| Architecture-quality holdout | Labeled dependency and architecture smells | Disposable companion |
| NIST ACVP | Cryptographic algorithm conformance vectors | Disposable companion |
| OpenID FAPI conformance | OAuth/OIDC positive, negative, and replay behavior | Disposable companion |
| W3C Web Platform Tests | WebAuthn browser and relying-party behavior | Disposable companion |
| MITRE attack emulation | Contained ATT&CK-aligned defensive validation | Disposable companion |
| OpenSSF Scorecard | Repository security-posture checks | Disposable companion |
| CIS AWS Foundations 7.0.0 | Level 1/2 recommendation, automated/manual, applicability, exception, drift, remediation and rescan conformance | Read-only AWS assessment plus disposable accounts |
| CIS Azure Foundations 6.0.0 | Level profile, recommendation, tenant/subscription/resource, manual-check, exemption, drift and rescan conformance | Read-only Azure assessment plus disposable subscriptions |
| CIS GCP Foundations 5.0.0 | Level profile, organization/folder/project/resource, manual-check, exception, drift and rescan conformance | Read-only GCP assessment plus disposable projects |
| CIS Docker 1.8.0 | Host, daemon, files, images/build, container runtime and orchestration recommendation conformance | No-egress disposable Docker hosts |
| OWASP GenAI Red Teaming Guide | Model, implementation, infrastructure and runtime campaign conformance with state/tool transcripts, clean controls, utility and remediation replay | No-egress inert-tool AI red-team laboratory |
| AI Verify and Project Moonshot | Governance process checks and reproducible technical tests across traditional and generative AI, protected strata, stochastic variance and scorer attacks | Isolated AI evaluation laboratory |
| NCSC CHECK engagement assurance | Provider/team qualification, authority, scope, method, evidence, reporting, cleanup, remediation and retest | Authorized CHECK engagement or isolated representative laboratory |
| AIUC-1 agent assurance | Q3 2026 capability-specific technical, legal and operational evidence plus recurring independent evals and change retest | No-egress inert-tool agent laboratory |
| CSA IoT controls conformance | Component control allocation, lifecycle, fault/attack, safe degradation, recovery, residue and crosswalk preservation | Representative no-egress IoT laboratory |
| ETSI EN 304 223 AI lifecycle conformance | Requirement applicability and evidence across five lifecycle stages with poisoning, substitution, privilege, monitoring, update, recovery and retirement cases | No-egress representative AI lifecycle laboratory; no certification claim |
| Agentic evaluator containment | Harness escape, policy/scorer subversion, privilege escalation, cross-agent compromise, persistence, covert exfiltration, shutdown evasion and cleanup corruption | Nested no-egress evaluator with an inaccessible outer boundary, out-of-band kill switch, immutable reset and residue scan |
| FIASSE securability assurance | Canonicalization, authoritative-state substitution, request-surface expansion, observability loss, merge-review and override-expiry mutations | Read-only source and architecture workspace; SSEM beta scores remain non-normative |
| `opencre-gemara-control-interoperability` | OpenCRE/Gemara/OSCAL identifier integrity, mapping provenance, conflict and cycle quarantine, semantic-loss reporting, drift and round-trip equivalence | Read-only no-egress mapping workspace with immutable snapshots and protected semantic oracles |
| `cbest-threat-led-assurance` | UK financial threat intelligence, external/insider/supply-chain scenarios, production safety, detection/response timelines, restoration, remediation and closure | Separately authorized production-safe engagement or no-egress financial-service twin; no regulator connectivity or supervisory claim |
| `ocp-safe-hardware-firmware-assurance` | Independent source, immutable/mutable firmware, secure boot/update, rollback, debug, physical-interface, supply-chain, tamper, fault and recovery appraisal | Residue-controlled no-egress hardware laboratory using synthetic keys and production-equivalent sacrificial devices; no OCP recognition claim |
| `doe-c2m2-capability-assessment` | C2M2 practice evidence, IT/OT scope, rating agreement, maturity-inflation challenges, risk-based investment and longitudinal outcomes | Access-controlled evidence workspace with blinded assessors and no DOE endorsement or certification claim |
| `finos-ccc-cloud-control-conformance` | FINOS CCC capability-threat-control-assessment links, cross-cloud applicability, responsibility, OSCAL semantics, native findings and drift | Read-only evidence plane plus disposable synthetic cloud fixtures; no FINOS, provider or regulatory certification claim |
| `ncsc-product-cyber-resilience-testing` | NCSC CRT principles, claims, arguments, evidence, public-interface attacks, essential behavior, residual risk, recovery and retest | NCSC-approved facility for scheme claims or a no-egress product lab that cannot claim NCSC approval |
| `nist-pram-privacy-risk-assessment` | PRAM data actions, problematic actions, individual impacts, likelihood, uncertainty, vulnerable populations, response effectiveness and reassessment | No-egress synthetic/deidentified privacy workspace with no legal-compliance or zero-risk claim |
| `itil4-service-management-outcome-assurance` | Licensed service-value, change, release, incident, problem, supplier, continuity, security and improvement outcome evidence | Licensed access-controlled workspace using deidentified records and synthetic faults; no PeopleCert or practitioner certification claim |
| Polyglot CVE pairs | Time-split vulnerable and patched revisions across eight language families | Disposable companion |
| Artifact interoperability | Semantic SARIF, SPDX, CycloneDX, and OSCAL conformance | Disposable companion |
| Scanner scale and determinism | Wall time, peak memory, and repeatable results | Disposable companion |
| Recovery/resilience holdout | Dependency-failure and restoration behavior | Disposable companion |
| Protocol-evasion holdout | Encoded, fragmented, and ambiguous parser inputs | Disposable companion |
| Atomic Red Team | Controlled detection-control validation mapped to ATT&CK | Disposable companion |
| Official artifact schema conformance | Official schema and semantic round-trip validation for security artifacts | Disposable companion |
| Defects4J | Reproducible real-world Java functional defects | Disposable companion |
| SWE-bench Verified | Repository-level Python functional diagnosis and repair | Disposable companion |
| Google FuzzBench | Statistical fuzzer performance and repeatability | Disposable companion |
| Magma | Ground-truth fuzzing bugs and reachability | Disposable companion |
| OWASP MAS Crackmes | Android and iOS mobile-security behavior | Disposable companion |
| CloudGoat | Disposable cloud attack-path validation | Disposable companion |
| SmartBugs Curated | Labeled Solidity and EVM vulnerability detection | Disposable companion |
| ETSI IoT conformance | Consumer-IoT assessment cases and approved product fixtures | Disposable companion |
| STIX/TAXII interoperability | Threat-intelligence schema and protocol exchange | Disposable companion |
| Secure-coding rule conformance | Organization-approved CERT, MISRA, and ISO rule examples | Disposable companion |
| Vul4J | Reproducible Java vulnerabilities, proof-of-vulnerability tests, and human patches | Disposable companion |
| BugsInPy | Reproducible Python functional defects, coverage, mutation, and repair behavior | Disposable companion |
| AgentDojo | Agent prompt-injection attack success and utility under attack | Disposable companion |
| HarmBench | Standardized automated LLM red teaming, robust refusal, utility, and private-holdout generalization | Disposable companion |
| AgentHarm Inspect Evals 6-B | Multi-step harmful agent behavior, refusal, tool-authority containment, benign utility, and scorer-correctness checks | Disposable companion |
| garak probe conformance | Version-pinned probe, detector, generator, plugin, calibration, and regression execution | Disposable companion |
| OWASP Cornucopia threat-model coverage | Card-to-threat-to-control-to-test traceability, omission mutations, and independent adjudication | Disposable companion |
| OSS-Fuzz/ClusterFuzzLite | Continuous fuzzing integration, crash discovery, deduplication, and regression | Disposable companion |
| DISA STIG/SCAP conformance | Quarterly release and rule deltas, asset/CPE applicability, automated/manual agreement, engine disagreement, exception expiry, laboratory remediation/rollback, rescan and drift durability | Disposable companion |
| IEC 62443 system conformance | Licensed system-requirement and claimed-security-level assessment | Disposable companion |
| Threat-model quality | Expert-labeled assets, boundaries, assumptions, threats, mitigations, tests, and drift | Disposable companion |
| Lifecycle traceability mutation | Seeded requirement-to-design-to-test-to-release trace breaks | Disposable companion |
| Architecture evaluation scenarios | Blinded, independently labeled quality-attribute and tradeoff scenarios | Disposable companion |
| Process capability assessor agreement | Blinded assessor agreement over evidence-bounded capability cases | Disposable companion |
| CWE mapping conformance | Full-release weakness abstraction and mapping correctness | Disposable companion |
| EPSS/KEV temporal backtest | Point-in-time exploit prioritization without future-data leakage | Disposable companion |
| SV-COMP | Resource-bounded software-verification tasks and validated witnesses | Disposable companion |
| Test-Comp | Resource-bounded test-generation tasks and validated test suites | Disposable companion |
| Sigstore client conformance | Trust-root, identity-policy, subject, and negative signature verification | Disposable companion |
| SLSA verifier conformance | Provenance subject, builder, identity, and negative verification cases | Disposable companion |
| NIST ARIA/Inspect evaluation | Repeatable AI-risk and robustness evaluation with stochastic repetitions | Disposable companion |
| IEC 62443 patch-management exercise | Signed advisory and firmware applicability through safety/availability review, qualification, maintenance window, deployment, partial failure, rollback, compensating-control expiry, restoration and longitudinal outcomes | Inert representative IACS digital twin or laboratory |
| DO-355/ARP5150B/ARP5151B continuing-airworthiness exercise | Transport and general-aviation or rotorcraft service signals, security/safety impact, configuration and fleet effectivity, authority decisions, field corrective action, effectiveness and recurrence | Licensed-criteria synthetic-fleet workspace with no production or flight connectivity |
| IACS maritime cyber conformance | Qualified ship and onboard-system lifecycle and recovery evidence | Disposable companion |
| SWIFT CSCF independent assessment | CSCF 2026 annual delta, architecture-specific applicability, significant change, permitted reliance, independent sampling, transaction/recovery scenarios, remediation, retest and KYC-SA handoff | Read-only synthetic financial-messaging assessment workspace |
| CCSDS space-mission link security | Mission threat and architecture trace, algorithms, credentials, security associations, SDLS processing, forgery/replay/reorder/delay/downgrade/link-fault cases, monitoring, recovery and residue checks | No-egress ground/relay/flight mission digital twin with inert payload and actuator interfaces |
| OWASP DSOVS maturity | Evidence-backed DevSecOps verification maturity and assessor agreement | Disposable companion |
| OWASP DSOMM maturity | Evidence-backed DevSecOps maturity and assessor agreement | Disposable companion |
| TMMi assessment | Test-process maturity and independent rating agreement | Disposable companion |
| BSIMM/CMMI cohort | Governed licensed-model and compatible external cohort comparison | Disposable companion |
| CSA STAR/CAIQ conformance | Independent cloud assurance scope and evidence conformance | Disposable companion |
| CACAO/OpenC2/OCSF interoperability | Security automation round-trip, negative-case, and semantic conformance | Disposable companion |
| MITRE ATT&CK Evaluations | Lossless result ingestion and authorized technique-level replay | Disposable companion |
| AI conformity and quality | AI quality, bias, trustworthiness, and control acceptance criteria | Disposable companion |
| PSTI/EN 18031 product conformance | Consumer and radio-product regulatory test evidence | Disposable companion |
| SCITT transparency conformance | Signed statements, COSE receipts, inclusion, consistency, replay, and equivocation | Disposable companion |
| Cloud-native API/service-mesh conformance | Gateway, workload identity, policy bypass, data-plane, and control-plane adversarial cases | Disposable companion |
| API contract specification conformance | Official OpenAPI, AsyncAPI, GraphQL, and JSON Schema positive, negative, downgrade, and round-trip cases | Disposable companion |
| OpenTelemetry semantic conformance | Trace context, baggage, redaction, semantic conventions, and round-trip integrity | Disposable companion |
| AI agentic testing conformance | Risk-based stochastic agent, tool, memory, delegation, utility, and recovery cases | Disposable companion |
| S2C2F consumer dependency conformance | Dependency acquisition, substitution, quarantine, update, and compromise response | Disposable companion |
| Multi-cloud/Kubernetes attack paths | Authorized AWS, Azure, GCP, and Kubernetes identity, network, data, and control-plane paths | Disposable companion |
| security.txt and patch operations | RFC 9116 parsing plus inventory-to-deployment patch lifecycle and rollback | Disposable companion |
| Regional cyber maturity assessment | Blinded assessor agreement for CAF, Cyber Essentials, Essential Eight, and CISA CPG evidence | Disposable companion |
| Automotive software update conformance | ISO 24089 and UNECE R156 authenticity, compatibility, interruption, rollback, and recovery | Disposable companion |
| Energy product security conformance | IEC 62351 and UL 2900 licensed protocol and product negative cases | Disposable companion |
| CISA SBOM minimum-elements conformance | Current minimum fields, relationships, known unknowns, freshness, and multi-format fixtures | Disposable companion |
| Enhanced CUI OSCAL conformance | SP 800-172r3/172Ar3 controls, assessment objects, depth, coverage, and OSCAL traceability | Disposable companion |
| NIST developer verification conformance | NISTIR 8397 technique coverage, overlap, limitations, and seeded positive/negative cases | Disposable companion |
| Cryptographic lifecycle/agility conformance | Key lifecycle, KEM, transition, downgrade, hybrid, rollover, recovery, and zeroization | Disposable companion |
| ISCM program assessment | SP 800-137A/IR 8212 evidence cases with blinded assessor agreement | Disposable companion |
| ICT continuity recovery exercise | ISO/IEC 27031 disruption, degraded-mode, failover, restoration, and lessons-learned cases | Disposable companion |
| Digital forensics chain of custody | Evidence handling, validated methods, repeatability, analysis, and custody integrity | Disposable companion |
| WCAG accessibility conformance | Automated rules plus keyboard, reflow, focus, screen-reader, speech, caption, and manual cases | Disposable companion |
| NIST CFReDS/CFTT | Documented forensic images, expected artifacts, acquisition, search, mobile, and cloud tool behavior | Disposable companion |
| W3C ACT Rules | Rule applicability and expected accessibility outcomes against the formally approved ACT corpus | Disposable companion |
| DroidBench | Android lifecycle, callback, reflection, ICC, aliasing, and source-to-sink taint analysis | Disposable companion |
| Ghera | Android framework misuse and security regression cases on a pinned emulator image | Disposable companion |
| SecBench.js | Real JavaScript/TypeScript vulnerability-fix pairs with locked dependencies | Disposable companion |
| Chaos Mesh/Litmus | Bounded failure experiments with steady state, SLO, blast radius, rollback, and cleanup assertions | Disposable companion |
| Sonobuoy | Kubernetes-release and plugin-pinned conformance execution | Disposable companion |
| CIS-CAT/SCAP platform conformance | Product-, edition-, profile-, and benchmark-specific configuration results | Disposable companion |
| C2SP Project Wycheproof | Valid, invalid, and acceptable cryptographic edge cases with algorithm- and implementation-bound results | Disposable companion |
| TIBER-EU threat-led red team | Approved threat intelligence, scoped objectives, control detection, kill switches, restoration, and independent engagement governance | Authorized external engagement |
| NIST Dioptra | Digest-pinned models, datasets, attacks, defenses, seeds, repeated attack success, utility, and variance | Disposable accelerator companion |
| Firmware resilience and measured boot | Signed firmware, protect/detect/recover faults, TPM event logs, PCR replay, quotes, and recovery oracles | Authorized hardware laboratory or emulator |
| Access-control policy/model conformance | Policy models, decision oracles, boundary cases, mutation operators, and fail-closed authorization outcomes | Disposable companion |
| Differential-privacy implementation evaluation | Neighboring datasets, privacy accountant, epsilon/delta, composition, hazards, utility, and repeated deterministic evidence | Disposable statistical companion |
| Security evaluator calibration | Role-specific licensed criteria, blinded cases, golden decisions, impartiality, agreement, and adjudication | Blinded assessment workspace |
| SQuaRE quality measurement | Approved quality requirements, measure definitions, reference datasets, formulas, scales, uncertainty, and golden results | Disposable measurement companion |
| ISO 29119 test-process conformance | Licensed Parts 2-5 criteria, process/document omissions, technique oracles, boundary cases, and traceability breaks | Protected test-management companion |
| SQuaRE quality-in-use/cloud | User contexts, cloud quality models, workloads, measures, uncertainty, degradation, and recovery decisions | Disposable cloud measurement companion |
| Risk technique calibration | ISO 31000/IEC 31010 scenarios, technique-selection oracles, uncertainty, sensitivity, agreement, and adjudication | Blinded assessment workspace |
| TLS protocol conformance | Pinned BoGo/tlsfuzzer state, alert, certificate, extension, replay, downgrade, fragmentation, and interoperability cases | Loopback-only protocol laboratory |
| Reproducible-build variation | Independent builds across controlled time, path, user, locale, ordering, parallelism, and builder-image variations | No-egress disposable builders |
| CISA Secure by Design negative assurance | Clean-install secure defaults, identity, logging, update, recovery, service exposure, and exception cases | Disposable product environment |
| AMTSO malware-protection evaluation | Approved test plan, harmless EICAR, inert positives, clean negatives, visibility, latency, remediation, safety, and restoration | Dedicated isolated malware laboratory |
| DICE attestation conformance | Layered identity, certificates, evidence, endorsements, freshness, mutation, verifier decisions, reset, and recovery | Authorized hardware laboratory or emulator |
| Telecom security controls | Licensed ISO/IEC 27011 scope, shared responsibility, controls, evidence, incidents, and non-applicability cases | Read-only assessment or disposable telecom lab |
| NICE workforce coverage | NICE 2.2.0 role/task/knowledge/skill mappings, qualifications, separation of duties, coverage, and drift | Access-controlled assessment workspace |
| Penetration-test engagement quality | Signed authorization, rules of engagement, competence, evidence, safety, cleanup, remediation, retest, and closure | Authorized target with kill switches and restoration |
| DORA delivery outcomes | Immutable change, deployment, incident, recovery, and rework events with independent five-metric recomputation | Read-only pseudonymized analytics workspace |
| Structured assurance-case conformance | SACM syntax/semantics and ISO 15026 graph mutation, defeater, evidence, confidence, and review cases | No-egress blinded validation worker |
| Integrity-level V&V conformance | IEEE 1012 integrity classification, task rigor, independence, interfaces, reuse, COTS, and anomaly disposition | Independent read-only V&V workspace |
| CMVP FIPS 140-3 validation | Current scheme publications, referenced editions, module boundary, algorithm prerequisites, certificate status, and decision trace | Qualified cryptographic laboratory |
| ISO 19790/24759 module conformance | International module requirements, vendor evidence, calibrated tests, faults, boundaries, and uncertainty | Qualified cryptographic laboratory |
| Biometric performance and PAD | Locked-threshold FMR, FNMR, IAPAR, demographic and attack-instrument strata with Wilson bounds | Consent-governed sequestered biometric laboratory |
| Service/security management integration | Change, release, configuration, supplier, incident, problem, continuity, recovery, and corrective-action traceability | Read-only evidence plus disposable service twin |
| Interlaboratory proficiency | Blinded assigned-value agreement, reference accuracy, bias, drift, outliers, appeals, and corrective action | Separated proficiency-provider workspace |
| NIST IR 8286 enterprise risk register | Official schema validation, estimation and prioritization re-performance, roll-up lineage, correlation, units, BIA, appetite, and mutation cases | Read-only risk evidence workspace |
| CIS RAM attack-path analysis | Pinned risk criteria, threat and safeguard analysis, blinded assessor agreement, sensitivity, adjudication, and acceptance | Blinded risk assessment workspace |
| SQuaRE quality governance | Licensed ISO/IEC 25001 planning, methods, tools, competence, decisions, feedback, and management fault injection | Independent quality-evaluation workspace |
| ISO/IEC TR 42106 differentiated AI benchmarking | Complexity- and context-stratified quality benchmarking, uncertainty, aggregation, metamorphic rank stability, evaluator robustness, and claim boundaries | Disposable AI benchmark laboratory |
| Enterprise architecture governance | Licensed framework mapping, ArchiMate semantics, stakeholder and decision trace, assessor agreement, and quantitative-risk sensitivity | Read-only blinded architecture workspace |
| Microsoft PyRIT AI red team | Pinned multi-turn scenarios, objectives, techniques, converters, targets, scorers, memory, private holdouts, calibration, and cleanup | No-egress disposable AI sandbox |
| OWASP AISVS 1.0 conformance | Requirement levels, applicability, system boundary, complete control/test/evidence trace, prompt/data/model/tool/memory negative cases, mutation, and adjudication | No-egress disposable AI application sandbox |
| ISO/IEC TS 25058 AI quality evaluation | Licensed quality-model criteria, context, measures, datasets, strata, uncertainty, metamorphic/adverse cases, decisions, and monitoring | Independent AI quality laboratory |
| EUCC scheme assurance | Regulation/amendment/SotA pinning, CC/CEM and security-target map, ITSEF/CB authority, certificate/product binding, and assurance continuity | Read-only separated certification workspace |
| CISA secure-software attestation | Common-form and SSDF claim map, product/release scope, signatory authority, exceptions, forgery, replay, staleness, and change triggers | Read-only test-signing workspace |
| IEEE 7000-series AI ethics | Ethical-value trace, transparency, privacy, subgroup bias, application boundaries, fail-safe behavior, appeals, uncertainty, and adjudication | Disposable responsible-AI assessment workspace |
| AI use-case security/privacy | Domain context and boundary, security/privacy risks and controls, normal/adverse/out-of-domain/misuse cases, and residual-risk review | Disposable domain use-case workspace |
| IT/quality governance assessor agreement | Licensed ISO/IEC 38500/ISO 9001 mapping, blinded cases, competence, agreement, nonconformity, correction, and adjudication | Blinded governance assessment workspace |
| NIST CSF profile reassessment | Valid CSF identifiers, current/target state, gap/risk/action/owner trace, exceptions, expiry, mutation, regression, and reassessment | Read-only governance evidence workspace |
| MLCommons AILuminate Safety | Versioned safety standard, locale, hazards, public/private split, evaluator calibration, grading, contamination, utility, and uncertainty | No-egress disposable model worker |
| MLCommons AILuminate Jailbreak | Versioned attack/baseline corpus, protected split, evaluator calibration, naive-versus-attack grading, variance, utility, and contamination | No-egress disposable model worker |
| Privacy engineering/PET conformance | Privacy model and attacker boundary plus ZKP statement/setup/parameter binding, malformed/replay/linkability/composition/differential cases, and cryptographic review | Disposable cryptographic privacy laboratory |
| MCP client/server security conformance | MCP 2025-11-25 plus OWASP and NSA guidance covering principal/session/delegation identity, trust domains, context, serialization, revocation, task propagation, injection, SSRF, confused deputy, teardown and residue | No-egress disposable MCP laboratory with separated roles and out-of-band shutdown |
| AWS FSBP/Security Hub conformance | Account/OU/region/resource coverage, controls, findings, suppressions, expiry, drift, remediation, CloudTrail, cleanup, and rescan | Read-only AWS assessment plus disposable test accounts |
| Microsoft MCSB/Defender conformance | Tenant/subscription/resource coverage, v1 baselines, Defender findings, exemptions, preview separation, drift, remediation, activity log, cleanup, and rescan | Read-only Azure assessment plus disposable subscriptions |
| GCP Enterprise Foundations conformance | Organization hierarchy, identities, policies, networks, logging, keys, secrets, SCC, Terraform drift, deviations, cleanup, and rescan | Read-only GCP assessment plus disposable projects |
| FIRST CSIRT/PSIRT maturity | Mandate, constituency, service portfolio, competencies, outcomes, capacity, handoffs, exercises, blinded assessor agreement, and improvement | Blinded synthetic response workspace |
| Memory-safety engineering | Unsafe and FFI reachability, production build hardening, static analysis, sanitizers, fuzzing, crash regressions, exceptions, and migration parity | No-egress native-code builders and runners |
| IEEE AI governance/well-being | Governing authority, roles, lifecycle, stakeholders, indicators, baselines, impacts, tradeoffs, monitoring, appeals, and assessor agreement | Blinded human-impact assessment workspace |
| Organizational resilience/BIA exercise | Dependencies, impact timelines, tolerances, RTO/RPO, capacity, disruption, degradation, failover, restoration, reconciliation, and reassessment | Authorized disposable service twin |
| OpenSSF badge conformance | Criteria revisions, project identity, response export, evidence freshness, disabled controls, stale links, inflated levels, and recomputation | Read-only project assessment workspace |
| ISMS implementation/process assessment | ISO/IEC 27003/27022 mapping, scope, interfaces, measures, capability, tailoring, audit/corrective-action cases, agreement, and claim boundaries | Blinded ISMS assessment workspace |
| A2A protocol security conformance | Agent Card identity, endpoint/version binding, principal/skill/task/message/artifact/subscription authorization, transport equivalence, downgrade, cross-tenant, SSRF, replay, race, and cleanup cases | No-egress disposable A2A laboratory with synthetic agents and callback sinkholes |
| SESIP IoT platform evaluation | SESIP/EN 17927 target, profile, assurance, composition, certificate, vulnerability, change, expiry, evaluator, laboratory, and negative-claim evidence | Separated authorized IoT laboratory with representative non-production hardware or emulators |
| FIRST TLP/IEP information handling | Label and policy semantics, recipients, communities, actions, attribution, storage, redistribution, STIX/TAXII round trips, downgrade, removal, and unauthorized-sharing cases | No-egress synthetic information-exchange laboratory with disclosure sinkholes |
| VERIS incident schema conformance | Schema/vocabulary identity, actor/action/asset/attribute/timeline/impact semantics, unknown values, round trips, aggregation, deidentification, and truth-claim boundaries | Read-only no-egress workspace using deidentified or synthetic incidents |
| W3C web-platform defense | CSP2/SRI1 policy, nonce/hash/source and integrity behavior, redirect/CORS/CDN substitution, multiple policies, reporting, fallback, recovery, and cross-engine results | Disposable loopback browser laboratory with synthetic origins and digest-pinned engines |
| DORA Level 2 technical standards | ICT-risk controls, incident classification/timelines/forms/channels, register templates, TLPT scope/testers/intelligence/safety/remediation, and legal claim boundaries | Legally reviewed synthetic assessment workspace plus separately authorized disposable TLPT service twin |
| FFIEC IT Handbook assessment | DAM 2024, AIO 2021, and Information Security 2016 scope, controls, outcomes, blinded examiner decisions, independence, and retired-CAT exclusion | Blinded financial-technology examination workspace with synthetic institutions and minimized data |
| BSI C5 cloud assurance | Service boundary, locations, architecture, subservices, control design/operation, customer controls, deviations, opinion period, samples, validity, and assessor agreement | Blinded licensed-criteria workspace with no provider mutation |
| FCC Cyber Trust Mark conformance | Product/component boundary, recognized-laboratory evidence, application and label-administrator authority, QR/registry integrity, renewal, forgery, expiry, withdrawal, and overclaim cases | Separated consumer-IoT laboratory with synthetic registry and no real mark application |
| OpenID digital credential conformance | VC issuance/presentation, selective disclosure, status, holder binding, privacy, and interoperability | Synthetic no-egress issuer-wallet-verifier laboratory |
| AuthZEN Authorization API conformance | Final 1.0 PDP/PEP metadata and capability negotiation, single/batch/search behavior, subject-resource-action binding, cache, partial failure, timeout, outage, confusion, draft exclusion, and clean controls | Synthetic target-only authorization laboratory |
| OpenID Federation conformance | Final Federation 1.1 and Connect 1.1 entity statements, signatures, chains, policies, trust marks, OIDC binding, rollover, expiry, cycles, forked anchors, substitution, downgrade, and explicit early-suite status | Synthetic no-egress federation with separately allowlisted official suite |
| NIST HPC/AI infrastructure assurance | SP 800-223 zones, threats and posture plus all 60 SP 800-234 tailored controls, ODPs, shared-resource isolation, scheduler/accelerator/storage cases, performance and recovery | Authorized isolated HPC partition, digital twin, or representative laboratory |
| ISO/IEC 24760 identity-management assurance | Licensed Parts 1-3:2025 concepts, principal types, authorities, architecture, privacy, federation and complete proofing-through-deletion lifecycle with blinded decisions | Protected no-egress licensed-criteria assessment workspace |
| ISO/IEC TR 5259-6 data-quality visualization | Measure/dataset/population/stratum binding, provenance, uncertainty, missingness, comparison, accessibility and misleading scale/aggregation/subgroup/color/order mutations | Deterministic no-egress visualization worker with guidance-only claims |
| Medical-device cybersecurity assurance | Risk-to-patient-harm trace, capability levels, connected clinical responsibilities, SBOM, legacy support, patching, safe recovery and adverse device/network cases | Synthetic device and clinical network with fictitious patients only |
| Autonomous physical-AI safety | ODD and hazard binding, deterministic nominal/boundary/rare/adversarial scenarios, sensor and environment degradation, safe fallback and safety-case review | No-egress simulator or inert bench with no real-world actuation |
| Critical C/C++ coding conformance | Licensed rule digests, multi-compiler/target analysis, positive/negative/ambiguous cases, sanitizers, deviations and adjudication | Disposable compiler workers with no production binaries |
| Confidential-computing attestation | Cross-vendor evidence, endorsements, reference values, TCB/revocation, replay, downgrade, claim confusion and fail-closed secret denial | Isolated verifier laboratory using synthetic secrets |
| VVSG voting-system assurance | Test Assertions 1.4 applicability, software independence, security, accessibility, ballot/log/media/power behavior, recovery and custody | Air-gapped synthetic election with no voter data or real ballots |
| Critical-sector safety-security | Nuclear/rail/space applicability, essential functions, zones, hazards, failure, degraded mode, recovery and independent IV&V | Inert sector digital twin with no production connectivity |
| Stateful smart-contract security | Source/compiler/bytecode/deployment binding, multi-actor exploits, economic invariants, governance, upgrades, bridges, clean controls and fixes | Disposable local EVM with synthetic identities and assets |
| DevSecOps/test maturity longitudinal | Scoped immutable delivery events, DORA metrics, maturity evidence, quality/security outcomes, escaped defects, anti-gaming, uncertainty and blinded reassessment | Read-only privacy-protected governance workspace |
| Detection-product longitudinal calibration | Independent ATT&CK step ground truth, representative benign workloads, source-preserving telemetry, visibility/detection/protection, false positives, latency, evasion and drift | Isolated synthetic enterprise with inert payloads and full restoration |
| NSS/DoD authorization assurance | CNSSI category/baseline/overlay/ODP, tailoring, inheritance, DoD RMF roles, assessment, POA&M, authorization term, significant change and monitoring | Controlled unclassified synthetic OSCAL workspace with no suite authorization claim |
| Zero-trust ZIG and microsegmentation assurance | All seven pillars, 77 Phase One/Two activities, discovery graph, PDP/PEP behavior, east-west denial, continuous signals, propagation, session revocation, outage and recovery | Isolated deny-by-default synthetic enterprise with full route and policy restoration |
| Healthcare operational resilience | HICP/HPH applicability, clinical/ePHI/device/facility/vendor dependencies, ransomware, identity, downtime, emergency access, restoration, reconciliation and safety outcomes | Synthetic hospital digital twin with fictitious patients and inert incidents |
| Aircraft system safety and development assurance | ARP4754B/ARP4761A function/requirement/item trace, DALs, FHA/PSSA/SSA, common causes, tool qualification, security interaction and change impact | Licensed-criteria no-egress assessment workspace with no flight actuation or certification credit |
| ILAC laboratory operating assurance | Proficiency participation, assigned values, metrological traceability, uncertainty, competence, impartiality, decision rules and corrective action | Blinded controlled interlaboratory workspace with no accreditation claim |
| Maritime operational cyber resilience | IMO/IACS ship-shore-port-supplier scope, inventories, operational modes, safety-management controls, cyber incidents, fallback, restoration and reconciliation | Inert ship/shore digital twin with no production vessel actuation |
| Weakness and prioritization temporal calibration | Complete CWE hierarchy and multi-label policy, project/time holdouts, duplicate controls, point-in-time EPSS/KEV, exploit outcomes, recall-at-budget, effort and delay | Immutable no-egress analytics workspace with a strict future-data firewall |
| Formal-method tool disagreement assurance | SV-COMP, Test-Comp, RERS and CHC tasks, independent witness/test validation, resource limits, parser/UB/timeout/OOM cases and solver disagreement | Resource-capped disposable solver and validator workers |
| Process/supplier assessor outcome calibration | Blinded ISO 33020/27036 assessment, completed-project outcomes, fourth parties, concentration, substitution, exit, defect escapes, incidents and recovery | Read-only licensed-criteria workspace with deidentified outcomes and synthetic supplier incidents |
| Incident/privacy outcome exercise calibration | Incident containment and recovery joined to PIA data-flow, individual impact, notification, residual risk, service restoration and reassessment outcomes | Synthetic tabletop and service twin with no real notification or personal data |
| CISA SCuBA SaaS posture | M365/GWS tenant coverage, read-only findings, exceptions, remediation, drift, and rescans | Least-privilege read-only tenant lane |
| CIS Kubernetes and Pod Security Admission | Automated/manual Kubernetes 2.0.1 checks plus privileged/baseline/restricted and enforce/audit/warn admission behavior, applicability, OS semantics, controller templates, bypasses, exceptions, drift and rescans | Disposable version-matched clusters plus immutable production snapshots |
| LINDDUN privacy threat modeling | DFD completeness, threat elicitation, mitigations, omission mutations, and assessor agreement | Blinded deidentified assessment workspace |
| OWASP Benchmark AST modality comparison | Matched SAST, DAST, and IAST precision/recall, overlap, latency, and capability boundaries | Separate matched-corpus runners |
| RASP prevention effectiveness | Attack block/observe/bypass, false positives, latency, health, tamper, and fail-mode behavior | Disposable instrumented application |
| GSMA NESAS/3GPP SCAS | Development-process and product security test assurance with laboratory authority and retest | Authorized segmented telecom laboratory |
| TISAX/VDA ISA | Scope, protection needs, maturity, findings, follow-up, assessor agreement, sharing, and label boundaries | Blinded licensed-criteria workspace |
| C2PA content credentials | Manifest/signature/trust validation, round trips, edits, revocation, tamper, and parser limits | Synthetic-media test-trust laboratory |
| PCI/EMV payment acceptance | MPoC/P2PE/PIN/PTS POI/3DS components, flows, PIN and key blocks, dual control, HSMs, SRED, ACS/DS/3DS Server messages, tamper, recovery and claim limits | Authorized synthetic-data and test-key payment laboratory |
| ECSS space software product assurance | Flight/ground software criticality, lifecycle trace, independent assurance, reuse/COTS, supplier, tools, coverage, reviews, anomalies, configuration, delivery and acceptance | No-egress synthetic mission-software project with inert models |
| Regional financial technology resilience | APRA/MAS applicability, critical operations, tolerances, material providers, technology controls, incidents, outages, recovery, reconciliation and board evidence | Synthetic financial-service digital twin with no regulator connectivity |
| Secure information sharing and competence | Community agreements, classification, TLP/IEP handling, forwarding/withdrawal, privacy, competence, agreement, bias, drift and economic-decision outcomes | Blinded synthetic multi-organization assessment workspace |
| SEMI fab-equipment cybersecurity | E187 hardening, E188 malware-free integration, E191 status reporting, service custody, monitoring, substitution and known-good recovery | No-egress inert fab-equipment twin with test software, media, certificates and service identities |
| API 1164 pipeline control resilience | Pipeline IAC architecture, essential commands/telemetry, remote access, manual/degraded operation, safety invariants and state reconciliation | Inert hydraulic and control-system twin with no production connectivity or actuation |
| GxP Part 11 data integrity | System validation, access and authority checks, audit trails, signature-record linking, retention, copies, migration and restoration | Synthetic regulated workflow with no real regulated records |
| FBI CJIS security policy | Agency/CJI scope, agreements, personnel, identity, encryption, audit, cloud/mobile, incidents, retention and sanitization | Synthetic CJI environment with no operational agency connection |
| Automotive SPICE capability | PAM process outcomes, practices, information items, work products, sampling, capability ratings and cybersecurity traceability | Blinded licensed-criteria workspace with independent adjudication |
| IEC 61511 SIS assurance | Hazard/SIF/SIL/SRS trace, SIS architecture and program, demand response, proof testing, bypass, fault injection and recovery | Inert process and SIS twin with independent functional-safety observer |
| BACnet Secure Connect | Node/hub/certificate identity, mutual authentication, authorization, segmentation, failover, legacy gateway and safe fallback | Inert building-automation twin protected from occupied and life-safety systems |
| Industrial robotics safety-security | Robot/cell/mobile scope, modes, stops, speed/space limits, zones, routes, human interaction, command/sensor faults and homing | Deterministic simulator or guarded reduced-energy physical safety cell |
| Data-centre facility resilience | Facility classes, topology, power, cooling, cabling, fire, access, monitoring, cascading faults, resilience KPIs and restoration | Validated facility digital twin with synthetic loads and telemetry |
| FedRAMP 20x continuous validation | Class rules, security goals, measures, KSIs, validation code, evidence freshness, boundary drift, Marketplace status, and agency-decision limits | Authorized read-only cloud evidence workspace |
| FIDO2 authenticator conformance | CTAP 2.2/WebAuthn transports, credentials, UV/PIN, malformed CBOR, downgrade, replay, MDS freshness, status, and recovery | No-egress test-authenticator laboratory |
| EUDI wallet functional conformance | ARF 3.0.0/FCAF issuance, presentation, wallet-to-wallet, trust lists, consent, minimization, replay, recovery, and privacy | Synthetic cross-wallet laboratory |
| HITRUST CSF assessment | Licensed 11.8.0 e1/i1/r2 scope, inheritance, samples, maturity, assessor agreement, QA, corrective action, validity, and claims | Blinded licensed assessment workspace |
| PCI Secure Software Framework | Secure Software 2.0/Secure SLC 1.1 product, SDK, module, lifecycle, delta, vulnerability, attestation, and listing evidence | Authorized synthetic-payment software laboratory |
| NIS2 implementing regulation | Applicability, technical measures, evidence effectiveness, incident thresholds/timing, supply chain, continuity, exceptions, and legal/guidance boundaries | Synthetic notification and service exercise |
| NIST supplier due diligence | Supplier ownership, provenance, dependencies, authoritative sources, contradictions, contract decisions, monitoring, exit, aliases, and deception | Blinded immutable-source workspace |
| OWASP SAMM assessment benchmark | SAMM 2.1 scope, quality criteria, maturity evidence, assessor agreement, roadmap, reassessment, cohort privacy, and representativeness | Blinded privacy-protected assessment workspace |
| OSS-CRS CRSBench | Repeated autonomous vulnerability discovery, proof validation, patch correctness, functional regression, holdout leakage, budgets, and confidence bounds | Authorized no-egress disposable challenge workers |
| OpenSSF Security Insights | Released schema, repository/revision identity, expiry, future-version quarantine, source provenance, and consumer-query behavior | Read-only immutable repository snapshots |
| GUAC interoperability | CycloneDX/SPDX/SLSA/VEX/Scorecard ingestion, identity reconciliation, golden graph queries, source provenance, and loss-bounded round trips | Disposable no-egress supply-chain graph |
| gittuf source policy | Root and delegation thresholds, reference-state authorization, transparency-log replay, rollback, fork, downgrade, and recovery | Disposable Git repository using test-only keys |
| OpenSSF Package Analysis | Runtime file/process/network/command behavior across protected malicious, clean, delayed, environment-sensitive, and evasive fixtures | Authorized disposable malware-analysis laboratory |
| OWASP Kubernetes Top 10 | Exact 2025 risk coverage, manifest/admission/runtime/recovery evidence, safe mutations, bypasses, and reviewed non-applicability | Disposable synthetic Kubernetes cluster |
| OWASP CI/CD Top 10 | Exact v1 risk coverage across forge, identity, source, runner, secret, artifact and deployment boundaries with safe attack mutations | Isolated synthetic forge and pipeline |
| SBOMit build-observed SBOM | Signed witness replay, source/builder/subject binding, filesystem/process/network observation, declared-observed reconciliation, omission and tamper cases | No-egress reproducible build workers |
| PrimeVul real-world vulnerability detection | Deduplicated vulnerable/fixed pairs, label audit, project/time holdouts, training-overlap checks, CWE strata, and confidence bounds | Protected no-egress source-analysis workers |
| DiverseVul unseen-project generalization | Project-disjoint evaluation, near-duplicate analysis, sampled fix replay, protected labels, and unseen-project limits | Protected no-egress source-analysis workers |
| CVEfixes chronological validation | CVE alias reconciliation, parent/fix replay, future-data exclusion, language/CWE strata, and chronological holdouts | No-egress repository replay workers |
| OWASP Mobile Top 10 | Exact 2024 risk coverage mapped to MASVS/MASTG plus source, binary, emulator/device, privacy, and behavioral mutations | Disposable mobile laboratory |
| OWASP Smart Contract Top 10 | Exact 2026 risks, SCWE/SCSTG traceability, SmartBugs, state/economic invariants, inert exploit replay, and upgrade/oracle cases | Disposable local chain with synthetic assets |
| CNCF cloud-native controls | Develop/distribute/deploy/runtime control closure, NIST mapping validation, architecture evidence, safe control-loss mutations, and CIS/Kubernetes reconciliation | Disposable synthetic cloud-native environment |
| ReposVul repository context | Repository/file/function/line labels, untangled and stale-patch audit, dependency graphs, fix replay, deduplication, contamination analysis, and project/time holdouts | Protected no-egress immutable repository workers |
| VulEval repository dependency evaluation | Separate function-detection, dependency-prediction, and repository-detection tasks with interprocedural cases and independently replayed dependency oracles | Protected task-separated repository workers |
| MITRE EMB3D 2.0.2 | Device-property inventory, property-to-threat and threat-to-mitigation mappings, STIX round trip, residual-risk review, and mapping mutations | No-egress synthetic embedded-device model worker |
| OWASP Business Logic Abuse Top 10 | Exact ten-risk coverage with state-machine, concurrency, idempotency, authorization, artifact-lifetime, quota, and termination mutations | Disposable stateful application with synthetic identities and assets |
| CNCF Supply Chain Best Practices v2 | Producer/consumer/operator responsibilities, source-to-operation lifecycle, SSDF/SLSA/S2C2F mapping, provenance and tamper mutations, and applicability closure | Disposable synthetic software factory |

| Water-sector cyber resilience | AWWA/EPA utility scope, process and public-health invariants, OT and supplier controls, adverse cyber-physical cases, manual operation, sampling and deterministic restoration | Inert treatment and distribution digital twin with independent process/public-health observers |
| `ransomware-resilience-exercise` | Govern-through-recover scope, inert encryption/exfiltration and identity/key-loss cases, offline/immutable backup integrity, detection and containment latency, restoration, business reconciliation, residue and retest | Disposable enterprise twin with synthetic identities/data; no live ransomware, production disruption or resilience certification claim |
| `media-sanitization-verification` | Clear/purge/destroy/cryptographic-erase applicability, key dependencies, command results separated from residual-data sampling, virtual/cloud cases, custody, certificates and failed-method rework | Dedicated disposable-media laboratory using synthetic data and keys; no production media destruction or product certification claim |
| `ot-backup-remote-access-recovery` | PLC/HMI/historian/engineering/identity/configuration dependencies, backup fidelity, restoration order, session approval/recording/revocation, kill switch, safe fallback and reconciliation | Inert OT/water twin with bounded effects, emergency stops and no production connectivity or actuation |
| `iec-62443-service-provider-evaluation` | Licensed 6-1/2-4 criteria, evaluator competence and independence, sampling, evidence sufficiency, nonconformity grading, blinded golden and mutated cases, agreement, adjudication and retest | Licensed protected assessment workspace; no provider modification or IEC conformity/certification claim |
| `crisis-exercise-assurance` | Protected objectives, scenarios and injects, leadership and decision latency, information quality, ethics, communications, participant welfare, independent evaluation, corrective owners and retest | Synthetic exercise only; no live emergency/public communication or ISO certification claim |
| `enterprise-ict-risk-aggregation` | Risk-to-service/mission trace, appetite and tolerance, correlations, concentrations, cascading loss, stale/hidden/duplicated risks, machine-readable lineage and independent re-performance | Synthetic protected risk registers; no confidential production register or enterprise-risk certification claim |
| `standards-crosswalk-semantic-conformance` | Edition and identifier locks, directional relationship types, provenance, rationale, confidence, positive/negative mappings, reversal/staleness/overclaim/drift mutations and lossless round trips | Source-pinned licensed/public standards workspace; no reproduction of licensed normative text or standards-equivalence claim |
| `lng-ev-charging-sector-resilience` | LNG terminal/vessel/support and EV/charger/cloud/building/utility maps, safety and service oracles, cyber-physical fault cases, recovery and reviewed CSF-version mappings | Inert digital twins; no production infrastructure actuation, sector certification or native-CSF-2.0 source-profile claim |
| NG911 and P25 public-safety communications | NG-SEC audit criteria, i3 message/location/routing semantics, P25 identity/key/interoperability, overload, site loss, dispatch failover and recovery | No-egress NG911/P25 laboratory using synthetic calls, locations, dispatch and RF-shielded or simulated radio traffic |
| Global GxP data integrity | Annex 11, WHO and PIC/S lifecycle, ALCOA+, metadata, audit trails, signatures, suppliers, continuity, migration, inspection reconstruction and mutations | Synthetic multinational regulated workflow with independent quality review and no real patient or regulated data |
| Transit cybersecurity resilience | Final IR 8576 mission and CSF outcomes, rail/bus/station/fare/passenger-information/operations dependencies, safe degraded operation and recovery | Inert multimodal transit digital twin with independent safety and operations observers |
| Emergency incident coordination | ISO 22320 authority, common operating picture, information quality, decisions, resources, communications, handoffs, cascading injects and after-action closure | Synthetic multi-organization exercise with protected injects and independent observers |
| Gas-SCADA cryptographic assurance | Endpoint/channel/key binding, forgery, replay, reorder, delay, downgrade, rollover, clock and partition cases plus manual control and recovery | Inert gas pipeline and protocol twin with independent safety and cryptographic observers |
| Water OT research-corpus calibration | License/source binding, duplicate and contamination audit, temporal/facility/attack/clean/physics holdouts, label quality, detection latency, false positives and generalization | Protected no-egress SWaT/WADI/BATADAL research evaluation; never a compliance, product or operational-safety claim |

The maintained 212-adapter catalog in `py_security_suite.benchmark_adapters`
defines acquisition, license, input, normalizer, positive/negative control, and
isolation requirements for CFReDS/CFTT, ACT Rules, DroidBench, Ghera,
SecBench.js, Chaos Mesh/Litmus, Sonobuoy, CIS-CAT/SCAP, Wycheproof, TIBER-EU,
OpenCRE/Gemara/OSCAL, CBEST, OCP S.A.F.E./SOLID,
DOE C2M2, FINOS CCC, NCSC CRT/CRTF, NIST PRAM, licensed ITIL 4,
NIST Dioptra, ransomware resilience, media sanitization, OT backup and remote
access, IEC 62443 provider evaluation, crisis exercises, enterprise ICT risk,
crosswalk semantics, LNG/EV resilience, firmware/device provenance and TPM resilience, Kubernetes Pod
Security Admission, PCI/EMV PIN/POI/HSM/3DS, ECSS software assurance, regional
financial resilience, secure information sharing and competence, access-control policy models,
differential privacy, evaluator calibration, SQuaRE measurement, exact
ISO 29119 testing, quality-in-use/cloud, risk calibration, TLS, reproducible
builds, secure-by-design negative testing, AMTSO malware protection, DICE,
telecom, NICE workforce coverage, penetration-test engagement quality, and
DORA delivery outcomes, structured assurance cases, integrity-level V&V,
CMVP and international cryptographic-module conformance, biometric performance
and PAD, integrated service/security management, interlaboratory proficiency,
HarmBench, AgentHarm Inspect Evals, garak, OWASP Cornucopia, Microsoft PyRIT,
OWASP AISVS, EUCC, CISA secure-software attestation, NIST CSF profile
reassessment, and separate MLCommons AILuminate Safety and Jailbreak contracts.
The 116 suite-owned semantic integrations add a strict evidence
envelope: bounded duplicate-key-safe JSON, exact fields, lowercase SHA-256
source and subject binding, isolated execution and network policy, verified
producer signature and independent replay, at least two detected negative
cases, and domain-specific semantic claims. The real-world vulnerability
adapters additionally require independent label audits, exact and near-duplicate
analysis, training-overlap assessment, project and chronological split
manifests, sampled fix replay, CWE-stratified metrics, and confidence bounds. A
generic successful exit or an upstream-generated score cannot satisfy this
boundary.
The CIS cloud/Docker, OWASP GenAI red-team, AI Verify/Moonshot, NCSC CHECK,
AIUC-1 and CSA IoT integrations enforce exact edition/profile, authorization,
manual-check, component/capability, test, exception, cleanup, restoration,
retest and issuer-bound claim semantics. The C2M2, FINOS CCC, NCSC CRT, PRAM
and ITIL 4 integrations enforce exact
model/catalog/criteria identity, applicability, ownership, source and subject
binding, assessor disagreement, negative cases, remediation and reassessment;
they cannot imply publisher endorsement, legal compliance, accreditation or
certification. The OpenCRE/Gemara, CBEST, OCP S.A.F.E., ransomware, sanitization, OT recovery,
provider-evaluation, crisis, enterprise-risk, crosswalk and LNG/EV integrations enforce recovery order,
residual-data verification, assessor agreement, strategic decisions, portfolio
aggregation, directional mapping semantics, CSF-version boundaries and retest.
The water, public-safety communications, global GxP, transit, emergency
coordination, gas-SCADA and water-research integrations enforce process,
message, radio, record, service, command, cryptographic, label, contamination,
holdout and recovery semantics. SWaT, WADI and BATADAL remain research-only:
they cannot become standards, compliance evidence or production-safety proof.
The semiconductor, pipeline, GxP, CJIS, Automotive SPICE, SIS, BACnet,
robotics and data-centre integrations enforce exact equipment, process,
record, information, safety and facility claim sets plus production-isolation
and no-certification boundaries. The firmware, Kubernetes, payment, ECSS,
regional-financial and secure-sharing integrations enforce device/component
provenance, admission decisions, key and transaction boundaries, lifecycle
traceability, critical-operation outcomes, handling policy and
assessor-calibration claims. The STIG, IEC patch,
continuing-airworthiness, Swift, and CCSDS integrations
now enforce exact domain claim sets in addition to adapter inputs: release and
criteria editions, complete applicability dimensions, independently replayed
disagreement or adverse cases, longitudinal or recovery outcomes, and explicit
false claims for production mutation, actuation, connectivity, authorization,
certification, or compliance. Missing or extra domain fields fail closed.
ReposVul and VulEval additionally require immutable repository snapshot
manifests, dependency-context oracles, tangled-patch audits, multi-granularity
label maps, and task-specific reporting. EMB3D, Business Logic Abuse, and CNCF
supply-chain conformance require exact model or taxonomy identity, complete
mapping/applicability evidence, detected safe mutations, and independent
replay; none of these outcomes is a certification.
The vulnerable-application adapters bind target release or image, authoritative
challenge and clean labels, route/state coverage, reset proof, two-identity
authorization replay, and a complete no-egress transcript. ASTF 2.0.1 adds
cross-target REST, GraphQL, gRPC, mTLS, and LLM-assisted protocol evidence
without inheriting upstream completeness claims. Statistical fuzzing requires
matched resources and toolchains, raw per-trial data, seed and dictionary
manifests, replayable crash oracles, deduplication, baseline and deliberately
broken controls, and exact repetition floors: 20 for FuzzBench, 10 for Magma,
and 3 for ClusterFuzzLite. SBOM build truth reconciles source declarations with
resolver, build, installed-artifact, and layer observations across at least
three ecosystems. Architecture fitness requires exact seeded cycle, layering,
unstable-dependency, change-coupling, ownership-concentration, and drift
mutations. Temporal EPSS/KEV backtesting requires three or more ordered dated
snapshots, as-of joins, alias reconciliation, future-data exclusion, censoring,
calibration, operational budgets, and time-shift controls.
AuthZEN, OpenID Federation, ISO/IEC 24760, SCIM, SSF/CAEP/RISC, and SPIFFE
integrations add exact final-spec identity,
synthetic tenant and trust-domain boundaries, lifecycle and stream state,
authorization, subject, replay, cursor, rotation, revocation, bundle, and
federation oracles. The official OpenID SSF conformance program is recorded as
alpha, and the experimental remote SPIFFE Workload API is excluded from stable
claims. OpenSSF Model Signing and CycloneDX ML-BOM integrations bind official
schemas and vectors, complete multi-file manifests, signer identity, model
cards, datasets, dependencies, provenance, round trips, omissions, path and
tamper cases while explicitly separating integrity/inventory from model safety,
fairness, quality, and fitness. Uptane 2.1.0 uses inert firmware and a simulated
fleet with Director/Image repositories, full and partial verification ECUs,
POUF, secure-time, rollback, freeze, mix-and-match, compromise and recovery
oracles. AIxCC-style evaluation requires an organization-approved immutable
corpus and scoring pipeline, protected splits, license and contamination
manifests, repeated resource-bounded trials, and independent proof, patch, and
functional replay; fragmented public material is never presumed ready.
OpenSSF Criticality Score is reproducible and temporally calibrated context
only, never a security pass/fail or vulnerability-likelihood signal.
The HPC integration requires the final SP 800-223 architecture and exactly 60
SP 800-234 overlay controls while excluding draft SP 800-239. The TR 5259-6
integration requires reproducible, accessible data-quality visualizations and
misleading-presentation mutations while explicitly prohibiting conformance or
certification claims from Technical Report guidance.
It also defines fail-closed adapters for MCP clients/servers/proxies, AWS FSBP,
MCSB/Defender, Google Enterprise Foundations/SCC, FIRST CSIRT/PSIRT maturity,
memory-safety engineering, IEEE AI governance and well-being, resilience/BIA
exercises, OpenSSF badge recomputation, ISMS process assessment, A2A 1.0,
SESIP/EN 17927, FIRST TLP/IEP, VERIS, CSP2/SRI1, DORA Level 2 technical acts,
FFIEC IT Handbook assessment, BSI C5, and FCC Cyber Trust Mark conformance.
The current tranche adds FedRAMP 20x, FIDO2, EUDI Wallet, HITRUST 11.8,
PCI Secure Software 2.0/Secure SLC, NIS2 implementation, NIST SP 1326, and
OWASP SAMM adapters, and promotes maintained contracts for OWASP Benchmark,
Juliet, ACVP, WPT WebAuthn, STIG/SCAP, Sigstore, SLSA, SV-COMP, Test-Comp,
ATT&CK Evaluations, Atomic Red Team, Defects4J, SWE-bench Verified, Vul4J,
BugsInPy, and OpenSSF Scorecard. Candidate CTAP 2.3 and EUCS, EUMSS, EUDIW,
and EU5G certification schemes remain in the non-normative publisher watchlist.
It deliberately does not vendor licensed content, organization targets, or
floating upstream branches.

The new adapters retain domain-specific safety boundaries. TLS runs are
loopback-only and use no production credentials. Malware-control evaluation
starts with harmless EICAR and permits only approved inert fixtures unless a
separately governed malware laboratory supplies stronger authorization,
containment, destruction, and restoration evidence. Penetration-test quality
assessment cannot authorize an engagement: it requires pre-existing signed
scope and rules of engagement, target allowlists, kill switches, cleanup, and
restoration proof. DORA metrics are research-backed operational outcomes, not
security certification, and CISA/CREST/PTES/Reproducible Builds publications
remain typed as guidance even though their measurable procedures are governed.
AISVS and AILuminate model tests require no-egress disposable targets,
synthetic identities and data, protected-split separation, scorer-manipulation
tests, bounded cost and authority, harmful-output quarantine, kill switches,
reset, and destruction proof. EUCC and federal attestation adapters are
verification-only: they cannot issue certificates or sign producer claims.
A2A, web, information-sharing, and regulatory adapters use synthetic parties,
origins, incidents, registries, and supervisory channels; SESIP, C5, FFIEC,
DORA, and FCC claims remain bounded to the applicable external scheme,
qualified party, and legal scope.
AST modality results are never collapsed into one union score: SAST, DAST, and
IAST retain separate identities and confusion matrices, while RASP uses the
detection/effectiveness protocol because prevention behavior is not a static
finding-classification claim. C2PA validity is also kept separate from content
truth, and all PCI, TISAX, NESAS, OpenID, and CIS outcomes retain external
authority and certification or label boundaries.

External vulnerable applications are never executed by the core scanner. Each
enabled family gets a runner contract naming its adapter, expected labels,
minimum repetitions, required execution evidence, score semantics, and whether
a disposable target is mandatory. The generated task remains a plan until a
separately authorized lane executes it. A benchmark declaration can name an
`adapter_manifest`; that switches its generated task from report-only scoring
to `benchmark-run`. The generated command intentionally omits
`--authorize-execution`, so registry generation cannot grant execution authority.

### Executable adapter contract

For maintained adapters, start from the schema
[`benchmark-preparation-request-1.0` example](../examples/benchmark-preparation-request.example.json)
and let the compiler bind the
registry version, lane, protocol, adapter-spec digest, required inputs, corpus,
and executable identities:

```shell
pysec benchmark-prepare security/benchmark-requests/droidbench.json \
  --workspace .artifacts/droidbench-workspace \
  --output security/benchmark-adapters/droidbench.json
pysec benchmark-runtime-probe /usr/bin/docker \
  --runtime-sha256 APPROVED_RUNTIME_SHA256 --runtime-name docker \
  --runtime-version APPROVED_RUNTIME_VERSION --authorize-execution \
  --output .artifacts/docker-capabilities.json
```

The compiler does not fabricate independent evidence. After the subject digest
is known, trusted authorities issue and sign the referenced acceptance-criteria,
adapter-conformance, runtime-observation, time, replay, contamination, SBOM,
provenance, environment, external-isolation, and cleanup attestations. Schema
1.2 requires role-correct, lifecycle-bounded authority envelopes with revocation
state, at least four distinct signer keys and two organizations, and declared
key/organization separation groups. High-risk `authorized-companion` contracts
reject process mode, inherited networking, non-disposable targets, and missing
cleanup stages.

For frozen legacy integrations, start from
[`benchmark-adapter-manifest.example.json`](../examples/benchmark-adapter-manifest.example.json)
and replace every placeholder with approved, immutable evidence. The runtime
requires an absolute executable path and SHA-256 for every stage, a digest-bound
corpus, license and label-authority digests, organization approval, runner SBOM
and provenance attestations, replay and trusted-time receipts, contamination evidence,
and an exact normalized-result location.

```shell
pysec schema benchmark-adapter-manifest-1.0 > benchmark-adapter.schema.json
pysec schema benchmark-adapter-manifest-1.1 > benchmark-adapter-1.1.schema.json
pysec schema benchmark-adapter-manifest-1.2 > benchmark-adapter-1.2.schema.json
pysec benchmark-run security/benchmark-adapters/droidbench.json \
  --workspace .artifacts/droidbench-workspace \
  --authority-trust-policy /etc/pysec/benchmark-authorities.json \
  --authority-trust-policy-sha256 APPROVED_POLICY_SHA256 \
  --authority-trust-policy-signature /etc/pysec/benchmark-authorities.sig \
  --authority-trust-root /etc/pysec/benchmark-authority-root.pem \
  --authority-trust-root-sha256 APPROVED_ROOT_SHA256 \
  --trusted-time-context /var/lib/pysec/benchmark-time-context.json \
  --trusted-time-context-sha256 APPROVED_TIME_CONTEXT_SHA256 \
  --replay-ledger /var/lib/pysec/benchmark-replay.sqlite3 \
  --replay-checkpoint-state /var/lib/pysec/benchmark-replay-checkpoint.json \
  --receipt-signing-key /run/secrets/benchmark-receipt-key.pem \
  --receipt-signing-key-sha256 APPROVED_RECEIPT_KEY_SHA256 \
  --authorize-execution \
  --output .artifacts/droidbench-execution.json
```

Use `--initialize-replay-checkpoint` only during an explicitly approved first
enrollment. The retained state is signed, bound to the ledger location, checked
before nonce consumption, and atomically advanced after consumption. Schema 1.2
first persists a signed intent, requires the retained checkpoint to be the live
ledger head, holds a cross-process operating-system lease for the complete
transition, and recovers only one exact matching advance after interruption.
Scorecard admission is a separate trust decision: policy 1.3 cannot declare
receipt authorities. The relying deployment supplies a root-signed, expiring,
digest-pinned authority policy outside the workspace through the five
`PYSEC_INDUSTRY_RECEIPT_AUTHORITY_*` settings. Active `execution-receipt` entries
are evaluated at receipt completion, so repository content and receipt-controlled
public keys cannot bootstrap downstream authority.

The preferred deployment authority file follows
[`benchmark-authority-trust-policy-1.1`](../src/py_security_suite/schemas/benchmark-authority-trust-policy-1.1.schema.json);
the repository includes a non-secret
[`example`](../examples/benchmark-authority-trust-policy-1.1.example.json). Its
approved digest, root signature, trusted-time context, replay checkpoint, and
receipt signer are deployment inputs, not manifest or workspace inputs. They
must resolve outside the benchmark workspace and should be protected by the
orchestrator's service-account ACLs. Policies expire within 31 days; public-key
identities hash canonical raw Ed25519 keys rather than serialization bytes.
Schema 1.1 binds key versions, activation/retirement windows, and revocation time;
the relying party evaluates the receipt completion time against those fields.

Each evidence reference names an artifact, digest, detached Ed25519
signature, and pinned public key. The runner verifies the signature and exact
benchmark subject (corpus, binaries, versions, protocol, and isolation policy),
then validates kind-specific claims and their cross-bindings. Acceptance must
bind the exact criteria, thresholds, protocol, and pre-registration; conformance
must bind the adapter spec, executable, normalizer, at least three golden,
malformed, and label-inversion fixtures, deterministic repetitions, the complete
fixture-set digest, and a named, digest-pinned semantic oracle; runtime
observation must bind the isolation mode,
target, image, network/resource controls, repetitions, power/leakage/duplicate
checks, and sequestered holdout. Replay protection is true only when the signed
receipt records a consumed unique nonce, that nonce is atomically consumed in
the deployment SQLite ledger, and its SHA-256 chain reproduces the retained
deployment checkpoint. Every signer must also match an active,
role-specific Ed25519 key, organization, and revocation-state digest in the
deployment policy. CycloneDX/SPDX SBOM subjects, DSSE Ed25519 envelopes over
canonical in-toto/SLSA v1 provenance with a signed complete-material-set digest
and count, repeated conformance outcomes, per-repetition runtime
observations, and two independent cleanup probes are replayed from digest-bound
documents rather than accepted as signed booleans alone. Advanced RFC 3161 time
is replayed from the raw receipt, pinned TSA chain, policy, revocation snapshot,
nonce, challenge, and deployment monotonic state. Power is recomputed with a
protocol-selected exact equal-tail two-sided binomial or standardized-mean model, explicit
Bonferroni adjustment, and a digest-verified preregistered analysis-plan document.
Training/holdout leakage, duplicate-case, and
training-corpus contamination are derived from the actual bounded corpus files
with material-digest-pinned Python/tree-sitter parsers; supplied semantic digests
must reproduce and cannot substitute for the files. Bounded multi-signal Jaccard
analysis combines AST structure, normalized lexical/operator sequences, and
control-flow features to reject high-similarity near-duplicates across languages.

Maintained adapters can use `run_adapter_conformance_suite` to produce a
multi-fixture qualification report by executing their real normalizer at least
three times. Golden, malformed, and label-inverted fixture classes each require
at least three cases; malformed parsing and semantic inversion are evaluated by
separate controls. The compatibility `run_adapter_conformance` helper remains
available for frozen single-fixture contracts. Each canonical golden output must
match its approved oracle, and a metadata-only declaration cannot produce a
passing report.

Commands are argument vectors, never shell strings. The runner verifies the
executable immediately before each stage, supplies a minimal environment,
disables stdin, bounds execution time and captured output, terminates child
process trees on timeout, validates unique normalized case identities, computes
accuracy metrics, applies thresholds, and emits an atomic digest-bound receipt.
After cleanup it rehashes the manifest, all attestation/signature/key material,
claim-referenced evidence, corpus, adapter inputs, and executables. Any mutation
or disappearance changes the decision to fail.
Schema 1.1 additionally rejects statistically insufficient or unbalanced samples
using protocol-specific floors and strata, rejects confidence intervals wider
than policy, and compares minimum metrics against Wilson lower bounds and maximum
error/attack rates against Wilson upper bounds. Its canonical receipt is consumed
directly by the industry scorecard without a hand-authored translation layer.
`process` isolation can claim only inherited network behavior. Before `oci`
execution, the runner actively probes the digest-pinned runtime version and
required containment options and binds the probe-output digests into the signed
receipt. It then starts a preloaded image with `--pull=never`, a read-only root filesystem, all Linux
capabilities dropped, no-new-privileges, denied networking, non-root identity,
bounded CPU/memory/PIDs/open files/core dumps, an init process, a no-exec
temporary filesystem, digest-pinned optional seccomp and named AppArmor
profiles, a read-only workspace and corpus, a single initially empty writable
`.pysec-output` mount with byte and file-count ceilings, explicit container-path
environment variables, and automatic container removal. A
target-restricted network claim requires a separately verified sandbox receipt.

The Linux CI matrix supplies Docker and rootless Podman through
`PYSEC_TEST_OCI_RUNTIME` with a digest-pinned `PYSEC_TEST_OCI_IMAGE` and
mandatorily verifies actual non-root, zero-capability, read-only-root,
no-exec-temporary-filesystem, isolated-network behavior against the immutable image.
Receipt signing is provider-neutral in the Python API: deployments can inject a
`ReceiptSigningProvider` backed by PKCS#11, an HSM, or a KMS. The included
`ExternalEd25519SigningProvider` is a digest-pinned, no-shell vendor bridge that
passes payloads on standard input and verifies returned signatures locally. Provider identity
and key version are cryptographically protected, and the returned Ed25519 public
key must remain admitted by the root-signed authority policy. The CLI retains a
digest-pinned local PEM provider for compatible offline deployments.

Audit JSONL records carry a cross-process global sequence in addition to their
hash link and fsync durability. `sign_security_event_log_head` creates an
HSM/KMS-compatible signed checkpoint whose signer is independently pinned by the
retaining party; subsequent verification rejects log replacement, truncation,
untrusted signers, or a broken anchor chain.

The normalized adapter output is deliberately small and tool-neutral:

```json
{
  "schema_version": "1.0",
  "benchmark_id": "droidbench",
  "protocol": "classification",
  "cases": [
    {
      "id": "Callbacks_Button1",
      "expected_positive": true,
      "observed_positive": true,
      "strata": {"category": "callbacks", "language": "java"}
    }
  ]
}
```

### Publisher lifecycle monitor

The compiled catalog and source manifest can be produced deterministically:

```shell
pysec assurance-catalog-export --output .artifacts/assurance-catalog.json
pysec standards-manifest-build security/standards-baselines.json \
  --output .artifacts/standards-source-manifest.json
```

The catalog export carries a digest for every component and the complete
catalog. The manifest builder verifies every selected local publisher baseline,
derives the exact HTTPS host allowlist and profile/control impact map, and fails
closed on missing or digest-mismatched inventory records.

`standards-monitor` retrieves only explicitly allowlisted HTTPS publisher hosts,
rejects credentials, fragments, nonstandard ports, and non-public resolved
addresses, validates redirects, bounds each response and the overall run, and
writes digest-named observations into quarantine. A changed publisher payload
yields `review-required`; it never changes a normative baseline automatically.

```shell
pysec standards-monitor examples/standards-source-manifest.example.json \
  --output .artifacts/standards-monitor \
  --authorize-network \
  --signing-key security/standards-monitor-ed25519.pem

pysec standards-monitor-verify \
  .artifacts/standards-monitor/standards-monitor-report.json \
  --report-sha256 APPROVED_TRANSPORT_SHA256 \
  --public-key security/standards-monitor-ed25519.pub.pem
```

Optional Ed25519 signing binds the report to the exact manifest, observations,
decision, semantic diff, impact mapping, and promotion policy. The monitor
compares a digest-pinned local baseline using structural JSON paths, XML/HTML
sections, PDF pages, or normalized text lines; identifies added, removed, and
modified sections; classifies normative keywords and lifecycle language; and
emits affected profiles, controls, benchmarks, and a pending approval artifact.
Promotion still requires licensed-requirement review where applicable and named
human approval.

```mermaid
flowchart TB
    BaselineInventory["Verified local publisher baselines"] --> ManifestBuilder["standards-manifest-build<br/>complete inventory + digest verification"]
    CatalogExport["assurance-catalog-export<br/>component + whole-catalog digests"] --> Review
    ManifestBuilder --> Monitor
    Publisher["Allowlisted HTTPS publisher sources"] --> Monitor["standards-monitor<br/>bounded retrieval + quarantine + JSON/XML/HTML/PDF/text diff"]
    Monitor --> Review["Normative and lifecycle classification<br/>impact map + named human approval"]
    Review --> Catalog["663 pinned standards and taxonomies"]
    Catalog --> Crosswalk["standards-crosswalk.json + lifecycle ledger + watchlist"]
    Stable["Stable technical baselines<br/>VC/OpenID/FAPI | SCuBA/Kubernetes | LINDDUN/C2PA"] --> Review
    Evaluation["Evaluation and certification inputs<br/>SESIP/EUCC | NESAS/SCAS"] --> Review
    Sector["Conditional sector baselines<br/>DORA/FFIEC/C5/FCC | TISAX/PCI"] --> Review
    Drafts["71 non-normative watch items<br/>CRA drafts + AIVSS 0.8 + research previews<br/>CyAS MVP + CoSAI MCP candidate + retired FFIEC CAT"] --> Monitor
    Packs["233 assurance packs"] --> ProfileRegistry["assurance-profile-registry.json"]
    Policy["Policy 1.3: packs + controls + procedures<br/>protocol-specific thresholds"] --> Control["control-assessment.json"]
    ProfileRegistry --> Control
    Policy --> Procedure["procedure-assessment.json"]
    Evidence["Complete governed artifacts"] --> Control
    Evidence --> Procedure
    Authorization["Explicit execution authorization"] --> Procedure
    Crosswalk --> Control
    ThreatModel["Source-bound threat model<br/>assets + flows + boundaries + threats + controls + tests"] --> Foundation
    Evidence --> Foundation["Lifecycle + architecture + process + prioritization<br/>maturity + interoperability + conformity + assurance/threat graphs"]
    Foundation --> Control
    Control --> OSCAL["OSCAL 1.2.2 lifecycle package<br/>7 models"]
    Procedure --> OSCAL

    Findings["Normalized findings + KEV/EPSS/VEX"] --> Priority["CVSS v4 + SSVC<br/>no fabricated decisions"]
    Corpus["Pinned labels + revision + authority<br/>license + split + contamination manifest"] --> Compiler["benchmark-prepare<br/>registry-bound manifest 1.1"]
    RepositoryOracle["ReposVul + VulEval<br/>snapshot + untangled patch + dependency graph<br/>repository/file/function/line + task-specific labels"] --> Corpus
    AppLabs["Juice Shop + WebGoat + crAPI + ASTF<br/>pinned targets + labels + clean routes<br/>state reset + identities + no-egress"] --> Corpus
    FuzzLabs["FuzzBench 20x + Magma 10x + ClusterFuzzLite 3x<br/>matched resources + raw trials + crash replay"] --> Corpus
    TruthOracles["SBOM build truth + architecture fitness<br/>temporal EPSS/KEV snapshots"] --> Corpus
    Compiler --> InputGate["Structural input gate<br/>strict JSON + safe ZIP/TAR + size/ratio bounds"]
    InputGate --> Adapter["212 maintained adapters<br/>verified subject evidence + 11 protocol scorers"]
    Acceptance["Independent acceptance authority<br/>criteria + thresholds + pre-registration"] --> Adapter
    Conformance["Independent adapter authority<br/>golden + malformed + inversion + determinism"] --> Adapter
    RuntimeObserver["Independent runtime observer<br/>OCI + network + resources + repetitions + holdout"] --> Lane
    DeploymentPolicy["Deployment-owned trust policy<br/>active role + organization + Ed25519 key + revocation digest"] --> Adapter
    Adapter --> Lane["Authorized disposable benchmark lane<br/>synthetic agents/origins/incidents/entities/devices"]
    Qualification["Native digest-only OCI isolation<br/>read-only + no capabilities/network + resource limits<br/>signed SBOM/SLSA evidence"] --> Lane
    Target["Pinned benchmark target"] --> Lane
    Lane --> ExtensionGate["116 suite-owned semantic integrations<br/>source + subject digests | independent replay<br/>domain claims + at least 2 negative cases"]
    DomainOracle["CIS cloud/Docker | GenAI red team | AI Verify | CHECK | AIUC-1 | CSA IoT<br/>C2M2/FINOS CCC/NCSC CRT/PRAM/ITIL 4<br/>resilience/industrial/public-safety/research holdouts"] --> ExtensionGate
    ExtensionGate --> Replay["Deployment SQLite replay ledger<br/>outside workspace + atomic nonce uniqueness"]
    Lane --> Integrity["Post-run immutable-input rehash<br/>manifest + evidence + corpus + executables"]
    Integrity --> Report
    Replay --> Report["Checksum-verified suite report<br/>confidence-bounded metrics"]
    Report --> Evaluate["pysec benchmark"]
    Corpus --> Evaluate
    Evaluate --> Score["Replay-protected score evidence"]
    Score --> Scorecard["benchmark-scorecard.json"]
    Baseline["Approved prior scorecard"] --> Delta["benchmark-delta.json"]
    Scorecard --> Delta
```

The diagram separates four claim layers that must not be collapsed. A catalog
entry records a reviewed publication; a selected pack records applicability;
an adapter records how evidence must be acquired and normalized; the semantic
gate proves the normalized result is source-bound, subject-bound, replayed, and
negative-tested; and a passing score records only the pinned subject, corpus,
method, authority, and execution context. SESIP, EUCC, C5, FCC, DORA, and FFIEC outcomes remain external-scheme
or regulatory evidence and never become suite-issued certifications,
attestations, labels, examinations, or supervisory submissions.

A benchmark score is eligible to pass only with the pinned corpus digest,
organization-approved authority, corpus revision, replay protection, validated
time, verified report checksum, and the evidence required by its scoring
protocol. Classification uses a complete confusion matrix; temporal,
verification, test-generation, fuzzing, stochastic-adversarial,
assessor-agreement, biometric-performance, proficiency-testing, conformance,
and detection-evaluation protocols use typed
method-specific metrics plus digest-bound, organization-approved acceptance
criteria. Every authorized
companion run also requires dataset-license, label-authority, contamination,
runner identity, digest-pinned OCI image, verified and image-subject-bound runner
SBOM and provenance, enforced resource limits, target, environment, toolset,
oracle, enforced network policy, complete egress transcript,
isolation and target-destruction receipts, and positive/negative control
evidence plus an approved fixed, project, or time split. Organization-
pinned corpora require at least two independent reviewers. Stochastic LLM, AI,
and agent families require at least five repetitions; continuous fuzzing
requires at least three. Qualified DISA STIG, IEC 62443, architecture/process,
airworthiness, CCSDS space-mission, maritime, and SWIFT conformance lanes additionally require
digest-bound method validation, evaluator competency, impartiality review, and
measurement traceability. Temporal prioritization requires pinned EPSS, KEV,
and outcome snapshots plus future-data exclusion and calibration/budget metrics.
Formal competitions require task, witness or test-suite, and resource-limit
digests. Signing lanes require pinned suites, trust roots, identity policies, and
negative cases. Scale benchmarks require wall-time, peak-memory, and at least
three deterministic runs. Missing execution context fails the score rather than
being treated as a weak pass.

## Capability readiness scores

These scores measure framework readiness, not organizational conformance or
certification. A deployment earns the corresponding assurance only after its
applicable pack, evidence, procedures, authority, and benchmark thresholds pass.

| Area | Readiness | Basis |
|---|---:|---|
| Application security standards | 9/10 | Versioned catalogs, requirement policy, procedures, and retained evidence |
| SAST/DAST methodology | 9/10 | Static, dynamic, API, mobile, and authorized adversarial lanes |
| Software supply chain | 9/10 | SLSA/OpenChain/SPDX profile plus provenance, SBOM, signing, release evidence, and product/version-bound federal producer attestation with authorized-signatory and exception validation |
| Benchmark methodology | 9/10 | Eleven scoring protocols, typed metrics, independently signed acceptance criteria, strata, power/leakage/duplicate/holdout checks, conservative Wilson decisions, replay protection, and deltas |
| Benchmark execution governance | 9/10 | 282 task contracts plus explicit authorization, default registry enforcement, structural corpus validation, deployment-owned active-key admission with four-signer/two-organization separation, subject/cross-bound Ed25519 evidence, durable external SQLite replay receipts, strict claim schemas, independently replayed conformance/runtime/SBOM/SLSA/cleanup documents, post-run immutable-input verification, eleven protocol-specific scorers, 212 maintained adapters, digest-pinned argv-only stages and OCI runtime, read-only-workspace OCI execution, contamination checks, negative controls, and conditional laboratory qualification |
| CIS cloud and container configuration | 9/10 | Separate AWS 7.0.0, Azure 6.0.0, GCP 5.0.0 and Docker 1.8.0 edition/profile/recommendation identities, automated/manual semantics, inventory and responsibility scope, exceptions, drift, remediation, rollback, cleanup, independent replay and rescans without CIS certification claims |
| GenAI adversarial testing methodology | 9/10 | OWASP model, implementation, infrastructure and runtime campaigns with preregistered authority, multi-turn and indirect attacks, inert tools, state/scorer transcripts, clean controls, utility retention, restoration, remediation and attack-family retest |
| AI governance and agent evaluation | 9/10 conditional | AI Verify/Moonshot principle and technical-test evidence plus conditional AIUC-1 Q3 2026 capability applicability, recurring independent evals, change retest, uncertainty and publisher-only certification boundaries |
| UK penetration-testing assurance | 9/10 conditional | NCSC CHECK 1.1 provider/team registry and credential validity, customer authority, methodology, evidence custody, safety, reporting, cleanup, remediation and independent retest without inferred provider status or government acceptance |
| IoT component control assurance | 9/10 conditional | CSA IoT v2 device/gateway/network/cloud/mobile/operator allocation, data-flow and lifecycle trace, supplier/update/degraded-operation/recovery cases, semantic crosswalks and no product-certification boundary |
| Cybersecurity capability maturity | 9/10 | C2M2 2.1 IT/OT scope, all ten domains, practice-level evidence, maturity-indicator challenges, blinded assessor disagreement, risk-based investment, improvement ownership, longitudinal outcomes and explicit no-endorsement boundaries |
| Financial cloud control engineering | 9/10 conditional | FINOS CCC Core v2025.10 and service-catalog identity, capability-threat-control-assessment trace, cross-provider responsibility, OSCAL round trips, native finding reconciliation, configuration drift, semantic-loss reports and no-certification boundaries |
| Connected-product resilience testing | 9/10 conditional | NCSC CRT APC 1.0 and CRTF 1.1 principle-claim-argument-evidence chains, public-interface attacks, essential behavior, known-good recovery, evaluator independence, report provenance and NCSC approval boundaries |
| Privacy-risk assessment methodology | 9/10 | NIST PRAM and NISTIR 8062 data-action, problematic-action, individual-impact, population, likelihood, uncertainty, response-effectiveness and changed-context evidence with independent scoring and no legal-compliance claim |
| Service-management outcome alignment | 9/10 conditional | Licensed ITIL 4 criteria joined to ISO 20000/27013 service-value, change, release, incident, problem, supplier, continuity, security, restoration, recurrence and improvement outcomes without PeopleCert or practitioner certification claims |
| Semiconductor equipment cybersecurity | 9/10 conditional | SEMI E187/E188/E191 hardening, malware-free integration, status semantics, supplier/service custody, adverse cases, restoration and no-conformity boundaries |
| Pipeline control-system cybersecurity | 9/10 conditional | API 1164 third-edition essential functions, zones/conduits, remote access, safety invariants, attack replay, manual operation and reconciled recovery in an inert twin |
| GxP computerized-system data integrity | 9/10 conditional | Current 21 CFR Part 11 plus licensed GAMP 5 validation, audit trails, signatures, copies, retention, migration, recovery and no-regulatory-claim boundaries |
| CJIS information security | 9/10 conditional | CJIS 6.1 agency/CJI scope, agreements, personnel, identity, encryption, audit, cloud/mobile, incident, sanitization and synthetic-data assurance |
| Automotive process capability | 9/10 conditional | Automotive SPICE 4.0 and cybersecurity PAM outcomes, work products, evidence sampling, capability ratings, traceability, blinded agreement and no-certification boundaries |
| Process SIS functional safety-security | 9/10 conditional | IEC 61511 and IEC TR 63069 hazard/SIF/SIL/SRS lifecycle, safety-security conflicts, proof testing, fault injection, safe-state recovery and independent review |
| Building automation security | 9/10 conditional | BACnet/SC identity, PKI, hubs, segmentation, legacy gateways, failover, protocol mutations, safe fallback and protected life-safety boundaries |
| Industrial robotics safety-security | 9/10 conditional | ISO 10218:2025 and RIA R15.08 robot/cell/mobile scope, modes, zones, stops, speed, routes, cyber-induced faults, guarded testing and independent safety review |
| Data-centre facility resilience | 9/10 conditional | ISO/IEC 22237 and TIA-942-C power, cooling, cabling, fire, physical security, monitoring, cascading failure, KPI replay and no-production-disruption boundaries |
| Water and wastewater cyber resilience | 9/10 conditional | AWWA J100/G430/G440 and EPA assessment guidance with process/public-health invariants, OT and supplier controls, manual operation, adverse cases, sampling and independently reviewed restoration |
| NG911 and P25 public-safety communications | 9/10 conditional | NENA NG-SEC/i3 plus TIA-102/P25 CAP message, location, routing, identity, key, conformance, interoperability, overload, failover and live-traffic exclusion controls |
| International GxP data integrity | 9/10 conditional | EU Annex 11, WHO TRS 1033 Annex 4 and PIC/S PI 041-1 across lifecycle validation, ALCOA+, metadata, audit trails, suppliers, continuity, migration and inspection reconstruction |
| Transit cybersecurity resilience | 9/10 conditional | Final NIST IR 8576 CSF outcomes spanning rail, bus, stations, fares, passenger information and operations IT/OT with safety, degraded service, communications and recovery |
| Emergency incident coordination | 9/10 conditional | ISO 22320 command, authority, information quality, decisions, resources, interoperable communications, handoffs, demobilization and independent after-action review |
| Gas-SCADA cryptographic resilience | 9/10 conditional | AGA Report 12 supplemented by API 1164 and IEC 62351 with channel/key identity, forgery/replay/downgrade/rollover faults, availability, manual control and reconciled recovery |
| Water OT research-corpus validity | 9/10 research-only | SWaT/WADI/BATADAL license and digest binding, independent label/duplicate/contamination audit, protected multi-axis holdouts, repeated statistics, drift, process fidelity and explicit non-compliance boundaries |
| Audit and assessment integrity | 9/10 | ISO 19011, ISO/IEC 27007/27008/27006-1/17021-1/17029 with scoped sampling, independence, validity, and reperformance |
| Security evaluator competence | 9/10 | ISO/IEC 19896 role-specific qualification plus blinded golden cases, agreement, drift, adjudication, and bounded claims |
| Firmware and hardware trust | 9/10 | NIST SP 800-147/147B/193/1800-34, CSWP 45/52 and TPM 2.0 across component provenance, update roots, rollback, measured boot, weakness metrics, bus monitoring, fault injection, known-good recovery and residue-verified laboratory isolation |
| Kubernetes-native workload enforcement | 9/10 | CIS Kubernetes 2.0.1 plus version-pinned Pod Security Standards and Admission across all levels and modes, namespace and controller-template coverage, OS semantics, exemption expiry, bypass, webhook interaction, upgrade drift, remediation and rescan |
| Payment device, key and 3DS security | 9/10 conditional | PCI MPoC/P2PE/PIN/PTS POI/3DS Core and EMV 3DS with synthetic account/PIN/transaction data, test keys, dual-control ceremonies, HSM and device identity, tamper, protocol mutation, recovery, destruction receipts and no-validation boundaries |
| Space software product assurance | 9/10 conditional | ECSS-E-ST-40C and Q-ST-80C Rev.2 lifecycle, criticality, bidirectional traceability, independent assurance, supplier/reuse/COTS/tool qualification, coverage, anomalies, configuration, corrected-package replay and no-qualification boundaries |
| Regional financial technology resilience | 9/10 conditional | APRA CPS 230/234 and MAS TRM applicability, critical operations and tolerances, providers, control testing, incidents, board oversight, cyber/cloud/fourth-party scenarios, restoration, reconciliation, reassessment and no-regulatory-claim boundaries |
| Secure information sharing and competence | 9/10 | ISO/IEC 27010, TR 27016 and 27021 community agreements, TLP/IEP handling, forwarding and withdrawal, privacy, economic assumptions and outcomes, blinded practitioner agreement, bias, drift, reassessment and no-public-ranking boundaries |
| Differential privacy engineering | 9/10 | NIST SP 800-226 guarantee, accountant, composition, implementation-hazard, reproducibility, and utility evidence |
| Data, software, and cloud quality measurement | 9/10 | ISO/IEC 25001/25012/25019/25020/25024/25030 and TS 25052 planning, governance, requirements, contexts, models, measures, workloads, uncertainty, and golden outcomes |
| Enterprise risk technique assurance | 9/10 | ISO 31000/IEC 31010 plus NIST IR 8286 and CIS RAM governance, schemas, technique selection, multi-tier roll-up, BIA, sensitivity, blinded scenarios, agreement, and adjudication |
| Secure-by-design product assurance | 9/10 | CISA secure-default properties and product bad-practice negative cases with explicit guidance-versus-certification boundaries |
| Build reproducibility | 9/10 | Independent no-egress rebuilds across controlled environment variations with artifact equivalence, classified diffs, and provenance subjects |
| Workforce and engagement quality | 9/10 | NICE 2.2.0 coverage plus CREST/PTES authorization, competence, evidence, cleanup, remediation, retest, and closure controls |
| DevSecOps and test maturity | 9/10 | DSOVS, DSOMM, SAMM and TMMi evidence joined to immutable delivery events, DORA definitions, security/quality outcomes, defect escape, mutation and test evidence, anti-gaming, longitudinal uncertainty, protected licensed criteria and blinded reassessment |
| AI quality and conformity | 9/10 | ISO/IEC 42006, 25058, 25059, TR 42106/24030/27563, 8183, 12792, TS 6254/8200/12791, TR 5469, TR 29119-11, TS 42119-2, IEEE 7000-series, CSA AICM, differentiated context, validity, ethics, and stochastic acceptance |
| Cloud independent and provider-native assurance | 9/10 | CSA STAR/CAIQ plus AWS FSBP, MCSB v1, and Google Enterprise Foundations scope, complete inventory, native findings, independent drift reconciliation, exceptions, cleanup, and rescans |
| Security automation interoperability | 9/10 | CACAO 2.0, OpenC2, OCSF, FIRST TLP/IEP, and VERIS schema, downgrade, deidentification, negative-case, round-trip, and semantic-equivalence evidence |
| Consumer-product regulation | 9/10 | UK PSTI, ETSI EN 18031, and FCC Cyber Trust Mark applicability, product/lab/QR/registry evidence, negative cases, withdrawal, and legal claim boundaries |
| Detection product evaluation | 9/10 | ATT&CK Evaluations and AMTSO methods with independent step ground truth, representative benign workloads, source-preserving telemetry normalization, separate visibility/detection/protection, false positives, latency, evasion variants, version drift and adjudication |
| Public conformance integration | 9/10 | ACVP, FAPI, WebAuthn/WPT, complete OpenID4VP/OpenID4VCI/HAIP self-certification suites, explicitly early OpenID Federation plans with independent negative replay, ATT&CK emulation, and OpenSSF runner contracts |
| Cross-language real-world benchmarks | 9/10 | Time/project-split CVE-pair contract across Python, JavaScript, Java, C/C++, C#, Go, and Rust plus PrimeVul, DiverseVul, CVEfixes, ReposVul, and VulEval protected holdouts |
| Independent benchmark assurance | 9/10 | Label-authority and contamination digests, independent label/fix replay, exact/near-duplicate controls, training-overlap assessment, protected project/time splits, repository dependency oracles, tangled-patch audits, task separation, and two-reviewer minimum for organization corpora |
| Enterprise governance | 9/10 | ISO ISMS/application security, ISO/IEC 38500 governing-body oversight, ISO 9001/90003 quality management, NIST IR 8286, CSF current/target profile management, and optional licensed COBIT, TOGAF, ArchiMate, and Open FAIR packs with evidence-bound OSCAL output |
| Vulnerability, CSIRT, and PSIRT lifecycle | 9/10 | FIRST service catalogs and PSIRT maturity plus disclosure, handling, outcomes, exercises, blinded assessment, improvement, and reassessment controls |
| Privacy engineering | 9/10 | ISO 27701/NIST Privacy plus ISO/IEC 27561 operationalisation, TS 27564 model validation, 27565 ZKP guidance, adversarial PET cases, data exposure, and risk-path evidence |
| Conditional regulatory readiness | 9/10 | CRA, EUCC, DORA technical acts, FFIEC handbooks, BSI C5, FCC labeling, PCI, CUI, federal software producer attestation, and service-organization packs with explicit applicability, scope, authority, expiry, and claim boundaries |
| Identity, MCP, A2A, and protocol security | 9/10 | ISO/IEC 24760 identity architecture and lifecycle, AuthZEN PDP/PEP interoperability, OpenID Federation trust chains and policies, NIST digital identity, OAuth BCP, WebAuthn, FAPI, stable MCP plus OWASP/NSA principal-session-delegation, context, serialization, revocation, propagation, teardown and residue conformance, and A2A authorization with confused-deputy, SSRF, cross-tenant, downgrade, replay, and cleanup cases |
| Web runtime defense | 9/10 | CSP2 and SRI1 policy/integrity behavior across nonce, hash, source, redirect, CORS, CDN substitution, reporting, fallback, multiple policies, and digest-pinned browser engines |
| Financial technology assurance | 9/10 conditional | DORA Level 2 ICT-risk, incident, provider-register, reporting, and TLPT evidence plus current FFIEC DAM/AIO/Information Security handbook assessment with legal scope, qualified testers, blinded examiners, and retired-CAT exclusion |
| Cloud-service attestation precision | 9/10 conditional | BSI C5 service/control/customer-responsibility evidence, independent practitioner decisions, report validity, and explicit attestation-versus-certification boundaries |
| Cloud, container, API, and zero trust | 9/10 | ISO cloud controls, NIST API/microservices/service-mesh/container/ZTA references, CIS execution, and workload-bound evidence |
| Cryptography, TLS, and PQC readiness | 9/10 | Module and algorithm conformance, TLS 1.3 BoGo/tlsfuzzer behavior, algorithm transition, PQC inventory, migration, and ACVP evidence requirements |
| Operational resilience and BIA | 9/10 | ISO 22316/22317 resilience and impact analysis plus dependency, tolerance, RTO/RPO, degraded-mode, failover, restoration, reconciliation, variance, and reassessment evidence |
| Memory-safety engineering | 9/10 | CISA roadmap, unsafe/FFI reachability inventory, production hardening, language rules, static analysis, sanitizers, fuzzing, regression, exception, and risk-prioritized migration evidence |
| EU digital regulation | 9/10 | Explicit GDPR, NIS2, DORA, AI Act, and CRA applicability plus DORA Level 2 risk, incident, register, reporting, and TLPT execution contracts |
| IoT and consumer products | 9/10 conditional | Current manufacturer/device/support baselines, SESIP/EN 17927 platform evaluation and composition, FCC Cyber Trust Mark laboratory/registry controls, and consumer-IoT lifecycle testing |
| OT and industrial systems | 9/10 | Full product, service-provider, asset-owner, zone/conduit, system-level, energy, and conformance coverage |
| Automotive | 9/10 | ISO/SAE lifecycle, ISO 24089 update engineering, UNECE management/update controls, and qualified negative-case testing |
| Medical devices | 9/10 | IEC lifecycle plus SW96 risk management, IEC 80001-1 connected-health responsibility, IEC 60601-4-5 capability levels, IMDRF lifecycle/legacy/SBOM guidance, patient-safety oracles and synthetic adverse testing |
| Federal cloud and defense | 9/10 | FedRAMP OSCAL, CMMC and CUI plus CNSSI 1253 Revision 5 NSS categorization/baselines/overlays and DoDI 8500.01/8510.01 RMF, authorization, POA&M and monitoring evidence |
| AI security | 9/10 | ETSI EN 304 223 lifecycle baseline, OWASP AISVS Level 1-3 and LLM Top 10 2026, AI SSDF, AI RMF, AITG, ATLAS, Five Eyes incremental autonomy, MAESTRO cross-layer paths, bounded tool/data/memory authority, mutation testing, and stochastic agentic benchmark coverage |
| Agentic evaluator containment | 9/10 conditional | Nested inaccessible outer enforcement, no egress, synthetic identities/secrets/tools, harness escape, policy and scorer subversion, escalation, persistence, covert channels, shutdown evasion, cleanup corruption, immutable reset, residue scan, independent replay and bounded safety claims |
| Software securability engineering | 9/10 | FIASSE 1.1.0 isolated integrity, canonical parsing, intentional request surfaces, transparency, actionable merge reports, accountable expiring overrides, negative mutations, independent reassessment and explicit non-normative SSEM score boundaries |
| Architecture and code quality | 9/10 | Policy enforcement, history, labeled holdout, and structural evidence |
| Interoperability and audit evidence | 9/10 | SARIF, SBOM/VEX, SCAP, OSCAL, STIX/TAXII, CACAO/OpenC2/OCSF, SCITT, API contracts, OpenTelemetry, signed evidence, and fail-closed protocol evidence |
| Systems security engineering and risk measurement | 9/10 | Trustworthy-systems, cyber-resiliency, RMF, NIST SP 800-30/39 multi-tier risk, ISO/IEC/IEEE 16085 lifecycle risk, and measurement controls with traceable review evidence |
| Security-data interoperability | 9/10 | Explicit SARIF, CSAF, STIX/TAXII, OpenVEX, OSCAL, and CycloneDX contracts plus official-schema benchmark handoff |
| Control-knowledge interoperability | 9/10 | Policy-pinned OpenCRE graph and Gemara schemas joined to OSCAL 1.2.2 with source and license digests, identifier integrity, directional mapping provenance, conflict/cycle quarantine, explicit semantic-loss reports, independently adjudicated round trips and no-unreviewed-equivalence boundaries |
| UK financial threat-led assurance | 9/10 conditional | CBEST 2024 scope, authority, threat intelligence, provider/test-manager/control-group governance, external/insider/supply-chain scenarios, production safety, detection/response timelines, restoration, remediation, retest, closure and no-supervisory-approval boundaries |
| Independent hardware and firmware appraisal | 9/10 conditional | OCP S.A.F.E./SOLID product/source/build/firmware binding, reviewer competence and independence, secure boot/update/rollback, debug and physical surfaces, supply chain, fault/tamper/recovery replay, report provenance, remediation and no-recognition/certification boundaries |
| Product certification readiness | 9/10 | Common Criteria, EUCC, and SESIP/EN 17927 scheme pinning, accredited or qualified laboratory/certification authority, target/product/component/certificate identity, assurance continuity, vulnerability handling, public status, and negative-claim validation |
| Detection engineering and threat intelligence | 9/10 | Sigma, ATT&CK, STIX/TAXII, FIRST TLP/IEP handling, VERIS classification/deidentification, and authorized Atomic Red Team validation contracts |
| Language-specific secure coding | 9/10 | CERT C/C++/Java plus licensed MISRA C:2023 and C++:2023 rule digests, multi-compiler/target matrices, positive/negative/ambiguous cases, sanitizer corroboration, deviations and independent adjudication |
| Formal software testing and V&V | 9/10 | Exact ISO/IEC/IEEE 29119 Parts 1-5 and ISO/IEC 20246 controls joined to a maintained process/document/technique conformance adapter and real-defect benchmarks |
| Safety and security co-engineering | 9/10 | IEC 61508, ISO 26262/21448/PAS 8800/34502, ISO 14971, UL 4600, avionics, nuclear, rail and space assurance with safety cases, deterministic scenario challenge, degraded operation and independent review |
| Specialized target validation | 9/10 | OWASP MAS Crackmes, CloudGoat, SmartBugs plus stateful EVM economic-invariant replay, medical-device emulation, VVSG synthetic elections, critical-sector digital twins and protocol-specific disposable lanes |
| AI robustness and impact | 9/10 | NIST AI impact and ISO robustness controls plus physical-AI ODD, data, hazard, scenario, degradation, fallback, metamorphic and safety-case evidence requirements |
| Privacy by design | 9/10 | ISO privacy principles, privacy-by-design and operationalisation lifecycle controls, model validation, consent-record interoperability, explicit data-flow procedures, and cryptographic PET evidence |
| Zero-trust implementation | 9/10 | NIST ZTA and CISA maturity plus NSA 2026 Primer/Discovery/Phase One/Phase Two, seven-pillar activity/capability evidence, identity-aware microsegmentation, lateral-movement denial, session revocation, failure and recovery testing |
| Canonical fuzzing and functional benchmarks | 9/10 | FuzzBench, Magma, OSS-Fuzz, Defects4J, SWE-bench, Vul4J, and BugsInPy contracts with pinned identities and qualified execution |
| Independent evaluator and laboratory assurance | 9/10 | ISO/IEC 17025/17020/17065 plus ILAC P9/P10/P14/P15 proficiency, traceability, uncertainty, inspection independence, blinded interlaboratory cases, corrective action and no-accreditation boundaries |
| Structured assurance-case reasoning | 9/10 | ISO 15026/SACM claim-argument-evidence graphs with scope, freshness, confidence, defeater, contradiction, cycle, and independent-review validation |
| Integrity-scaled V&V | 9/10 | IEEE 1012 risk-tiered system/software/hardware rigor, independence, interface, reuse, COTS, and anomaly evidence |
| Cryptographic-module certification precision | 9/10 | Separate CMVP scheme-pinned and ISO 19790:2025/24759:2025 profiles with certificate status, calibrated methods, faults, and non-invasive options |
| Biometric identity assurance | 9/10 conditional | ISO 19795/30107 locked-threshold FMR, FNMR, IAPAR, demographic and attack-instrument strata, and Wilson confidence bounds |
| Integrated service/security management | 9/10 | ISO 20000-1/27013 lifecycle trace from service configuration and change through incidents, recovery, suppliers, and corrective action |
| Cross-laboratory proficiency | 9/10 | ISO 17043 blinded assigned values, agreement, chance correction, reference accuracy, bias, drift, appeals, and corrective action |
| Healthcare security operations | 9/10 | HIPAA/HITRUST and NIST SP 800-66 plus HICP 2023/HPH CPG ransomware, identity, clinical/ePHI/device/facility/vendor dependency, downtime, restoration, reconciliation and patient-safety outcome exercises |
| Airborne software assurance | 9/10 | DO-178C/330/326A joined to ARP4754B/ARP4761A functions, architecture, DALs, FHA/PSSA/SSA, common causes, derived requirements, change impact and qualified assessor calibration |
| Federal configuration conformance | 9/10 | Quarterly version-pinned DISA STIG/SRG and SCAP deltas, asset/CPE applicability, automated/manual and engine-disagreement adjudication, exception expiry, laboratory remediation/rollback, rescan and longitudinal drift durability |
| Software quality evaluation process | 9/10 | ISO/IEC 25001/25002/25021/25022/25040/25041/25051 planning, technology management, model selection, measure elements, quality-in-use reproduction, evaluation design, product acceptance, ratings, limitations, and evaluator viewpoint |
| Incident management lifecycle | 9/10 | ISO/IEC 27035, ISO/IEC/IEEE 23612 and NIST SP 800-61 preparation-through-recovery joined to measurable containment, restoration, reconciliation, service and reassessment outcomes |
| Privacy impact assessment | 9/10 | ISO/IEC 29134 data-flow, processing, recipient, individual-impact, notification and residual-risk evidence with missed-flow, reidentification, scope-change and longitudinal outcome cases |
| Supply-chain identifier integrity | 9/10 | in-toto/DSSE verification and lossless CPE, SWID, purl, OSV, CVE, CycloneDX, and SPDX identities |
| Threat-model quality | 9/10 | A source-bound asset/component/flow/boundary graph with referential integrity, exact risk arithmetic, assumption and acceptance expiry, verified mitigations, passing negative tests, architecture-change coverage, two-person independent approval, systems-engineering traceability, and a labeled benchmark |
| Software and systems lifecycle traceability | 9/10 | Seven-stage, source-bound graph with complete bidirectional requirement evidence, directional digest-backed links, end-to-end requirement reachability, independently verified change-impact samples, two-person review, and a mutation benchmark |
| Scenario-based architecture evaluation | 9/10 | ISO architecture evaluation plus ATAM utility trees, sensitivity and trade-off points, risk themes, dispositions, and blinded assessor scenarios |
| Software process capability | 9/10 | Seven evidence dimensions plus licensed ISO 33020 criteria, blinded multi-assessor calibration, completed-project defects/escapes/incidents/recovery, reassessment, uncertainty and anti-inflation cases |
| Comprehensive weakness mapping | 9/10 | Complete versioned CWE hierarchy with explicit abstraction/multi-label policy, independently audited multi-language labels, project/time holdouts, duplicate controls, misses and disagreement adjudication |
| Exploit prioritization validation | 9/10 | Point-in-time EPSS/KEV snapshots with strict future-data firewall, exploit-outcome authority, project/chronology separation, calibration, recall-at-budget, effort, response delay and label-noise adjudication |
| Formal verification and test generation | 9/10 | SV-COMP/Test-Comp plus RERS/CHC cases with task semantics, independent witness/test validation, UB review, parser/timeout/OOM/unsoundness mutations, solver disagreement and adjudicated truth |
| AI lifecycle, data quality, and evaluation | 9/10 | ISO/IEC 22989 terminology, 23053 ML architecture, 38507 governance, 38505-1 data governance, 5338 lifecycle, 5259 Parts 1-5 data quality and TR 5259-6 visualization fidelity, TS 25058 quality evaluation, TR 24030/27563 domain cases, and ARIA/Inspect/AILuminate stochastic digest-bound evaluation contracts |
| HPC and AI infrastructure security | 9/10 conditional | Final SP 800-223 reference architecture, threats and posture plus complete SP 800-234 sixty-control overlay tailoring, scheduler/accelerator/storage/shared-resource cases, performance evidence, recovery, and explicit SP 800-239 draft exclusion |
| Supplier relationship assurance | 9/10 | ISO/IEC 27036 governance, agreements and monitoring plus blinded supplier-incident exercises, fourth-party dependency, concentration, substitution, exit, recovery, reassessment and longitudinal outcome evidence |
| Software-signing conformance | 9/10 | Sigstore and SLSA verifier contracts bind suites, trust roots, identities, subjects, and negative cases |
| Remote attestation assurance | 9/10 | DICE/TPM/RATS/EAT layered identity, evidence, endorsements, freshness, mutations, appraisal, reset/recovery, and relying-party decision boundaries |
| OT patch management | 9/10 | IEC 62443-2-3 signed advisory and firmware applicability, safety/availability qualification, maintenance windows, partial failure, safe state, rollback, compensating-control expiry, restoration and longitudinal outcome evidence |
| Continuing airworthiness security | 9/10 | DO-355A joined to ARP5150B/ARP5151B monitoring, sparse service-signal correlation, safety/security impact, aircraft and fleet effectivity, authority decisions, field correction, effectiveness and recurrence |
| Space-mission communications security | 9/10 conditional | CCSDS threat, planning, architecture, algorithms, credentials, network adaptation, SDLS and extended-procedure coverage with ground/relay/flight digital-twin forgery, replay, ordering, desynchronization, link-fault and recovery cases |
| Maritime cyber resilience | 9/10 | IACS UR E26/E27 product lifecycle plus IMO MSC-FAL.1/Circ.3/Rev.3 operational governance, safety management, ship/shore/port/supplier scope, cyber incident, degraded operation, recovery and reconciliation evidence |
| Financial messaging security | 9/10 | SWIFT CSCF 2026 annual delta, architecture-specific applicability, significant-change detection, bounded prior-evidence reliance, independent assessor competence, design/operation sampling, remediation, retest and KYC-SA handoff |
| Reproducible real-world defect benchmarks | 9/10 | Defects4J, SWE-bench Verified, Vul4J, BugsInPy, CVE pairs, and governed project/time splits |
| Agent security benchmark realism | 9/10 | AgentDojo, HarmBench, AgentHarm Inspect Evals 6-B, version-pinned garak probes, and an internal holdout with attack success, utility retention, scorer-manipulation tests, contamination analysis, private-case generalization, confidence intervals, inert tools, bounded authority, and five-repetition requirements |

Classification scorecards report precision, recall, specificity, F1, Matthews
correlation coefficient, balanced accuracy, false-positive rate, and Youden's J.
Other protocols retain their native metrics: calibration error and effort;
competition outcomes and scores; generated-test coverage and faults; fuzzing
trials, effect size, and significance; stochastic attack/utility variance;
assessor agreement; conformance cases; or detection coverage, false positives,
and latency. Native effectiveness evaluations also emit Wilson 95% confidence
intervals and strata by CWE, language, parser variant, boundary type, severity,
and mutation operator.
`benchmark-delta.json` compares only identical benchmark families and pinned
corpus digests. The protocol identifier is part of that comparison scope;
changing scoring methodology makes an older baseline incomparable. Protocol
metrics are retained per benchmark, while a previously passing benchmark that
fails its current acceptance criteria is reported as a protocol regression.

Example invocation from an authorized benchmark lane:

```text
pysec benchmark PATH_TO_VERIFIED_REPORT \
  --corpus PATH_TO_PINNED_CORPUS.json \
  --corpus-sha256 APPROVED_CORPUS_SHA256 \
  --format json --output owasp-benchmark-score.json
```

## Interoperability

`industry-assurance.json` reports observed support for SARIF 2.1.0,
CycloneDX 1.7, SPDX 2.x/3.x, CycloneDX VEX 1.7, OpenVEX 0.2, CSAF VEX 2.0,
SCAP 1.4, and OSCAL 1.2.2. CycloneDX and Syft commands explicitly request
CycloneDX 1.7; parsers reject a different SBOM version. VEX inputs are
digest-pinned offline snapshots and never suppress a finding by themselves.

Authoritative references include the [NIST OSCAL project](https://pages.nist.gov/OSCAL/),
[OWASP Benchmark](https://owasp.org/www-project-benchmark/),
[NIST SAMATE/SARD](https://www.nist.gov/itl/csd/secure-systems-and-applications/samate),
[NIST SSDF](https://csrc.nist.gov/pubs/sp/800/218/final),
[NIST CSF](https://www.nist.gov/cyberframework),
[OpenSSF OSPS Baseline](https://baseline.openssf.org/),
[OWASP API Security Testing Framework](https://owasp.org/www-project-api-security-testing-framework/),
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
[OWASP WebGoat](https://owasp.org/www-project-webgoat/),
[OWASP crAPI](https://owasp.org/www-project-crapi/),
[Google FuzzBench](https://google.github.io/fuzzbench/),
[Magma](https://hexhive.epfl.ch/magma/),
[OSS-Fuzz](https://google.github.io/oss-fuzz/),
[MITRE CWE Top 25](https://cwe.mitre.org/top25/), and
[MITRE ATLAS](https://atlas.mitre.org/). Additional qualification and sector
sources include [ISO/IEC 17025](https://www.iso.org/standard/66912.html),
[NIST SP 800-66r2](https://csrc.nist.gov/pubs/sp/800/66/r2/final),
[FAA AC 20-115D](https://www.faa.gov/airports/resources/advisory_circulars/index.cfm/go/document.information/documentNumber/20-115D),
[DISA STIGs](https://public.cyber.mil/stigs/),
[ISO/IEC 25040](https://www.iso.org/standard/83467.html),
[ISO/IEC 29134](https://www.iso.org/standard/86012.html),
[in-toto specifications](https://in-toto.io/docs/specs/),
[Vul4J](https://github.com/tuhh-softsec/vul4j),
[BugsInPy](https://github.com/soarsmu/BugsInPy),
[PrimeVul](https://github.com/DLVulDet/PrimeVul),
[DiverseVul](https://github.com/wagner-group/diversevul),
[CVEfixes](https://github.com/secureIT-project/CVEfixes),
[ReposVul](https://arxiv.org/abs/2401.13169),
[VulEval](https://arxiv.org/abs/2404.15596),
[MITRE EMB3D](https://emb3d.mitre.org/),
[OWASP Business Logic Abuse Top 10](https://owasp.org/www-project-top-10-for-business-logic-abuse/),
[CNCF Software Supply Chain Best Practices v2](https://tag-security.cncf.io/community/working-groups/supply-chain-security/supply-chain-security-paper-v2/),
[OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/),
[OWASP Smart Contract Top 10](https://owasp.org/www-project-smart-contract-top-10/),
[CNCF TAG Security publications](https://tag-security.cncf.io/community/publications/), and
[AgentDojo](https://github.com/ethz-spylab/agentdojo). The AI adversarial
execution sources also include
[HarmBench](https://github.com/centerforaisafety/HarmBench),
[AgentHarm in Inspect Evals](https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/agentharm),
[NVIDIA garak](https://github.com/NVIDIA/garak), and
[OWASP Cornucopia](https://cornucopia.owasp.org/), and
[Microsoft PyRIT](https://github.com/microsoft/PyRIT). Their outputs remain
corpus-, implementation-, scorer-, model-, and configuration-specific and are
not presented as proof of general AI safety. The added foundational
and conformance sources include [MITRE CWE](https://cwe.mitre.org/),
[FIRST EPSS](https://www.first.org/epss/),
[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[SV-COMP](https://sv-comp.sosy-lab.org/),
[Test-Comp](https://test-comp.sosy-lab.org/),
[Sigstore conformance](https://github.com/sigstore/sigstore-conformance),
[SLSA verification](https://slsa.dev/verification_summary/),
[NIST ARIA](https://ai-challenges.nist.gov/aria),
[UK AISI Inspect](https://inspect.aisi.org.uk/),
[IETF RATS architecture](https://www.rfc-editor.org/rfc/rfc9334), and
[Entity Attestation Token](https://www.rfc-editor.org/rfc/rfc9711). The latest
extension also uses the official [OWASP DSOVS](https://owasp.org/www-project-devsecops-verification-standard/),
[OWASP DSOMM](https://owasp.org/www-project-devsecops-maturity-model/),
[TMMi](https://www.tmmi.org/tmmi-documents/),
[CSA STAR](https://cloudsecurityalliance.org/star),
[CSA AICM](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix-v1-1),
[OASIS CACAO 2.0](https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html),
[OpenC2](https://www.oasis-open.org/standard/oc2-ls-v1-0/),
[OCSF](https://ocsf.io/),
[NIST SP 800-216](https://csrc.nist.gov/pubs/sp/800/216/final),
[NIST SP 800-228 Update 1](https://csrc.nist.gov/pubs/sp/800/228/upd1/final),
[NIST SP 800-204C](https://csrc.nist.gov/pubs/sp/800/204/c/final),
[NIST SP 800-233](https://csrc.nist.gov/pubs/sp/800/233/final),
[NISTIR 8505](https://csrc.nist.gov/pubs/ir/8505/final),
[IETF SCITT RFC 9943](https://www.rfc-editor.org/info/rfc9943),
[RFC 9116](https://www.rfc-editor.org/info/rfc9116),
[OWASP Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/),
[ISO/IEC TS 42119-2](https://www.iso.org/standard/84127.html),
[OpenSSF S2C2F](https://github.com/ossf/s2c2f),
[OpenTelemetry semantic conventions](https://opentelemetry.io/docs/specs/semconv/),
[NCSC CAF](https://www.ncsc.gov.uk/collection/cyber-assessment-framework),
[ASD Essential Eight](https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model),
[ISO 24089](https://www.iso.org/standard/77796.html),
[IEC 62351](https://webstore.iec.ch/en/publication/6912), and
[UK PSTI guidance](https://www.gov.uk/guidance/regulations-consumer-connectable-product-security). The current extension is grounded in
[ISO/IEC/IEEE 29119-2](https://www.iso.org/standard/79428.html),
[ISO/IEC 25019](https://www.iso.org/standard/78177.html),
[ISO/IEC TS 25052-2](https://www.iso.org/standard/86722.html),
[ISO 31000](https://www.iso.org/standard/65694.html),
[IEC 31010](https://webstore.iec.ch/en/publication/59809),
[CISA Secure by Design](https://www.cisa.gov/securebydesign),
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446),
[tlsfuzzer](https://tlsfuzzer.readthedocs.io/en/latest/),
[Reproducible Builds](https://reproducible-builds.org/docs/plans/),
[AMTSO](https://www.amtso.org/standards/),
[TCG DICE](https://trustedcomputinggroup.org/resource/dice-attestation-architecture/),
[NICE Framework Components](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions),
[CREST](https://www.crest-approved.org/wp-content/uploads/2023/04/A-Guide-to-Penetration-Testing-2022.pdf), and
[DORA metrics](https://dora.dev/guides/dora-metrics/). The assurance-case,
V&V, module, biometric, service, and proficiency extensions use
[ISO/IEC/IEEE 15026-2](https://www.iso.org/standard/80625.html),
[OMG SACM 2.3](https://www.omg.org/spec/SACM/2.3),
[IEEE 1012-2024](https://standards.ieee.org/ieee/1012/12536/),
[NIST CMVP](https://csrc.nist.gov/Projects/cryptographic-module-validation-program),
[ISO/IEC 19790:2025](https://www.iso.org/standard/82423.html),
[ISO/IEC 24759:2025](https://www.iso.org/standard/82424.html),
[ISO/IEC 30107-3:2023](https://www.iso.org/standard/79520.html),
[ISO/IEC 20000-1](https://www.iso.org/standard/70636.html), and
[ISO/IEC 17043:2023](https://www.iso.org/standard/80864.html). Enterprise-risk,
quality-governance, AI, and architecture additions use
[NIST IR 8286 Rev. 1](https://csrc.nist.gov/pubs/ir/8286/r1/final),
[CIS RAM 2.2](https://learn.cisecurity.org/cis-ram-v2-2),
[ISO/IEC 25001](https://www.iso.org/standard/64787.html),
[ISO/IEC TR 42106](https://www.iso.org/standard/86903.html),
[ISO/IEC 8183](https://www.iso.org/standard/83002.html),
[ISO/IEC 12792](https://www.iso.org/standard/84111.html),
[ISO/IEC TS 8200](https://www.iso.org/standard/83012.html),
[COBIT](https://www.isaca.org/resources/cobit), and policy-pinned Open Group
TOGAF, ArchiMate, and Open FAIR sources. Licensed content is never vendored;
adopters must supply approved requirement and interpretation digests.
Control-knowledge and independent sector assurance use
[OWASP OpenCRE](https://github.com/OWASP/OpenCRE),
[OpenSSF Gemara](https://github.com/gemaraproj/gemara),
[NIST OSCAL 1.2.2](https://github.com/usnistgov/OSCAL/releases/tag/v1.2.2),
[Bank of England CBEST](https://www.bankofengland.co.uk/financial-stability/operational-resilience-of-the-financial-sector/cbest-threat-intelligence-led-assessments-implementation-guide),
[OCP S.A.F.E.](https://github.com/opencomputeproject/OCP-Security-SAFE), and
[OCP SOLID](https://github.com/opencomputeproject/OCP-Security-SOLID/blob/main/requirements.md).
Every external graph, schema, guide, product revision, provider scope and
laboratory record is digest-pinned; the suite does not confer mapping
equivalence, CBEST completion, supervisory approval, OCP recognition or product
certification.
The latest assurance tranche uses
[OWASP AISVS 1.0](https://owasp.org/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/),
[ISO/IEC TS 25058](https://www.iso.org/standard/82570.html),
[EUCC](https://certification.enisa.europa.eu/certification-library/eucc-certification-scheme_en),
[CISA Secure Software Development Attestation](https://www.cisa.gov/resources-tools/resources/secure-software-development-attestation-form),
[IEEE autonomous and intelligent system standards](https://standards.ieee.org/initiatives/autonomous-intelligence-systems/standards/),
[ISO/IEC TR 27563](https://www.iso.org/standard/80396.html),
[ISO/IEC TR 24030](https://www.iso.org/standard/84144.html),
[ISO/IEC 38500](https://www.iso.org/standard/81684.html),
[NIST SP 1301](https://csrc.nist.gov/pubs/sp/1301/final), and
[MLCommons AILuminate](https://mlcommons.org/ailuminate/).
The agent, IoT, information-handling, web, and sector additions use official
[A2A 1.0](https://a2a-protocol.org/latest/specification/),
[GlobalPlatform SESIP 1.2](https://globalplatform.org/specs-library/sesip-methodology/),
[FIRST TLP 2.0](https://www.first.org/tlp/),
[FIRST IEP 2.0](https://www.first.org/iep/),
[VERIS](https://verisframework.org/),
[W3C CSP Level 2](https://www.w3.org/TR/CSP2/),
[W3C SRI 1.0](https://www.w3.org/TR/2016/REC-SRI-20160623/),
[DORA delegated and implementing acts](https://www.eba.europa.eu/activities/direct-supervision-and-oversight/digital-operational-resilience-act),
[FFIEC IT Handbooks](https://ithandbook.ffiec.gov/it-booklets/),
[BSI C5](https://www.bsi.bund.de/dok/C5), and
[FCC 24-26](https://docs.fcc.gov/public/attachments/FCC-24-26A1.pdf).
The digital-credential, posture, privacy, telecom, provenance, automotive, and
payment tranche uses official
[W3C VC Data Model 2.0](https://www.w3.org/TR/vc-data-model-2.0/),
[OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html),
[OpenID4VC HAIP 1.0](https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0-final.html),
[OpenID digital-credential self-certification](https://openid.net/openid4vp-and-openid4vci-conformance-tests-are-complete-and-open-for-self-certification/),
[AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html),
[OpenID Federation 1.1](https://openid.net/openid-federation-1-1-final-specifications-approved/),
[OpenID Federation conformance status](https://openid.net/certification/federation_testing/),
[FAPI 2.0 final specifications](https://openid.net/fapi-2-security-profile-attacker-model-final-specifications-approved/),
[NIST SP 800-223](https://csrc.nist.gov/pubs/sp/800/223/final),
[NIST SP 800-234](https://csrc.nist.gov/pubs/sp/800/234/final),
[ISO/IEC 24760-1:2025](https://www.iso.org/standard/24760-1),
[ISO/IEC 24760-2:2025](https://www.iso.org/standard/24760-2),
[ISO/IEC 24760-3:2025](https://www.iso.org/standard/24760-3),
[ISO/IEC TR 5259-6:2026](https://www.iso.org/standard/86532.html),
[CISA SCuBA](https://github.com/cisagov/ScubaGear),
[CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes),
[LINDDUN](https://linddun.org/),
[OWASP Benchmark](https://owasp.org/www-project-benchmark/),
[GSMA NESAS](https://www.gsma.com/solutions-and-impact/technologies/security/network-equipment-security-assurance-scheme/),
[ENX TISAX downloads](https://enx.com/en-us/TISAX/downloads/),
[C2PA specifications](https://spec.c2pa.org/specifications/), and
[PCI Security Standards](https://www.pcisecuritystandards.org/standards/).

The maturity, cloud, product, privacy, and service tranche is source-pinned to
[DOE C2M2 2.1](https://www.energy.gov/ceser/cybersecurity-capability-maturity-model-c2m2),
[FINOS Common Cloud Controls](https://ccc.finos.org/),
[FINOS CCC Core](https://ccc.finos.org/catalogs/core/core/),
[NCSC Cyber Resilience Test Facilities](https://www.ncsc.gov.uk/schemes/cyber-resilience-test-facilities/introduction),
[NCSC CRTF documents](https://www.ncsc.gov.uk/schemes/cyber-resilience-test-facilities/documents),
[UK Software Security Code of Practice](https://www.gov.uk/government/publications/software-security-code-of-practice),
[NIST PRAM](https://www.nist.gov/privacy-framework/nist-pram),
[NISTIR 8062](https://csrc.nist.gov/pubs/ir/8062/final), and
[ITIL 4](https://www.peoplecert.org/Organizations/Certifications/ITIL-Corporate-Framework).
ITIL execution requires organization-licensed criteria; the repository stores
only identifiers, control intent, source and license digests, evidence contracts,
and claim boundaries. NCSC approval, FINOS or DOE endorsement, PeopleCert
certification, and legal privacy compliance remain external decisions.

The operational-depth tranche is source-pinned to the
[NSA Zero Trust Implementation Guidelines](https://www.nsa.gov/Cybersecurity/ZIG/),
[CISA microsegmentation guidance](https://www.cisa.gov/resources-tools/resources/microsegmentation-zero-trust-part-one-introduction-and-planning),
[DoDI 8500.01](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/850001_2014.pdf),
[DoDI 8510.01](https://www.esd.whs.mil/Portals/54/Documents/DD/issuances/dodi/851001p.pdf),
[HHS HICP](https://hhscyber.hhs.gov/cornerstone-hicp.html),
[HHS HPH Cybersecurity Performance Goals](https://hhscyber.hhs.gov/cybersecurity-performance-goals.html),
[SAE ARP4754B](https://saemobilus.sae.org/standards/arp4754b-guidelines-development-civil-aircraft-systems),
[SAE ARP4761A](https://saemobilus.sae.org/standards/arp4761a-guidelines-conducting-safety-assessment-process-civil-aircraft-systems-equipment),
[SAE ARP5150B](https://saemobilus.sae.org/standards/arp5150-safety-assessment-transport-airplanes-commercial-service),
[SAE ARP5151B](https://saemobilus.sae.org/standards/arp5151-safety-assessment-general-aviation-airplanes-rotorcraft-commercial-service),
[CCSDS active publications](https://ccsds.org/view/allpubs/),
[CCSDS Blue Books](https://ccsds.org/view/bluebooks/),
[ILAC policy publications](https://ilac.org/publications-and-resources/ilac-policy-series/),
and [IMO MSC-FAL.1/Circ.3/Rev.3](https://wwwcdn.imo.org/localresources/en/OurWork/Security/Documents/MSC-FAL.1-Circ.3-Rev.3.pdf).

The recovery and governance tranche is source-pinned to
[NIST IR 8374 Rev. 1](https://csrc.nist.gov/pubs/ir/8374/r1/final),
[NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final),
[NIST SP 1339](https://csrc.nist.gov/pubs/sp/1339/final),
[NIST SP 1800-45](https://csrc.nist.gov/pubs/sp/1800/45/final),
[IEC TS 62443-6-1](https://webstore.iec.ch/en/publication/67462),
[ISO 22361](https://www.iso.org/standard/50267.html),
[ISO 22398](https://www.iso.org/standard/50294.html),
[NIST SP 800-221](https://csrc.nist.gov/pubs/sp/800/221/final),
[NIST SP 1347](https://csrc.nist.gov/pubs/sp/1347/final),
[NIST IR 8406](https://csrc.nist.gov/pubs/ir/8406/upd1/final), and
[NIST IR 8473](https://csrc.nist.gov/pubs/ir/8473/final). Licensed IEEE and
ISO/IEC criteria remain outside the repository; the suite retains only bounded
identifiers, control intent, evidence contracts, and claim limitations.

The specialized-sector tranche is source-pinned to
[SEMI semiconductor cybersecurity resources](https://www.semi.org/en/products-services/semitwn-semiconductor-cybersecurity-service),
[API Standard 1164](https://www.api.org/products-and-services/standards/important-standards-announcements/1164),
[FDA 21 CFR Part 11](https://www.ecfr.gov/current/title-21/chapter-I/subchapter-A/part-11),
[FBI CJIS Security Policy resources](https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center),
[Automotive SPICE](https://www.automotivespice.com/),
[IEC 61511](https://webstore.iec.ch/en/publication/61289),
[ASHRAE BACnet](https://www.ashrae.org/technical-resources/bookstore/bacnet),
[ISO 10218-1:2025](https://www.iso.org/standard/73933.html),
[ISO/IEC 22237-1](https://www.iso.org/standard/78550.html), and
[ANSI/TIA-942-C](https://tiaonline.org/standard/tia-942/).
Licensed SEMI, ISPE, Automotive SPICE, IEC, ISO, ASHRAE, RIA and TIA criteria
are never redistributed by the suite: execution requires an authorized,
digest-pinned criteria map and retains publisher, edition, license and assessor
scope in the evidence package.
CNSSI 1253 Revision 5 remains `policy-pinned` because organizations must obtain
and govern the authoritative controlled-source edition and overlays; the suite
does not redistribute its contents or infer government authorization.

The cloud, adversarial, AI and IoT tranche is source-pinned to the
[CIS benchmark catalog](https://www.cisecurity.org/cis-benchmarks),
[OWASP GenAI Red Teaming Guide](https://genai.owasp.org/resource/genai-red-teaming-guide/),
[IMDA AI Verify](https://www.imda.gov.sg/about-imda/research-and-statistics/sgdigital/tech-pillars/artificial-intelligence),
[AI Verify Foundation Project Moonshot](https://github.com/aiverify-foundation/moonshot),
[NCSC CHECK scheme](https://www.ncsc.gov.uk/schemes/check/introduction),
[AIUC-1](https://www.aiuc-1.com/), and the
[CSA IoT Security Controls Framework](https://cloudsecurityalliance.org/artifacts/iot-security-controls-framework).
CIS content remains subject to its terms and is represented only through
versioned identifiers and organization-authorized criteria digests. AIUC-1 is
conditional and issuer-bound; suite evidence cannot issue its certificate.
Project Moonshot output and all other framework results are engineering
evidence, not legal conformity, product safety, provider status or certification.

ISO/IEC 27090, ISO/IEC 27091, NIST Privacy Framework 1.1, ISO/IEC 42119 parts 3, 7, and 8,
the next ISO 31000 and ISO/IEC/IEEE 15026-4 editions, IEEE P1012, TCG DICE
1.3, ISO/IEC/IEEE 29119-14, ISO/IEC 42105, ISO/IEC 24970, ISO/IEC 42007,
NIST IR 8596, the next ISO/IEC TR 24030 edition, unreleased AILuminate
Agentic/Multimodal contracts, release-ambiguous OWASP ISVS, W3C CSP Level 3,
SRI 2, Trusted Types, the OWASP Client-Side Top 10 candidates, VulnGym,
SecVulEval, W3C VC Data Model 2.1, OpenID4VP 1.1, NIST SP 800-239,
OpenEoX 1.0 CSD01, CSAF 2.1 CSD02, VDA ISA 2027, and draft BSI TR-03183
Parts 1 and 3, plus NIST SP 800-82 Rev. 4, NIST IR 8183 Rev. 2, NIST SP 1353,
NIST IR 8613, the NCSC CyAS MVP, and CoSAI MCP Security guidance remain
publication watch items. The registry
intentionally avoids a normative claim until the responsible publisher exposes
a stable final edition and the organization pins its version, source digest,
applicability, and licensed requirements after legal review.
