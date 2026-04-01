# 0xRecon v2 — Legacy Reference File Manifest

This directory contains read-only copies of files from the original 0xRecon
(CAIP) codebase. They exist as reference for logic porting during the rebuild.
They are never imported, executed, or modified.

## Usage Rules

- Reference files are READ ONLY — never modify them
- Never import from docs/reference/ in application code
- When porting logic, rewrite in the new stack — do not copy verbatim
- Each phase prompt specifies exactly which reference files to consult

## File Index

| File | Source | Used In Phase | Size | Status |
|------|--------|---------------|------|--------|
| `legacy_luna_hsm.py` | `caip_scanning_functions/collectors/luna_hsm.py` | Phase 5 | 24 KB | Copied |
| `legacy_azure_keyvault.py` | `caip_scanning_functions/collectors/azure_keyvault.py` | Phase 6 | 28 KB | Copied |
| `legacy_ejbca_collector.py` | `caip_scanning_functions/collectors/ejbca_collector.py` | Phase 6 | 52 KB | Copied |
| `legacy_tls_scanner.py` | `caip_scanning_functions/collectors/tls_scanner.py` | Phase 6 | 36 KB | Copied |
| `legacy_crl_collector.py` | `caip_scanning_functions/collectors/crl_collector.py` | Phase 6 | 12 KB | Copied |
| `legacy_file_share.py` | `caip_scanning_functions/collectors/file_share.py` | Phase 6 | 16 KB | Copied |
| `legacy_scan_orchestrator.py` | `caip_scanning_functions/_scan_orchestrator.py` | Phase 7 | 64 KB | Copied |
| `legacy_rule_assessment.py` | `caip_policy_functions/rule_assessment.py` | Phase 8 | 40 KB | Copied |
| `legacy_policy_assessment_service.py` | `caip_policy_functions/policy_assessment_service.py` | Phase 8 | 40 KB | Copied |
| `legacy_scoring_service.py` | `caip_service_layer/scoring_service.py` | Phase 9 | 60 KB | Copied |
| `legacy_pqc_detector.py` | `caip_pqc_functions/pqc_detector.py` | Phase 9 | 32 KB | Copied |
| `legacy_inventory_service.py` | `caip_service_layer/inventory_service.py` | Phase 10 | 48 KB | Copied |
| `legacy_asset_context_service.py` | `caip_service_layer/asset_context_service.py` | Phase 10 | 48 KB | Copied |
| `legacy_environment_inference_service.py` | `caip_service_layer/environment_inference_service.py` | Phase 10 | 68 KB | Copied |
| `legacy_key_normalisation_service.py` | `caip_service_layer/key_normalisation_service.py` | Phase 10 | 80 KB | Copied |
| `legacy_certificate_service.py` | `caip_service_layer/certificate_service.py` | Phase 11 | 152 KB | Copied |
| `legacy_cbom_export_service.py` | `caip_reporting_functions/cbom_export_service.py` | Phase 13 | 40 KB | Copied |
| `legacy_engagement_docx_builder.py` | `caip_reporting_functions/engagement_docx_builder.py` | Phase 14 | 20 KB | Copied |
| `legacy_executive_report_service.py` | `caip_reporting_functions/executive_report_service.py` | Phase 14 | 192 KB | Copied |
| `legacy_financial_calculator.py` | `caip_reporting_functions/engagement_financial_calculator.py` | Phase 14 | 16 KB | Copied |
| `legacy_document_assessment_service.py` | `caip_document_assessment_functions/document_assessment_service.py` | Phase 15 | 48 KB | Copied |
| `legacy_document_templates.py` | `caip_document_assessment_functions/document_templates.py` | Phase 15 | 100 KB | Copied |
| `legacy_remote_collector_daemon.py` | `remote_collector/daemon.py` | Phase 17 | 36 KB | Copied |
| `legacy_remote_collector_client.py` | `remote_collector/client.py` | Phase 17 | 48 KB | Copied |
| `legacy_unified_vault_service.py` | `caip_service_layer/unified_vault_service.py` | Phase 18 | 28 KB | Copied |
| `legacy_secret_resolution_service.py` | `caip_service_layer/secret_resolution_service.py` | Phase 18 | 24 KB | Copied |
| `RECON_INVENTORY.md` | `RECON_INVENTORY.md` | Reference | 84 KB | Copied |
| `REPORT_CRYPTO_INVENTORY.md` | `REPORT_CRYPTO_INVENTORY.md` | Reference | 60 KB | Copied |

## Phase → Reference File Mapping

### Phase 5 — Collector Framework + Luna HSM
- `legacy_luna_hsm.py` — Port: _safe_get() pattern, slot resolution by
  token_label, session lifecycle (open→login→collect→logout→close in finally),
  full CKA attribute list. Rewrite using python-pkcs11 API, not PyKCS11.

### Phase 6 — Remaining Collectors
- `legacy_azure_keyvault.py` — Port: field extraction logic, Azure metadata
  fields captured, error handling patterns.
- `legacy_ejbca_collector.py` — Port: EJBCA REST API endpoint structure,
  P12 mTLS session pattern. Rewrite using httpx, not requests.
- `legacy_tls_scanner.py` — Port: TLS metadata captured (forward secrecy,
  CT SCTs, OCSP, cipher suite, protocol enumeration). Wrap in asyncio.to_thread().
- `legacy_crl_collector.py` — Port: CRL parsing logic. Rewrite using httpx.
- `legacy_file_share.py` — Lift and shift. Wrap filesystem ops in
  asyncio.to_thread(). Extension list and content detection patterns preserved.

### Phase 7 — Scan Orchestration
- `legacy_scan_orchestrator.py` — Port: partial failure handling, collector
  result combination, per-collector timeout pattern. Full async rewrite.

### Phase 8 — Policy Engine
- `legacy_rule_assessment.py` — Port: RuleRegistry, RuleEvaluator,
  UnifiedAssessor, condition type evaluation (simple/expression/temporal),
  get_rules_for_collector() scoping. Fix all bare except blocks.
- `legacy_policy_assessment_service.py` — Port: assess_scan_results()
  orchestration pattern.

### Phase 9 — Scoring, Aggregation, PQC Detection
- `legacy_scoring_service.py` — Port: weight factor values, health index
  formula, A+–F grade boundaries, priority queue top-10 logic. All exact
  numerical values must be preserved.
- `legacy_pqc_detector.py` — Port: all OID mappings (40+), name patterns,
  migration status classification, vulnerability assessment logic. Lift and
  shift — pure logic, no framework dependencies.

### Phase 10 — Inventory and Enrichment
- `legacy_inventory_service.py` — Port: sync logic, promote-to-inventory
  pattern, change tracking.
- `legacy_asset_context_service.py` — Port: context override logic, history
  tracking pattern.
- `legacy_environment_inference_service.py` — Port: hostname heuristics,
  source string matching, confidence scoring values.
- `legacy_key_normalisation_service.py` — Port: normalisation logic across
  collector formats. Preserve field mappings exactly.

### Phase 11 — PKI Sub-System
- `legacy_certificate_service.py` — Port: CA provisioning, cert generation
  parameters (RSA 4096, validity periods, X.509 extensions), mTLS validation,
  vault key naming convention. Private key storage pattern must carry across.

### Phase 12 — Signed and Encrypted Reports
- `legacy_certificate_service.py` — Port: encrypt_report_data() and
  sign_encrypted_blob() methods exactly. AES-256-GCM parameters, RSA-OAEP
  padding config, PSS salt length, blob JSON structure must be byte-for-byte
  compatible with existing distributed reports.

### Phase 13 — CBOM, Reassessments, Aggregations
- `legacy_cbom_export_service.py` — Port: CycloneDX 1.6+ component structure,
  assetType values, dependency mapping. Output format must match exactly.

### Phase 14 — Reporting
- `legacy_engagement_docx_builder.py` — Port: report structure and section
  ordering. Decouple from Flask/SQLite.
- `legacy_executive_report_service.py` — Port: executive summary structure.
  Fix 15+ bare except blocks.
- `legacy_financial_calculator.py` — Lift and shift. Pure calculation logic,
  no framework dependencies.

### Phase 15 — Document Assessment
- `legacy_document_assessment_service.py` — Port: assessment logic and scoring.
- `legacy_document_templates.py` — Port: template schema definitions.

### Phase 17 — Remote Collector Agent
- `legacy_remote_collector_daemon.py` — Port: registration handshake, heartbeat
  protocol, result submission flow. Rewrite as proper packaged agent.
- `legacy_remote_collector_client.py` — Port: server communication patterns.

### Phase 18 — Secret Store Management
- `legacy_unified_vault_service.py` — Port: PBKDF2 parameters (600k iterations),
  AES-256-GCM nonce/salt sizes. These values must be preserved — any change
  breaks existing vault files.
- `legacy_secret_resolution_service.py` — Port: priority order, resolution
  logic, fallback chain.
