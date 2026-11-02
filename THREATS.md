# TrustVault Threat Model (THREATS.md)

| Threat ID | Category | Attack Vector | Mitigation in TrustVault | Test Case Verification |
| :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | BOLA / IDOR | Swapping document UUID in `/api/documents/{id}/download` | Centralized `verify_document_access` dependency returning `404` for unauthorized users | `test_unauthorized_user_cannot_access_doc` |
| **THREAT-02** | Stale Grant | Downloading file after access revocation | Synchronous DB check per file request; zero cached download URLs | `test_immediate_revocation_blocks_subsequent_download` |
| **THREAT-03** | Log Tampering | Malicious admin/attacker editing `audit_logs` | Cryptographic SHA-256 hash chaining (`prev_hash` + payload) & DB-level update denial | `test_audit_log_tamper_detection` |
| **THREAT-04** | Path Traversal | Filenames containing `../../` | Files stored using random UUIDs in isolated storage root; filenames decoupled from disk path | `test_filename_sanitization` |
| **THREAT-05** | Privilege Escalation | Viewer attempting to grant permissions to others | Strict role-based gate requiring ownership or admin role for `/permissions` endpoints | `test_viewer_cannot_grant_permissions` |
