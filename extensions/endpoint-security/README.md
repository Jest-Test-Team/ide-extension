# Endpoint Security & Compliance Toolkit

Editor support for people building EDR / AV agents and SIEM / SOAR back-ends.

## WFP, ETW and Endpoint Security API validation

For C, C++, Objective-C and Rust (`windows` / `windows-sys` crates). A curated API database (`data/apis/*.json`) covering the Windows Filtering Platform (user and kernel mode), Event Tracing for Windows and Apple Endpoint Security drives:

- **Hover, signature help and completion** with return semantics, IRQL, the matching release function, pitfalls and a link to Microsoft / Apple documentation.
- **Diagnostics:**

| Rule | Finds |
|---|---|
| `edr/missing-cleanup` | `FwpmEngineOpen0` without `FwpmEngineClose0`, `FwpsCalloutRegister*` without unregister, `StartTrace` without stop, `OpenTrace` without `CloseTrace`, `es_new_client` without `es_delete_client`, `EventRegister` without `EventUnregister` |
| `edr/unchecked-status` | discarded `DWORD` / `ULONG` / `NTSTATUS` / `es_return_t` results (incl. Rust `let _ =`) |
| `edr/esf-auth-no-response`, `edr/esf-auth-open-flags` | AUTH subscriptions with no `es_respond_*` path; AUTH_OPEN answered with `es_respond_auth_result` |
| `edr/deprecated-api` | `es_copy_message`, `es_free_message` (quick fix), `es_mute_path_literal/prefix` |
| `edr/wfp-server-name`, `edr/wfp-transaction` | non-NULL `serverName`; multiple policy adds without a transaction; transactions without `FwpmTransactionAbort0` |
| `edr/etw-broad-enable`, `edr/etw-opentrace-check` | VERBOSE / all-keyword enables; `OpenTrace` result compared with `INVALID_HANDLE_VALUE`/0 |

## Compliance scanning (PCI DSS 4.0.1, CCSP Domain 2)

For Go and TypeScript / JavaScript services that handle cardholder or sensitive cloud data. Rule packs live in `data/rules/*.yaml` and every finding cites its requirement:

- **PCI DSS 4.2.1:** disabled TLS verification (`InsecureSkipVerify`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`), TLS < 1.2, cleartext `http://` endpoints.
- **PCI DSS 3.5.1:** weak hashes/ciphers, Luhn-valid PAN literals.
- **PCI DSS 3.3.1 / 3.5.1:** account data (PAN, CVV, track data…) flowing into log calls — tracked through local assignments, ignoring masked/tokenised values.
- **PCI DSS 8.6.2:** hard-coded credentials.
- **PCI DSS 6.2.4:** SQL built with `fmt.Sprintf`, concatenation or template literals.
- **CCSP Domain 2:** public-read object ACLs, sensitive values in URL query strings, S3 writes without explicit SSE-KMS, long-lived pre-signed URLs.

**Scan Workspace** checks every file; **Export Compliance Report** writes **SARIF** (upload to GitHub code scanning) or Markdown. Add organisation-specific packs with `endpointSecurity.rulePacks`.

## Process-tree simulation

Describe malware behaviour as a synthetic event timeline in a `*.ptree.yaml` file. A JSON schema is contributed for completion and validation with the YAML extension.

```yaml
scenario: Macro dropper
processes:
  - { id: word, image: 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE' }
events:
  - { t: 0,   type: spawn, process: ps, parent: word, image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', cmdline: 'powershell -enc …' }
  - { t: 900, type: terminate, process: ps }
rules:
  - id: my-rule
    match: { type: spawn, parent.image: '(?i)winword\.exe$' }
```

**▶ Simulate** (CodeLens) replays the timeline through a local agent process (JSON-RPC over stdio) and shows the following against the built-in, ATT&CK-mapped detections and your own:
- the resulting process tree, with terminate/inject edges
- the detections
- a timeline linked back to the YAML

Rules can be single-event `match`, `threshold` (count within a time window) or `sequence` with bindings (`bind: { P: parent.id }` … `target.id: $P`). Fields include `image`, `cmdline`, `parent.*`, `ancestor.*`, `target.*`, `path`, `key`, `remote` and `count`.

**Nothing is executed.** The agent only evaluates data. To run it elsewhere (e.g. inside your sandbox VM), start `node dist/ptreeAgent.js --http 8765 --host 0.0.0.0` there and set `endpointSecurity.simulation.agentUrl`.

## Sources

- [Microsoft — Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Microsoft — Event Tracing for Windows](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Apple — Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/)
- [ISC2 CCSP Exam Outline (Domain 2: Cloud Data Security)](https://www.isc2.org/certifications/ccsp/ccsp-certification-exam-outline)
- [MITRE ATT&CK](https://attack.mitre.org/)
