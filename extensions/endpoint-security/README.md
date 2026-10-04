# Endpoint Security & Compliance Toolkit

Editor support for people building EDR / AV agents and SIEM / SOAR back-ends, plus a risk scan of the VS Code extensions you have installed.

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

## Installed extension risk scan

The **shield** icon in the activity bar opens **Installed Extensions**. **Scan Installed Extensions** gives every installed extension a heuristic risk level: **low**, **medium** or **high**. Each level comes with the reasons behind it, much like an EDR's suspicious-behaviour score.

> **The scan cannot prove an extension is safe.** It flags risk signals. Many legitimate extensions run processes (language servers, formatters) or read credentials for their own features, so read the reasons before acting. The scan never uninstalls, disables or modifies anything. It only links to the extension's page and its install folder.

Signals:

| Source | Signals (weight) |
|---|---|
| Manifest | activates on `*` (+2) or `onStartupFinished` (+1) · runs in untrusted workspaces (+1) · more than 3 `extensionDependencies` (+1) · installed from a VSIX file (+1) · identifier resembles a popular extension, e.g. `ms-pythom.python` (+4) · publisher not on the built-in trusted list (0, amplifies others) · Marketplace install from a well-known publisher (−2) |
| Code (bundled JS, incl. `node_modules`) | `child_process` (+1) · `eval` / `new Function` / `vm.run*` / computed `require()` (+1) · literal public IP (+2) · webhook / paste / tunnel / IP-lookup service (+3) · credential store paths such as `~/.ssh/id_*`, `.aws/credentials`, browser `Login Data`, VS Code `state.vscdb`, wallets and the keychain CLI (+3) · clipboard reads or keyboard hooks (+2) · javascript-obfuscator output or an encoded payload next to `eval` (+3) · native binaries (+1) |
| Known-bad list | listed in Microsoft's [RemovedPackages.md](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md): *Malware* forces **high**; *Impersonation*, *Untrustworthy* and *Expired domain* add +6; *Spam* and owner requests are informational |
| Marketplace (opt-in) | not listed (+3) · unverified publisher (+1) · fewer than 1,000 installs (+1) · no update for 2 years (0) · verified publisher (−1) |

Each signal counts **once**, however often it occurs. Some signals only add up when they appear together:
- Credential paths plus a network endpoint: +4.
- Obfuscation plus code evaluation: +2.
- Unknown publisher plus startup activation plus process or input capture: +2.

Scores map to levels: 5 or more is **medium** and 9 or more is **high**. A score reaches high only through one of these combinations or a known-bad entry. Otherwise it is capped at medium, so a well-behaved tool with many capabilities doesn't look like malware.

Code hits open read-only at the exact file and line. Code is scanned with the same tree-sitter rule engine as the other checks, in a worker thread. Results are cached per extension version, so only new or updated extensions are scanned again.

- **Trust (Allowlist)…** on an extension lists its reasons without scoring them. Trusting `publisher.name@version` covers only that version, so an update is scored again. A *Malware* listing overrides the allowlist.
- **Export Extension Risk Report** writes SARIF (one `ext/risk` result per extension, plus every finding) or Markdown.

Privacy: the scan reads files locally. Two opt-in settings use the network:

| Setting | Sends | Default |
|---|---|---|
| `endpointSecurity.extensionScan.marketplaceLookup` | the identifiers of your installed extensions, to the VS Marketplace | off |
| `endpointSecurity.extensionScan.updateKnownBadList` | nothing (downloads the public list from GitHub weekly) | off |

With both off, the scan uses the list bundled with this version. **Update Known-Bad Extension List** refreshes it on demand.

Other settings:
- `extensionScan.includeBuiltin`: also scan VS Code's own extensions (default off).
- `includeNodeModules`: also scan dependencies (default on).
- `maxFileSizeMB`: largest file scanned (default 10).
- `maxFilesPerExtension`: file limit per extension (default 2000).
- `trustedPublishers`: add your organisation's publisher ids.

## Sources

- [Microsoft — Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
- [Microsoft — Event Tracing for Windows](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [Apple — Endpoint Security](https://developer.apple.com/documentation/endpointsecurity)
- [PCI DSS v4.0.1](https://www.pcisecuritystandards.org/document_library/)
- [ISC2 CCSP Exam Outline (Domain 2: Cloud Data Security)](https://www.isc2.org/certifications/ccsp/ccsp-certification-exam-outline)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [VS Code — Extension runtime security](https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security)
- [microsoft/vsmarketplace — Removed extensions](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md)
