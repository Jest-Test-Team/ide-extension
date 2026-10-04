# Security & Systems Engineering Pack

Installs the Endpoint Security & Compliance Toolkit, the Julia Invalidation & Compiler Profiler and the Embedded Hardware Security Workbench together.

## Command line

**Security Pack: Install 'jest-security' Command in PATH** adds one command for all three tools:

```bash
jest-security scan . -o security.sarif      # every rule set → one SARIF file
jest-security lint src firmware --format md
jest-security endpoint simulate attack.ptree.yaml
jest-security hw entropy trng.bin --bits 8
jest-security julia report profile.json
jest-security doctor                        # check data files, julia and git
```

The same tools are on npm as `@jest-test-team/security-cli`, which provides `jest-security`, `jest-endpoint`, `jest-hw` and `jest-julia`.
