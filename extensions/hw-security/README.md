# Embedded Hardware Security Workbench

Security tooling for ESP32 firmware, entropy sources / PUFs and side-channel evaluation.

## ESP32 / ESPHome firmware linter

Runs on C/C++ (ESP-IDF, Arduino), `sdkconfig` and ESPHome YAML. Every finding links to the Espressif documentation or CWE it is based on; quick fixes and `// ide-ext-ignore-next-line <rule>` suppressions are available.

| Area | Rules |
|---|---|
| Memory safety | unbounded `strcpy`/`sprintf`/`gets`… · copy sizes taken from a parameter or packet (`info->len`, `bufsize`) without a bounds check — CSI, ESP-NOW, BLE, USB HID handlers · unchecked `malloc`/`heap_caps_malloc` · non-literal format strings (fix: `"%s"`) |
| Error handling | ignored `esp_err_t` (fix: wrap in `ESP_ERROR_CHECK`) |
| Concurrency | non-ISR-safe calls in `IRAM_ATTR` / registered ISRs (suggests `…FromISR`) · logging/allocation/I/O in the Wi-Fi CSI callback |
| Randomness & secrets | `esp_random()` with no RF / `bootloader_random_enable()` · `rand()` for security values · hard-coded passwords, PSKs and key arrays · disabled TLS verification |
| Root of trust (`sdkconfig`) | Secure Boot v2 off or insecure · flash encryption off / Development mode · UART bootloader decrypt/encrypt/cache · insecure ROM download mode · NVS encryption · ESP-TLS insecure / skip verify · memory protection · stack protector · verbose logs |
| ESPHome | plaintext secrets instead of `!secret` · API without `encryption:` · OTA without password · web server without `auth:` |

**HW Security: Scan Workspace** lints every firmware file. Add your own YAML/JSON rule packs with `hwSecurity.lint.rulePacks` (same schema as the built-in rules).

## Entropy source assessment (NIST SP 800-90B)

**Assess Entropy Source (SP 800-90B)…** (also in the Explorer context menu for `.bin`) runs the full non-IID track — Most Common Value, Collision, Markov, Compression, t-Tuple, LRS, MultiMCW, Lag, MultiMMC and LZ78Y — on literal samples and the bitstring, and reports `H_original`, `H_bitstring` and the assessed min-entropy. The implementation is a port of NIST's reference code and matches `ea_non_iid` to 1e-9 on the bundled validation datasets. Set `hwSecurity.nist.eaNonIidPath` to cross-check every run against your own build of the NIST tool.

**Run Restart Test (SP 800-90B 3.1.4)…** validates an entropy claim `H_I` from 1000 × 1000 restart data (sanity check + row/column estimates).

Inputs: binary files with one sample per byte (NIST convention) or text files with integers. The IID-track permutation tests (section 5) are not implemented; use NIST `ea_iid` for an IID claim.

## PUF analysis

**Analyze PUF Responses…** reads a CSV (`device,read,response`, responses as 0/1 or hex) from SRAM or quantum-tunnelling PUFs and reports uniformity, uniqueness, reliability / bit error rate, bit-aliasing, per-bit min-entropy and unstable cells, with inter/intra Hamming-distance histograms. An ECC model (`hwSecurity.puf.eccBlockBits`, `targetFailureRate`) computes the error-correction capability needed for key reconstruction.

## Side-channel tags (ChipWhisperer)

Mark leakage points in firmware and reference them from analysis scripts:

```c
// @sca(aes-sbox, "S-box lookup indexed by plaintext ^ key byte")
state[i] = sbox[state[i] ^ key[i]];
```
```python
# @sca-ref(aes-sbox)
attack = cwa.cpa(project, cwa.leakage_models.sbox_output)
```

- Go to Definition / Find References in both directions, CodeLens links, and id completion.
- The **Side-Channel Points** view lists each point, analysed or not.
- Diagnostics flag duplicate ids and references without a tag.
- Hints suggest tags for untagged secret-indexed table lookups, secret-dependent branches and early-exit `memcmp` of MACs in crypto functions.

## Command line

The same features are available as `jest-hw` (alias `jest-embedded`), for terminals and CI pipelines:
- **Install from VS Code:** **HW Security: Install 'jest-hw' Command in PATH**. It needs no Node.js.
- **Install from npm:** `npm i -g @jest-test-team/security-cli`.

```bash
jest-hw lint firmware/ sdkconfig esphome/
jest-hw entropy trng.bin --bits 8 --min 7.5
jest-hw restart restarts.bin --hi 7 --bits 8
jest-hw puf sram.csv --ecc-bits 255 --target 1e-9
jest-hw sca firmware/ analysis/                  # exit 1 on orphan / duplicate tags
```

- Reports: `--format text|json|sarif|md`.
- Exit codes: `1` on findings or a failed check, so the commands work as CI gates.
- Options: see `jest-hw <command> --help`.

## Sources

- [Espressif — ESP-IDF Security](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/security.html)
- [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final) and [SP800-90B_EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment)
- [ChipWhisperer documentation](https://chipwhisperer.readthedocs.io/)
- Maiti, Gunreddy & Schaumont, *A Systematic Method to Evaluate and Compare the Performance of Physical Unclonable Functions* (2013)
