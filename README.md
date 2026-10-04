# ide-extension

Three VS Code extensions for security and systems engineering, plus an extension pack:

| Extension | Folder | What it does |
|---|---|---|
| **Endpoint Security & Compliance Toolkit** | [`extensions/endpoint-security`](extensions/endpoint-security/README.md) | WFP / ETW / Endpoint Security API hover + validation, PCI DSS 4.0.1 & CCSP D2 compliance scan with SARIF export, process-tree detection simulation, risk scan of installed VS Code extensions |
| **Julia Invalidation & Compiler Profiler** | [`extensions/julia-profiler`](extensions/julia-profiler/README.md) | SnoopCompile.jl invalidation tree & inference flame graph, invalidation linter, benchmark judge vs. git baseline |
| **Embedded Hardware Security Workbench** | [`extensions/hw-security`](extensions/hw-security/README.md) | ESP32/ESPHome security linter, NIST SP 800-90B entropy & restart tests, PUF metrics, ChipWhisperer side-channel tags |
| Security & Systems Engineering Pack | `extensions/security-pack` | Installs all three; `jest-security` CLI |
| Command-line tools | [`packages/cli`](packages/cli/README.md) | `jest-endpoint`, `jest-hw` (`jest-embedded`), `jest-julia`, `jest-security` — npm package `@jest-test-team/security-cli` |

Shared code lives in [`packages/core`](packages/core): a web-tree-sitter host, the declarative rule engine (tree-sitter queries, regex/absent rules and code rules — every rule cites its sources), diagnostics with quick fixes and suppressions, SARIF/Markdown reports, and webview helpers. Each extension bundles it with esbuild.

**Languages:** [English](#install--use) · [繁體中文](#安裝與使用) · CLI guide: [English](#cli-step-by-step) · [繁體中文](#命令列工具逐步教學)

## Install & use

### Install

Build the packages with `npm install && npm run package`, then install them. Install the three extensions first and the pack last: the pack refers to the others by Marketplace ID, so on its own it would try to download them from the Marketplace.

```bash
code --install-extension vsix/endpoint-security-0.3.2.vsix
code --install-extension vsix/julia-profiler-0.2.2.vsix
code --install-extension vsix/hw-security-0.2.2.vsix
code --install-extension vsix/security-pack-0.2.2.vsix   # optional
```

You can also use the Extensions view → `…` → **Install from VSIX…**.

### How to use

Most features run automatically when you open a matching file. The rest are commands: press **⌘⇧P** (Ctrl+Shift+P on Windows/Linux) and type the extension's prefix (`Endpoint Security:`, `HW Security:` or `Julia Profiler:`). Endpoint Security (**shield** icon), HW Security (**chip** icon) and the Julia Profiler (**flame** icon) also add views to the activity bar.

The quickest way to try everything is to open the sample files in each extension's `test/fixtures` folder. They are written to trigger the features.

#### Endpoint Security & Compliance Toolkit

- **API checks (C / C++ / Rust):** open `extensions/endpoint-security/test/fixtures/agent/esf_client.c`.
  - Squiggles mark leaked or misused API calls; they're also listed in the Problems panel (**⌘⇧M**).
  - Hover over `es_new_client` to see its signature, pitfalls and a docs link.
  - Type `FwpmFilterAdd0(` to get parameter hints.
  - Press **⌘.** on a finding for quick fixes, such as replacing `es_free_message` or suppressing a rule.
- **Compliance scan (Go / TypeScript):** open `test/fixtures/backend/payments.go` or `payments.ts`. Findings cite the PCI DSS or CCSP requirement they're based on.
  - **Endpoint Security: Scan Workspace** checks the whole project.
  - **Endpoint Security: Export Compliance Report** saves the results as `.sarif` (for GitHub code scanning) or `.md`.
- **Process-tree simulation:** open `test/fixtures/scenarios/ransom.ptree.yaml` and click **▶ Simulate** at the top of the file.
  - A panel shows the process tree, detections with MITRE ATT&CK links, and a timeline; click a timeline row to jump to its line in the YAML.
  - **New Process-Tree Scenario** creates a template. Nothing is executed: the simulation only replays the event data.
- **Installed extension risk scan:** click the **shield** icon, then **Scan Installed Extensions**.
  - Each extension gets **low / medium / high**. Expand it to see the reasons, and click a code reason to open the file at that line.
  - The scan is heuristic: it can't prove an extension safe, and tools such as language servers legitimately run processes. Right-click → **Trust (Allowlist)…** for extensions you trust.
  - It reads files only and never uninstalls anything. Network lookups (Marketplace reputation, a fresh removed-extensions list) are opt-in settings.

#### Embedded Hardware Security Workbench

- **ESP32 linter:** open `extensions/hw-security/test/fixtures/esp-app/main/csi_main.c`, `esp-app/sdkconfig` or `esphome/livingroom.yaml`. Warnings appear automatically, for example unsafe `strcpy`, ignored `esp_err_t` (**⌘.** wraps it in `ESP_ERROR_CHECK`), or Secure Boot disabled.
- **Entropy test:** right-click `test/fixtures/entropy/rand8_short.bin` → **Assess Entropy Source (SP 800-90B)…** and choose **8** bits per sample. A report opens with the assessed min-entropy, a chart for each estimator, and Export buttons. **Run Restart Test…** validates an entropy claim from 1000 × 1000 restart data.
- **PUF analysis:** right-click `test/fixtures/puf/sram.csv` → **Analyze PUF Responses…**
- **Side-channel tags:**
  1. Open `test/fixtures/sca/firmware/aes.c` and `sca/analysis/cpa_attack.py`.
  2. **⌘-click** `aes-sbox` in the Python file to jump to the C code.
  3. Click the **chip** icon to see all tagged points.

  Use **Insert Side-Channel Tag** in your own code.

#### Julia Invalidation & Compiler Profiler

- **Without Julia installed:**
  1. Click the **flame** icon → **Open Profile JSON…** and pick `extensions/julia-profiler/test/fixtures/invdemo.profile.json`.
  2. The sidebar now lists the methods that caused invalidations; the graph icon at the top of that view opens the flame graph.
  3. Open `test/fixtures/InvDemo/src/InvDemo.jl` to see the linter warnings. On the `x::Real` field, **⌘.** turns it into a type parameter.
- **With Julia installed** (`brew install julia` or juliaup):
  - Open a Julia project and run **Julia Profiler: Analyze Invalidations & Inference**. The first run installs SnoopCompile into a separate tool environment, so your project is never modified.
  - **Run Benchmarks & Compare…** compares the working tree with a git commit. It needs a `benchmark/benchmarks.jl`, which the extension can create for you.

#### Settings

Open **⌘,** and search `endpointSecurity`, `hwSecurity` or `juliaProfiler` to:
- switch individual rules off (`…disabledRules`);
- add your own YAML rule packs (`…rulePacks`);
- set the Julia path or the NIST `ea_non_iid` cross-check binary.

Each extension's **Details** tab in the Extensions view contains its full documentation.

### Command-line tools

Every extension also works from a terminal or CI pipeline:

| Command | Extension | Commands |
|---|---|---|
| `jest-endpoint` | Endpoint Security & Compliance Toolkit | `lint`, `compliance`, `simulate`, `api`, `agent`, `extensions` |
| `jest-hw` (alias `jest-embedded`) | Embedded Hardware Security Workbench | `lint`, `entropy`, `restart`, `puf`, `sca` |
| `jest-julia` | Julia Invalidation & Compiler Profiler | `lint`, `analyze`, `report`, `bench`, `init` |
| `jest-security` | Security & Systems Engineering Pack | `lint`, `scan`, `doctor`, plus `endpoint` / `hw` / `julia …` |

**Get them** in one of two ways:
- **From VS Code** (no Node.js needed): **⌘⇧P → Install '<tool>' Command in PATH**, e.g. *Endpoint Security: Install 'jest-endpoint' Command in PATH*.
  - The command goes into `~/.local/bin` (Windows: `%LOCALAPPDATA%\Programs\jest-cli`). If that folder isn't on your PATH, VS Code shows the line to add.
  - The pack's command installs `jest-security`.
- **From npm:** `npm i -g @jest-test-team/security-cli` installs all five commands. From this repo: `npm run build -w @jest-test-team/security-cli`, then `node packages/cli/dist/jest-security.js`.

**Examples:**

```bash
jest-endpoint lint src/                                   # API misuse + PCI DSS / CCSP findings
jest-endpoint compliance services/ -f sarif -o pci.sarif  # SARIF for GitHub code scanning
jest-endpoint simulate attack.ptree.yaml --expect lsass-access
jest-endpoint extensions                                  # risk-scan installed VS Code / Cursor extensions
jest-hw lint firmware/ sdkconfig
jest-hw entropy trng.bin --bits 8 --min 7.5               # NIST SP 800-90B, fails below 7.5 bits/sample
jest-julia analyze --max-invalidated 0                    # SnoopCompile, fails on any invalidation
jest-julia bench --baseline main                          # fails on benchmark regressions
jest-security scan . -o security.sarif                    # every rule set, one SARIF file
```

**Output:**
- Every command has `--help`, and the lint-style commands support `--format text|json|sarif|md` and `--out`.
- **Exit codes:** `0` clean, `1` findings at or above `--fail-on` (or a failed test / threshold), `2` usage or runtime error. This makes the commands CI gates.
- Full reference: [`packages/cli/README.md`](packages/cli/README.md). New to the CLI? Follow [CLI step by step](#cli-step-by-step).

### CLI step by step

#### Step 1 — Install the commands (choose one way)

**Option A — from VS Code (recommended, no Node.js needed)**

1. Install the extensions (see [Install](#install)).
2. Press **⌘⇧P** (Ctrl+Shift+P) and run the install command for each tool you want:

   | Command Palette entry | Installs |
   |---|---|
   | *Endpoint Security: Install 'jest-endpoint' Command in PATH* | `jest-endpoint` |
   | *HW Security: Install 'jest-hw / jest-embedded' Command in PATH* | `jest-hw`, `jest-embedded` |
   | *Julia Profiler: Install 'jest-julia' Command in PATH* | `jest-julia` |
   | *Security Pack: Install 'jest-security' Command in PATH* | `jest-security` (all tools) |

3. The commands are written to `~/.local/bin` (macOS/Linux) or `%LOCALAPPDATA%\Programs\jest-cli` (Windows).
   If VS Code says the folder is not on your PATH, click **Copy Command** and add the line to your shell profile:

   ```bash
   # macOS (zsh) — Linux: use ~/.bashrc
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc
   ```

   On Windows, run the copied `setx PATH …` line, then open a new terminal.

**Option B — from this repository (needs Node.js 20+)**

```bash
git clone https://github.com/Jest-Test-Team/ide-extension.git
cd ide-extension
npm install
npm run build -w @jest-test-team/security-cli
npm install -g ./packages/cli      # links jest-endpoint, jest-hw, jest-embedded, jest-julia, jest-security
```

To use the tools without a global install, run them directly: `node packages/cli/dist/jest-security.js --help`.

**Option C — from npm (once the package is published)**

```bash
npm install -g @jest-test-team/security-cli
```

#### Step 2 — Check the installation

Open a **new** terminal, then:

```bash
jest-security --version
jest-security doctor          # ✔ for every bundled data folder; shows whether julia and git were found
jest-endpoint --help          # list of commands; "jest-endpoint <command> --help" shows the options
```

#### Step 3 — Try every tool on the sample files

Run these from the root of this repository; every path points to a sample file that ships with it.

**Endpoint Security (`jest-endpoint`)**

```bash
# 1. WFP / ETW / Endpoint Security API misuse in C, C++ and Rust → exit code 1 (errors found)
jest-endpoint lint extensions/endpoint-security/test/fixtures/agent

# 2. PCI DSS 4.0.1 / CCSP compliance of Go and TypeScript code, as a SARIF file
jest-endpoint compliance extensions/endpoint-security/test/fixtures/backend --format sarif --out compliance.sarif

# 3. Replay a ransomware scenario: process tree, 10 detections, timeline (nothing is executed)
jest-endpoint simulate extensions/endpoint-security/test/fixtures/scenarios/ransom.ptree.yaml --expect mass-file-encryption

# 4. Look up an API, or list all known ones
jest-endpoint api OpenTraceW
jest-endpoint api --list

# 5. Risk-scan the VS Code / Cursor extensions installed on this machine (read-only)
jest-endpoint extensions
```

**Embedded Hardware Security (`jest-hw`, alias `jest-embedded`)**

```bash
# 1. ESP32 C code, sdkconfig and ESPHome YAML → 26 problems in the samples
jest-hw lint extensions/hw-security/test/fixtures/esp-app extensions/hw-security/test/fixtures/esphome

# 2. NIST SP 800-90B entropy of a noise-source dump → "Assessed min-entropy: 5.860894 bits/sample"
jest-hw entropy extensions/hw-security/test/fixtures/entropy/rand8_short.bin --bits 8

# 3. PUF quality (uniformity, uniqueness, reliability…) and the ECC needed
jest-hw puf extensions/hw-security/test/fixtures/puf/sram.csv

# 4. Side-channel tags between firmware and ChipWhisperer scripts → exit 1: one reference has no tag
jest-hw sca extensions/hw-security/test/fixtures/sca
```

**Julia Profiler (`jest-julia`)**

```bash
# 1. Invalidation / inference problems in Julia code (warnings → exit code 0 unless --fail-on warning)
jest-julia lint extensions/julia-profiler/test/fixtures/InvDemo

# 2. Summarise a recorded SnoopCompile profile
jest-julia report extensions/julia-profiler/test/fixtures/invdemo.profile.json

# 3. With Julia installed: profile a real package, then compare benchmarks with git HEAD
cd extensions/julia-profiler/test/fixtures/InvDemo
jest-julia analyze --out profile.json        # first run installs SnoopCompile into ~/.cache/jest-julia
jest-julia bench --baseline HEAD --seconds 0.2
cd -
```

**Everything at once (`jest-security`)**

```bash
jest-security lint extensions --format md --out findings.md      # all rule sets, Markdown report
jest-security scan extensions --out security.sarif               # all rule sets, one SARIF file
jest-security hw entropy extensions/hw-security/test/fixtures/entropy/rand8_short.bin --bits 8   # any sub-tool
```

#### Step 4 — Use it on your own project

```bash
cd ~/my-project
jest-security lint .                          # human-readable report
jest-security lint . --fail-on warning        # stricter: warnings also fail
jest-endpoint lint . --disable edr/etw-broad-enable --rule-pack team-rules.yaml
```

- **Formats:** `--format text` (default), `json`, `sarif` or `md`; add `--out <file>` to write to a file.
- **Exit codes:** `0` = clean, `1` = findings at or above `--fail-on` or a failed check, `2` = wrong usage or error.
- **Ignore one line:** put `// ide-ext-ignore-next-line <rule-id>` above it (`#` in Julia / YAML / sdkconfig). For a whole file, add `// ide-ext-ignore-file <rule-id>` anywhere in it.
- **Skip folders:** create a `.jestignore` (gitignore syntax) in the folder you run the command from, or pass `--ignore 'vendor/**'`. Paths you name explicitly are always scanned; `--no-ignore-file` turns the file off.

#### Step 5 — Run it in CI (GitHub Actions)

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write        # needed to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g @jest-test-team/security-cli
      - run: jest-security scan . --out security.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security.sarif
      - run: jest-hw entropy firmware/trng-dump.bin --bits 8 --min 7.5   # optional gate
```

#### Step 6 — Update or uninstall

- **VS Code commands:** after an extension update the command is refreshed automatically. To remove it, run *… Uninstall '<tool>' Command* from the Command Palette; it deletes only files it created.
- **npm:** `npm update -g @jest-test-team/security-cli` / `npm uninstall -g @jest-test-team/security-cli`.

#### Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: jest-…` right after installing | zsh caches the commands it knows: run `rehash` (or `hash -r` in bash), or open a new terminal. |
| `command not found: jest-…` in a new terminal | Check that `echo $PATH` contains `~/.local/bin` (Option A) or your npm global bin (`npm prefix -g`), and that the file exists: `ls ~/.local/bin/jest-*`. If it's missing, run the *Install '…' Command in PATH* entry again (reload the VS Code window first after updating the extensions). |
| `code --install-extension` didn't update VS Code | Your `code` command may belong to another editor (`ls -l $(which code)`; e.g. Cursor). Use VS Code's own CLI: `"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" --install-extension …`. |
| Findings from sample or vendored code | List folders to skip in a `.jestignore` file (gitignore syntax) or pass `--ignore <glob>`; this repo's `.jestignore` skips `test/fixtures`. |
| `cannot find the "grammars" data folder` | The bundled data is missing: reinstall, or set `JEST_ASSETS` to a folder with `grammars/`, `rules/`, `ptree/`, `extscan/`, `scripts/`. |
| `Julia not found` | Install Julia (`brew install julia` or juliaup) or pass `--julia /path/to/julia` (or set `$JULIA`). |
| `bench`: *not a git repository* | Run inside a git checkout, or use `--baseline none`. |
| `restart`: *must contain 1000 × 1000 samples* | Restart data is 1000 restarts × 1000 samples, row-major; use `--rows` for a smaller square matrix. |

## 安裝與使用

### 安裝

先執行 `npm install && npm run package` 產生安裝檔，再進行安裝。請先安裝三個擴充套件，最後才裝 Pack：Pack 以 Marketplace ID 引用其他三個套件，若單獨安裝，它會嘗試從 Marketplace 下載。

```bash
code --install-extension vsix/endpoint-security-0.3.2.vsix
code --install-extension vsix/julia-profiler-0.2.2.vsix
code --install-extension vsix/hw-security-0.2.2.vsix
code --install-extension vsix/security-pack-0.2.2.vsix   # 選用
```

也可以在「擴充功能」檢視中點選 `…` → **從 VSIX 安裝…**。

### 使用方式

大多數功能在開啟對應檔案時會自動執行，其餘功能以命令操作：按 **⌘⇧P**（Windows/Linux 為 Ctrl+Shift+P），輸入擴充套件的前綴（`Endpoint Security:`、`HW Security:` 或 `Julia Profiler:`）。Endpoint Security（**盾牌**圖示）、HW Security（**晶片**圖示）與 Julia Profiler（**火焰**圖示）也會在左側活動列加入檢視。

最快的試用方式是開啟各擴充套件 `test/fixtures` 資料夾中的範例檔案，這些檔案是為了觸發各項功能而設計的。

#### Endpoint Security & Compliance Toolkit（端點安全與合規工具組）

- **API 檢查（C / C++ / Rust）**：開啟 `extensions/endpoint-security/test/fixtures/agent/esf_client.c`。
  - 有資源洩漏或誤用的 API 呼叫會出現波浪線，也會列在「問題」面板（**⌘⇧M**）。
  - 將游標停在 `es_new_client` 上，可查看函式簽章、常見陷阱與官方文件連結。
  - 輸入 `FwpmFilterAdd0(` 會顯示參數提示。
  - 在問題上按 **⌘.** 可套用快速修正，例如替換 `es_free_message` 或抑制規則。
- **合規掃描（Go / TypeScript）**：開啟 `test/fixtures/backend/payments.go` 或 `payments.ts`。每個問題都會註明所依據的 PCI DSS 或 CCSP 條款。
  - **Endpoint Security: Scan Workspace** 掃描整個專案。
  - **Endpoint Security: Export Compliance Report** 將結果匯出為 `.sarif`（供 GitHub code scanning 使用）或 `.md`。
- **程序樹模擬**：開啟 `test/fixtures/scenarios/ransom.ptree.yaml`，點選檔案頂端的 **▶ Simulate**。
  - 面板會顯示程序樹、附 MITRE ATT&CK 連結的偵測結果與時間軸；點選時間軸的列可跳到 YAML 中對應的行。
  - **New Process-Tree Scenario** 可建立範本。模擬只重播事件資料，不會執行任何程式。
- **已安裝擴充套件風險掃描**：點選**盾牌**圖示，再按 **Scan Installed Extensions**。
  - 每個擴充套件會標示 **low / medium / high** 風險；展開可查看原因，點選程式碼原因會開啟檔案並跳到該行。
  - 這是啟發式掃描：無法證明擴充套件安全，語言伺服器等工具本來就會執行程序。信任的擴充套件可按右鍵 → **Trust (Allowlist)…**。
  - 掃描只讀取檔案，不會解除安裝任何東西。需要網路的查詢（Marketplace 信譽、更新已下架清單）皆須在設定中自行開啟。

#### Embedded Hardware Security Workbench（嵌入式硬體安全工作台）

- **ESP32 檢查**：開啟 `extensions/hw-security/test/fixtures/esp-app/main/csi_main.c`、`esp-app/sdkconfig` 或 `esphome/livingroom.yaml`。警告會自動出現，例如不安全的 `strcpy`、忽略 `esp_err_t`（按 **⌘.** 可包上 `ESP_ERROR_CHECK`）、未啟用 Secure Boot 等。
- **熵源評估**：在 `test/fixtures/entropy/rand8_short.bin` 上按右鍵 → **Assess Entropy Source (SP 800-90B)…**，每個樣本位元數選 **8**。報告會顯示評估後的最小熵、各估計器的圖表與匯出按鈕。**Run Restart Test…** 可用 1000 × 1000 的重啟資料驗證熵值宣告。
- **PUF 分析**：在 `test/fixtures/puf/sram.csv` 上按右鍵 → **Analyze PUF Responses…**
- **旁通道標記**：
  1. 開啟 `test/fixtures/sca/firmware/aes.c` 與 `sca/analysis/cpa_attack.py`。
  2. 在 Python 檔中對 `aes-sbox` 按 **⌘-點擊**，即可跳到 C 程式碼。
  3. 點選**晶片**圖示可查看所有標記點。

  在自己的程式碼中可使用 **Insert Side-Channel Tag** 插入標記。

#### Julia Invalidation & Compiler Profiler（Julia 失效與編譯分析器）

- **未安裝 Julia 時**：
  1. 點選**火焰**圖示 → **Open Profile JSON…**，選擇 `extensions/julia-profiler/test/fixtures/invdemo.profile.json`。
  2. 側邊欄會列出造成失效的方法；點選該檢視頂端的圖表圖示可開啟火焰圖。
  3. 開啟 `test/fixtures/InvDemo/src/InvDemo.jl` 查看檢查警告。在 `x::Real` 欄位上按 **⌘.**，可將它改為型別參數。
- **已安裝 Julia 時**（`brew install julia` 或 juliaup）：
  - 開啟 Julia 專案並執行 **Julia Profiler: Analyze Invalidations & Inference**。第一次執行會把 SnoopCompile 安裝到獨立的工具環境，不會修改你的專案。
  - **Run Benchmarks & Compare…** 會比較工作目錄與某個 git commit 的效能。需要 `benchmark/benchmarks.jl`，擴充套件可以替你建立。

#### 設定

按 **⌘,** 搜尋 `endpointSecurity`、`hwSecurity` 或 `juliaProfiler`，即可：
- 關閉個別規則（`…disabledRules`）；
- 加入自訂的 YAML 規則包（`…rulePacks`）；
- 設定 Julia 路徑或 NIST `ea_non_iid` 交叉驗證程式。

在「擴充功能」檢視中點選各擴充套件的 **Details** 分頁，可查看完整文件。

### 命令列工具

每個擴充套件也能在終端機或 CI 流程中使用：

| 指令 | 擴充套件 | 子命令 |
|---|---|---|
| `jest-endpoint` | 端點安全與合規工具組 | `lint`、`compliance`、`simulate`、`api`、`agent`、`extensions` |
| `jest-hw`（別名 `jest-embedded`） | 嵌入式硬體安全工作台 | `lint`、`entropy`、`restart`、`puf`、`sca` |
| `jest-julia` | Julia 失效與編譯分析器 | `lint`、`analyze`、`report`、`bench`、`init` |
| `jest-security` | 安全與系統工程套件包 | `lint`、`scan`、`doctor`，以及 `endpoint` / `hw` / `julia …` |

**取得方式**（擇一）：
- **從 VS Code 安裝**（不需要 Node.js）：**⌘⇧P → Install '<tool>' Command in PATH**，例如 *Endpoint Security: Install 'jest-endpoint' Command in PATH*。
  - 指令會安裝到 `~/.local/bin`（Windows：`%LOCALAPPDATA%\Programs\jest-cli`）。若該資料夾不在 PATH 中，VS Code 會顯示需要加入的設定。
  - Pack 的命令會安裝 `jest-security`。
- **從 npm 安裝**：`npm i -g @jest-test-team/security-cli` 會一次安裝全部五個指令。在本 repo 中：先執行 `npm run build -w @jest-test-team/security-cli`，再執行 `node packages/cli/dist/jest-security.js`。

**範例：**

```bash
jest-endpoint lint src/                                   # API 誤用 + PCI DSS / CCSP 問題
jest-endpoint compliance services/ -f sarif -o pci.sarif  # 產生 GitHub code scanning 用的 SARIF
jest-endpoint simulate attack.ptree.yaml --expect lsass-access
jest-endpoint extensions                                  # 掃描已安裝的 VS Code / Cursor 擴充套件風險
jest-hw lint firmware/ sdkconfig
jest-hw entropy trng.bin --bits 8 --min 7.5               # NIST SP 800-90B，低於 7.5 位元/樣本即失敗
jest-julia analyze --max-invalidated 0                    # SnoopCompile，出現任何失效即失敗
jest-julia bench --baseline main                          # 效能退步時失敗
jest-security scan . -o security.sarif                    # 所有規則，輸出單一 SARIF 檔
```

**輸出：**
- 每個指令都支援 `--help`；檢查類命令支援 `--format text|json|sarif|md` 與 `--out`。
- **結束碼**：`0` 無問題；`1` 有達到 `--fail-on` 門檻的問題（或測試、門檻未通過）；`2` 用法或執行錯誤。因此可直接作為 CI 關卡。
- 完整說明：[`packages/cli/README.md`](packages/cli/README.md)。第一次使用？請參考[命令列工具：逐步教學](#命令列工具逐步教學)。

### 命令列工具：逐步教學

#### 步驟 1 — 安裝指令（三選一）

**方式 A — 從 VS Code 安裝（建議，不需要 Node.js）**

1. 先安裝擴充套件（見[安裝](#安裝)）。
2. 按 **⌘⇧P**（Ctrl+Shift+P），執行想要的工具的安裝命令：

   | 命令選擇區項目 | 安裝的指令 |
   |---|---|
   | *Endpoint Security: Install 'jest-endpoint' Command in PATH* | `jest-endpoint` |
   | *HW Security: Install 'jest-hw / jest-embedded' Command in PATH* | `jest-hw`、`jest-embedded` |
   | *Julia Profiler: Install 'jest-julia' Command in PATH* | `jest-julia` |
   | *Security Pack: Install 'jest-security' Command in PATH* | `jest-security`（所有工具） |

3. 指令會寫入 `~/.local/bin`（macOS/Linux）或 `%LOCALAPPDATA%\Programs\jest-cli`（Windows）。
   若 VS Code 提示該資料夾不在 PATH 中，點選 **Copy Command**，並把設定加入 shell 設定檔：

   ```bash
   # macOS（zsh）— Linux 請改用 ~/.bashrc
   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
   source ~/.zshrc
   ```

   Windows 請執行複製的 `setx PATH …`，再開啟新的終端機。

**方式 B — 從本 repo 安裝（需要 Node.js 20 以上）**

```bash
git clone https://github.com/Jest-Test-Team/ide-extension.git
cd ide-extension
npm install
npm run build -w @jest-test-team/security-cli
npm install -g ./packages/cli      # 建立 jest-endpoint、jest-hw、jest-embedded、jest-julia、jest-security 指令
```

若不想全域安裝，也可以直接執行：`node packages/cli/dist/jest-security.js --help`。

**方式 C — 從 npm 安裝（套件發佈後）**

```bash
npm install -g @jest-test-team/security-cli
```

#### 步驟 2 — 確認安裝

開啟**新的**終端機，然後執行：

```bash
jest-security --version
jest-security doctor          # 每個內建資料夾都應顯示 ✔，並列出是否找到 julia 與 git
jest-endpoint --help          # 列出子命令；「jest-endpoint <子命令> --help」顯示選項
```

#### 步驟 3 — 用範例檔試用每個工具

請在本 repo 根目錄執行以下指令；路徑都指向 repo 內附的範例檔。

**端點安全（`jest-endpoint`）**

```bash
# 1. C / C++ / Rust 中 WFP / ETW / Endpoint Security API 的誤用 → 結束碼 1（有錯誤）
jest-endpoint lint extensions/endpoint-security/test/fixtures/agent

# 2. Go 與 TypeScript 程式碼的 PCI DSS 4.0.1 / CCSP 合規檢查，輸出 SARIF 檔
jest-endpoint compliance extensions/endpoint-security/test/fixtures/backend --format sarif --out compliance.sarif

# 3. 重播勒索軟體情境：程序樹、10 個偵測結果、時間軸（不會執行任何程式）
jest-endpoint simulate extensions/endpoint-security/test/fixtures/scenarios/ransom.ptree.yaml --expect mass-file-encryption

# 4. 查詢 API 說明，或列出所有支援的 API
jest-endpoint api OpenTraceW
jest-endpoint api --list

# 5. 掃描本機已安裝的 VS Code / Cursor 擴充套件風險（唯讀）
jest-endpoint extensions
```

**嵌入式硬體安全（`jest-hw`，別名 `jest-embedded`）**

```bash
# 1. ESP32 C 程式碼、sdkconfig 與 ESPHome YAML → 範例共有 26 個問題
jest-hw lint extensions/hw-security/test/fixtures/esp-app extensions/hw-security/test/fixtures/esphome

# 2. 雜訊源資料的 NIST SP 800-90B 熵評估 →「Assessed min-entropy: 5.860894 bits/sample」
jest-hw entropy extensions/hw-security/test/fixtures/entropy/rand8_short.bin --bits 8

# 3. PUF 品質（均勻性、唯一性、可靠度…）與所需的錯誤更正能力
jest-hw puf extensions/hw-security/test/fixtures/puf/sram.csv

# 4. 韌體與 ChipWhisperer 腳本間的旁通道標記 → 結束碼 1：有一個引用找不到對應標記
jest-hw sca extensions/hw-security/test/fixtures/sca
```

**Julia 分析器（`jest-julia`）**

```bash
# 1. Julia 程式碼的失效 / 型別推導問題（只有警告時結束碼為 0，除非加上 --fail-on warning）
jest-julia lint extensions/julia-profiler/test/fixtures/InvDemo

# 2. 摘要已錄製的 SnoopCompile 分析結果
jest-julia report extensions/julia-profiler/test/fixtures/invdemo.profile.json

# 3. 已安裝 Julia 時：分析實際套件，並與 git HEAD 比較效能
cd extensions/julia-profiler/test/fixtures/InvDemo
jest-julia analyze --out profile.json        # 第一次執行會把 SnoopCompile 安裝到 ~/.cache/jest-julia
jest-julia bench --baseline HEAD --seconds 0.2
cd -
```

**一次執行全部（`jest-security`）**

```bash
jest-security lint extensions --format md --out findings.md      # 所有規則，輸出 Markdown 報告
jest-security scan extensions --out security.sarif               # 所有規則，輸出單一 SARIF 檔
jest-security hw entropy extensions/hw-security/test/fixtures/entropy/rand8_short.bin --bits 8   # 也可呼叫任一子工具
```

#### 步驟 4 — 用在自己的專案

```bash
cd ~/my-project
jest-security lint .                          # 易讀的文字報告
jest-security lint . --fail-on warning        # 更嚴格：有警告也視為失敗
jest-endpoint lint . --disable edr/etw-broad-enable --rule-pack team-rules.yaml
```

- **輸出格式**：`--format text`（預設）、`json`、`sarif` 或 `md`；加上 `--out <檔案>` 可寫入檔案。
- **結束碼**：`0` 無問題；`1` 有達到 `--fail-on` 門檻的問題或檢查未通過；`2` 用法錯誤或執行錯誤。
- **忽略單行**：在該行上方加上 `// ide-ext-ignore-next-line <規則 ID>`（Julia / YAML / sdkconfig 使用 `#`）。整個檔案則可在任意位置加上 `// ide-ext-ignore-file <規則 ID>`。
- **略過資料夾**：在執行指令的資料夾中建立 `.jestignore`（與 .gitignore 相同語法），或使用 `--ignore 'vendor/**'`。明確指定的路徑一定會掃描；`--no-ignore-file` 可停用該檔案。

#### 步驟 5 — 在 CI 中使用（GitHub Actions）

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      security-events: write        # 上傳 SARIF 需要此權限
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
      - run: npm install -g @jest-test-team/security-cli
      - run: jest-security scan . --out security.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: security.sarif
      - run: jest-hw entropy firmware/trng-dump.bin --bits 8 --min 7.5   # 選用的熵值門檻
```

#### 步驟 6 — 更新或移除

- **VS Code 安裝的指令**：擴充套件更新後會自動更新指令。要移除時，在命令選擇區執行 *… Uninstall '<tool>' Command*；它只會刪除自己建立的檔案。
- **npm**：`npm update -g @jest-test-team/security-cli` / `npm uninstall -g @jest-test-team/security-cli`。

#### 疑難排解

| 問題 | 解決方式 |
|---|---|
| 剛安裝完就出現 `command not found: jest-…` | zsh 會快取已知指令：執行 `rehash`（bash 為 `hash -r`），或開啟新的終端機。 |
| 新終端機中仍出現 `command not found: jest-…` | 確認 `echo $PATH` 包含 `~/.local/bin`（方式 A）或 npm 全域 bin 目錄（`npm prefix -g`），並確認檔案存在：`ls ~/.local/bin/jest-*`。若不存在，請再次執行 *Install '…' Command in PATH*（更新擴充套件後請先重新載入 VS Code 視窗）。 |
| `code --install-extension` 沒有更新 VS Code | 你的 `code` 指令可能屬於其他編輯器（用 `ls -l $(which code)` 檢查，例如 Cursor）。請改用 VS Code 本身的 CLI：`"/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code" --install-extension …`。 |
| 範例或第三方程式碼被掃描出問題 | 在 `.jestignore`（與 .gitignore 相同語法）中列出要略過的資料夾，或使用 `--ignore <glob>`；本 repo 的 `.jestignore` 會略過 `test/fixtures`。 |
| `cannot find the "grammars" data folder` | 內建資料遺失：請重新安裝，或把 `JEST_ASSETS` 設為包含 `grammars/`、`rules/`、`ptree/`、`extscan/`、`scripts/` 的資料夾。 |
| `Julia not found` | 安裝 Julia（`brew install julia` 或 juliaup），或使用 `--julia /path/to/julia`（或設定 `$JULIA`）。 |
| `bench` 顯示 *not a git repository* | 請在 git 專案中執行，或使用 `--baseline none`。 |
| `restart` 顯示 *must contain 1000 × 1000 samples* | 重啟資料需為 1000 次重啟 × 每次 1000 個樣本（逐列排列）；較小的方陣請用 `--rows`。 |

## Development

```bash
npm install
npm run build              # bundle every extension (dist/)
npm run typecheck && npm run lint
npm test                   # vitest unit + webview DOM tests
npm run test:integration   # @vscode/test-cli in a downloaded VS Code (xvfb-run on Linux)
npm run package            # vsix/*.vsix
```

Press **F5** in VS Code and choose *Run Endpoint Security*, *Run Julia Profiler* or *Run HW Security* to open an Extension Development Host. The host opens on that extension's `test/fixtures`.

### Tests that need external tools

| Env var | Enables |
|---|---|
| `JULIA_PROFILER_TEST_JULIA=/path/to/julia` | integration tests that run SnoopCompile and BenchmarkTools for real |
| `NIST_EA_NON_IID=/path/to/ea_non_iid` | regenerates `extensions/hw-security/test/fixtures/entropy/nist-reference.json` |
| `NIST_EA_RESTART=/path/to/ea_restart` | regenerates the restart-test reference |

The committed NIST reference values come from [usnistgov/SP800-90B_EntropyAssessment](https://github.com/usnistgov/SP800-90B_EntropyAssessment). The TypeScript estimators must match them to 1e-9.

## Releasing

1. Create the Marketplace publisher `jest-test-team` at <https://marketplace.visualstudio.com/manage>, or change `publisher` in each `extensions/*/package.json` and the pack's `extensionPack` ids.
2. In Azure DevOps, create a Personal Access Token: organisation **All accessible organizations**, scope **Marketplace → Manage**.
3. Add it as the repository secret `VSCE_PAT`. Optionally add `OVSX_PAT` for Open VSX.
4. Bump versions and changelogs, then tag the release: `git tag v0.1.0 && git push --tags`. [`release.yml`](.github/workflows/release.yml) tests, packages and publishes the extensions in dependency order, and attaches the `.vsix` files to a GitHub release.

To publish manually instead, run `npx vsce login jest-test-team`, then `npm run package`, then `npx vsce publish --packagePath vsix/<file>.vsix`.

**CLI on npm:** create the npm organisation `jest-test-team`, or rename the package in `packages/cli/package.json`. Then add an automation token as the `NPM_TOKEN` secret, and `release.yml` will also publish `@jest-test-team/security-cli`. To publish by hand, run `npm publish -w @jest-test-team/security-cli --access public`.
