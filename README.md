# ide-extension

Three VS Code extensions for security and systems engineering, plus an extension pack:

| Extension | Folder | What it does |
|---|---|---|
| **Endpoint Security & Compliance Toolkit** | [`extensions/endpoint-security`](extensions/endpoint-security/README.md) | WFP / ETW / Endpoint Security API hover + validation, PCI DSS 4.0.1 & CCSP D2 compliance scan with SARIF export, process-tree detection simulation, risk scan of installed VS Code extensions |
| **Julia Invalidation & Compiler Profiler** | [`extensions/julia-profiler`](extensions/julia-profiler/README.md) | SnoopCompile.jl invalidation tree & inference flame graph, invalidation linter, benchmark judge vs. git baseline |
| **Embedded Hardware Security Workbench** | [`extensions/hw-security`](extensions/hw-security/README.md) | ESP32/ESPHome security linter, NIST SP 800-90B entropy & restart tests, PUF metrics, ChipWhisperer side-channel tags |
| Security & Systems Engineering Pack | `extensions/security-pack` | Installs all three |

Shared code lives in [`packages/core`](packages/core): a web-tree-sitter host, the declarative rule engine (tree-sitter queries, regex/absent rules and code rules — every rule cites its sources), diagnostics with quick fixes and suppressions, SARIF/Markdown reports, and webview helpers. Each extension bundles it with esbuild.

**Languages:** [English](#install--use) · [繁體中文](#安裝與使用)

## Install & use

### Install

Build the packages with `npm install && npm run package`, then install them. Install the three extensions first and the pack last: the pack refers to the others by Marketplace ID, so on its own it would try to download them from the Marketplace.

```bash
code --install-extension vsix/endpoint-security-0.2.0.vsix
code --install-extension vsix/julia-profiler-0.1.0.vsix
code --install-extension vsix/hw-security-0.1.0.vsix
code --install-extension vsix/security-pack-0.1.0.vsix   # optional
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

## 安裝與使用

### 安裝

先執行 `npm install && npm run package` 產生安裝檔，再進行安裝。請先安裝三個擴充套件，最後才裝 Pack：Pack 以 Marketplace ID 引用其他三個套件，若單獨安裝，它會嘗試從 Marketplace 下載。

```bash
code --install-extension vsix/endpoint-security-0.2.0.vsix
code --install-extension vsix/julia-profiler-0.1.0.vsix
code --install-extension vsix/hw-security-0.1.0.vsix
code --install-extension vsix/security-pack-0.1.0.vsix   # 選用
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
