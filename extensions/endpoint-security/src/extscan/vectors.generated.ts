// Generated from data/extscan/vectors.yaml by scripts/gen-vectors.mjs. Do not edit; run `npm run gen:vectors`.
import type { VectorDef } from './vectorTypes';

export const VECTOR_DEFS: readonly VectorDef[] = [
  {
    "id": "ext/activates-on-startup",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Activates on every startup (`*`)",
    "description": "The `*` activation event runs the extension as soon as VS Code starts, whether or not its features are used.",
    "attack": [],
    "cwe": [],
    "doc": [
      "activation"
    ]
  },
  {
    "id": "ext/activates-after-startup",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Activates after startup (`onStartupFinished`)",
    "description": "The extension runs shortly after every startup, independent of the files or commands in use.",
    "attack": [],
    "cwe": [],
    "doc": [
      "activation"
    ]
  },
  {
    "id": "ext/untrusted-workspace",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Runs in untrusted workspaces",
    "description": "The extension declares full support for Restricted Mode, so it is active in workspaces the user has not trusted.",
    "attack": [],
    "cwe": [],
    "doc": [
      "trust"
    ]
  },
  {
    "id": "ext/many-dependencies",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Pulls in many other extensions",
    "description": "More than three `extensionDependencies` are installed and activated together with this extension.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/typosquat",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Identifier resembles a popular extension",
    "description": "The identifier is a near-miss of a popular extension (edit distance or look-alike characters), a common impersonation technique.",
    "attack": [
      "T1036.005"
    ],
    "cwe": [],
    "doc": [
      "removed"
    ]
  },
  {
    "id": "ext/uri-handler",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Handles vscode:// deep links",
    "description": "The extension registers a URI handler (`onUri` / `registerUriHandler`), so a web page or e-mail link can trigger its code with attacker-chosen parameters.",
    "attack": [
      "T1204.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/broad-workspace-contains",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Activates for almost any folder",
    "description": "A `workspaceContains` pattern such as `**/*` or `*` activates the extension in practically every workspace.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/remote-workspace-exec",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Runs on the remote host and executes programs",
    "description": "`extensionKind: workspace` plus process execution runs programs on SSH / container / WSL hosts the user connects to.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/terminal-profile",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Contributes a terminal profile",
    "description": "A contributed terminal profile can launch an arbitrary program whenever the user opens that terminal.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/task-provider",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Provides tasks",
    "description": "Task providers can define commands that run in a terminal; informational unless combined with other signals.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/debug-adapter-executable",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Debug adapter runs an executable",
    "description": "A contributed debugger launches a program or runtime when a debug session starts.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/auth-provider",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Registers an authentication provider",
    "description": "The extension can present sign-in flows and receive the resulting tokens; a fake provider can phish credentials.",
    "attack": [
      "T1556"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/keybinding-override",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Overrides common shortcuts",
    "description": "Keybindings for copy, paste, save or Enter without a `when` clause intercept everyday actions.",
    "attack": [
      "T1056"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/security-setting-defaults",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "error",
    "online": false,
    "title": "Weakens security settings by default",
    "description": "`configurationDefaults` changes workspace-trust, extension-update or similar security settings for every user.",
    "attack": [
      "T1562.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/proxy-defaults",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Sets a default HTTP proxy",
    "description": "`configurationDefaults` for `http.proxy*` can route all editor traffic through a third party.",
    "attack": [
      "T1090"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/terminal-env-defaults",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Injects terminal environment variables",
    "description": "`configurationDefaults` for `terminal.integrated.env.*` can set `PATH`, `NODE_OPTIONS` or `LD_PRELOAD` for every terminal.",
    "attack": [
      "T1574.006"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/unknown-dependency",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Depends on unknown extensions",
    "description": "`extensionDependencies` / `extensionPack` pull in extensions from publishers outside the trusted list.",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/missing-repository",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "No source repository",
    "description": "The manifest has no `repository`, so the code cannot be compared with its source.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/missing-license",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "No license",
    "description": "The manifest declares no license.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/brand-impersonation",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Display name copies a popular extension",
    "description": "The display name matches a popular extension from a different publisher.",
    "attack": [
      "T1036.005"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/manifest-install-scripts",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Lifecycle scripts in the manifest",
    "description": "`preinstall` / `postinstall` scripts are unusual in a packaged extension and point to an unusual build or tampering.",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/remote-schema",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Downloads JSON schemas",
    "description": "`jsonValidation` points to remote URLs fetched while editing files, which leaks activity to that host.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/remote-walkthrough-media",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Walkthrough loads remote media",
    "description": "Walkthrough steps load images or Markdown from the network.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/unusual-entry",
    "category": "manifest",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Unusual entry point",
    "description": "The `main` / `browser` entry is hidden, deeply nested, outside the usual output folders or has an obfuscated name.",
    "attack": [
      "T1036"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/process-exec",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Runs external programs",
    "description": "The code loads `child_process`. Common for language servers, linters and formatters; suspicious together with other signals.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/shell-exec",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Runs commands through a shell",
    "description": "`exec` / `spawn` with `shell: true` interprets a command string, enabling injection and hiding what runs.",
    "attack": [
      "T1059"
    ],
    "cwe": [
      "78"
    ],
    "doc": []
  },
  {
    "id": "ext/shell-interpreter",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Starts a shell interpreter with inline code",
    "description": "`bash -c`, `sh -c`, `cmd /c` or `powershell -enc` run inline or encoded scripts.",
    "attack": [
      "T1059.004",
      "T1059.001",
      "T1059.003"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/pipe-to-shell",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Pipes a download into a shell",
    "description": "`curl … | sh`, `wget -O- | bash` or `iwr … | iex` execute remote code directly.",
    "attack": [
      "T1105",
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/download-exec",
    "category": "process",
    "engines": [
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Downloads, writes and executes a file",
    "description": "Data flow from a network response to a written file that is then made executable or spawned.",
    "attack": [
      "T1105",
      "T1204.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/chmod-exec",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Makes files executable",
    "description": "`chmod +x` / `fs.chmod(…, 0o7xx)` prepares files for execution.",
    "attack": [
      "T1222.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/persistence-launchagent",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Writes macOS LaunchAgents / LaunchDaemons",
    "description": "Files in `~/Library/LaunchAgents` or `/Library/LaunchDaemons` run at login or boot.",
    "attack": [
      "T1543.001",
      "T1543.004"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/persistence-cron",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Installs cron jobs",
    "description": "`crontab` edits or writes to `/etc/cron*` schedule recurring execution.",
    "attack": [
      "T1053.003"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/persistence-shell-rc",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Modifies shell start-up files",
    "description": "Writes to `.bashrc`, `.zshrc`, `.profile` or PowerShell profiles run code in every new shell.",
    "attack": [
      "T1546.004"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/persistence-windows",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Windows persistence",
    "description": "Startup folder files, `reg add …\\Run` keys or `schtasks /create` run code at logon.",
    "attack": [
      "T1547.001",
      "T1053.005"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/service-control",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Controls system services",
    "description": "`launchctl`, `systemctl` or `sc.exe` load, start or modify services.",
    "attack": [
      "T1543"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/privilege-escalation",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Requests elevated privileges",
    "description": "`sudo`, `osascript … with administrator privileges`, `runas` or UAC prompts.",
    "attack": [
      "T1548"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/ui-automation",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Automates the GUI",
    "description": "`osascript` keystrokes / System Events or accessibility APIs drive other applications.",
    "attack": [
      "T1059.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/screen-capture",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Captures the screen",
    "description": "`screencapture`, desktop capturer or screenshot APIs.",
    "attack": [
      "T1113"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/tcc-tamper",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Tampers with macOS privacy permissions",
    "description": "`tccutil` or direct access to `TCC.db`.",
    "attack": [
      "T1548"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/trust-store",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Installs trusted root certificates",
    "description": "`security add-trusted-cert` or `certutil -addstore` allow interception of TLS traffic.",
    "attack": [
      "T1553.004"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/process-kill",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Kills other processes",
    "description": "`kill`, `pkill`, `killall` or `taskkill` against processes the extension did not start.",
    "attack": [
      "T1489"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/other-extension-write",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Writes into other extensions",
    "description": "Writes to the editor extensions folder outside its own install directory.",
    "attack": [
      "T1554"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/vscode-config-write",
    "category": "process",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Edits editor configuration files directly",
    "description": "Writes `settings.json` / `keybindings.json` on disk, bypassing the settings API and user consent.",
    "attack": [
      "T1112"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/credential-path",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "References credential stores",
    "description": "Paths of SSH keys, cloud / package-registry credentials, browser password and cookie stores, VS Code state or crypto wallets.",
    "attack": [
      "T1552.001",
      "T1555.003"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/input-capture",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Reads the clipboard or keystrokes",
    "description": "Clipboard reads or global keyboard hooks can capture secrets the user copies or types.",
    "attack": [
      "T1115",
      "T1056.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/ssh-keys",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Reads SSH keys",
    "description": "Paths under `~/.ssh` (private keys, `known_hosts`, `config`).",
    "attack": [
      "T1552.004"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/cloud-credentials",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Reads cloud credentials",
    "description": "AWS, Google Cloud or Azure credential files and token caches.",
    "attack": [
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/registry-tokens",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Reads package-registry tokens",
    "description": "`.npmrc`, `.yarnrc`, `.pypirc`, Cargo credentials.",
    "attack": [
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/git-credentials",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Reads git / netrc credentials",
    "description": "`.git-credentials`, `.netrc`, credential-helper output.",
    "attack": [
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/kube-docker-config",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Reads Kubernetes / Docker credentials",
    "description": "`~/.kube/config`, `~/.docker/config.json`.",
    "attack": [
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/browser-data",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Reads browser credential stores",
    "description": "Browser `Login Data`, `Cookies`, `Local State` or profile folders.",
    "attack": [
      "T1555.003",
      "T1539"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/keychain-access",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Accesses the OS credential store",
    "description": "`security find-*-password`, Keychain APIs or Windows DPAPI / Credential Manager.",
    "attack": [
      "T1555.001",
      "T1555.004"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/crypto-wallet",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Reads cryptocurrency wallets",
    "description": "Wallet files or browser-wallet extension storage (MetaMask, Phantom, Electrum…).",
    "attack": [
      "T1005"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/shell-history",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Reads shell history",
    "description": "`.bash_history`, `.zsh_history`, PowerShell history often contain secrets.",
    "attack": [
      "T1552.003"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/env-file-harvest",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Collects .env files",
    "description": "Searches for and reads `.env` files across the workspace or home folder.",
    "attack": [
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/env-dump",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Serialises the whole environment",
    "description": "`JSON.stringify(process.env)` or iterating all environment variables captures tokens.",
    "attack": [
      "T1082"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/broad-auth-session",
    "category": "data",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Requests broad sign-in scopes",
    "description": "`authentication.getSession` with repository / admin scopes, especially at activation.",
    "attack": [
      "T1528"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/workspace-harvest",
    "category": "data",
    "engines": [
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Reads the whole workspace and sends it out",
    "description": "Data flow from workspace-wide `findFiles` / `readFile` to a network sink.",
    "attack": [
      "T1119",
      "T1041"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/hardcoded-ip",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Hard-coded public IP address",
    "description": "Connections to a literal public IP address bypass DNS and are typical for command-and-control endpoints.",
    "attack": [
      "T1071"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/exfil-endpoint",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Known exfiltration / tunnelling endpoint",
    "description": "Webhook, paste, tunnelling or IP-lookup services that malware commonly uses to send data out or to locate the victim.",
    "attack": [
      "T1567"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/raw-socket",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Opens raw TCP / UDP sockets",
    "description": "`net.connect`, `dgram` or `tls.connect` outside HTTP client libraries.",
    "attack": [
      "T1095"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/dns-exfil",
    "category": "network",
    "engines": [
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "DNS exfiltration pattern",
    "description": "DNS lookups whose host names are built from data at run time.",
    "attack": [
      "T1048.003"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/tor-endpoint",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Contacts Tor hidden services",
    "description": "`.onion` addresses: traffic routed through Tor hides the destination, typical for command-and-control.",
    "attack": [
      "T1090.003"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/mining-pool",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Cryptocurrency mining pool",
    "description": "`stratum+tcp://` URLs or known pool hosts.",
    "attack": [
      "T1496"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/ip-lookup",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Looks up the public IP / location",
    "description": "IP-geolocation services used by malware to profile victims.",
    "attack": [
      "T1614"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/cleartext-endpoint",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Unencrypted HTTP / WebSocket endpoint",
    "description": "`http://` or `ws://` URLs to non-local hosts.",
    "attack": [],
    "cwe": [
      "319"
    ],
    "doc": []
  },
  {
    "id": "ext/tls-disabled",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Disables TLS verification",
    "description": "`rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED=0`.",
    "attack": [],
    "cwe": [
      "295"
    ],
    "doc": []
  },
  {
    "id": "ext/executable-download",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Downloads executables or scripts",
    "description": "URLs ending in `.exe`, `.dll`, `.sh`, `.ps1`, `.bat`, `.msi` or `.dmg`.",
    "attack": [
      "T1105"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/encoded-url",
    "category": "network",
    "engines": [
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Builds URLs from encoded data",
    "description": "Hosts or URLs assembled from base64, hex or char-code arrays at run time.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/websocket-c2",
    "category": "network",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "WebSocket to an IP or unusual port",
    "description": "Persistent WebSocket channels to IP literals or non-standard ports.",
    "attack": [
      "T1071.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/domain-inventory",
    "category": "network",
    "engines": [
      "go"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Contacted domains",
    "description": "Inventory of every host the code references, classified first- vs third-party.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/domain-reputation",
    "category": "network",
    "engines": [
      "go"
    ],
    "weight": 4,
    "severity": "warning",
    "online": true,
    "title": "Domain with poor reputation",
    "description": "A referenced domain is newly registered or listed by threat-intelligence feeds (online lookup).",
    "attack": [
      "T1071"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/dynamic-code",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 1,
    "severity": "warning",
    "online": false,
    "title": "Evaluates dynamically built code",
    "description": "`eval`, `new Function`, `vm.run*` or `require()` with a computed module name can run code that is not visible in the package. Common in bundled libraries (schema compilers, plugin loaders); weighs in mainly together with obfuscation.",
    "attack": [
      "T1027"
    ],
    "cwe": [
      "95"
    ],
    "doc": []
  },
  {
    "id": "ext/obfuscated",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Obfuscated code",
    "description": "javascript-obfuscator style identifiers or a high-entropy payload next to code evaluation. Plain minification does not trigger this.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/packer",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Packed JavaScript",
    "description": "`eval(function(p,a,c,k,e,d)…)` and similar packers.",
    "attack": [
      "T1027.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/high-entropy-string",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "High-entropy string literals",
    "description": "Long literals whose Shannon entropy suggests compressed or encrypted payloads.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/encoded-blob",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Large encoded blobs",
    "description": "Long base64 / hex literals embedded in code.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/charcode-chain",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Builds strings from character codes",
    "description": "Long `String.fromCharCode` chains or numeric arrays decoded to text.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/decode-eval",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Decodes and evaluates code",
    "description": "`atob` / `Buffer.from(…, \"base64\")` flowing into `eval`, `Function` or `vm`.",
    "attack": [
      "T1027",
      "T1059.007"
    ],
    "cwe": [
      "95"
    ],
    "doc": []
  },
  {
    "id": "ext/encrypted-payload",
    "category": "obfuscation",
    "engines": [
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Decrypts and runs an embedded payload",
    "description": "`createDecipheriv` with an embedded key whose output is evaluated or written and executed.",
    "attack": [
      "T1027.013"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/wasm-blob",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Instantiates embedded WebAssembly",
    "description": "WebAssembly compiled from an inline buffer rather than a shipped `.wasm` file.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/anti-debug",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Anti-debugging code",
    "description": "`debugger` traps in loops, timing checks or inspector detection.",
    "attack": [
      "T1622"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/sandbox-evasion",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Detects sandboxes / CI / VMs",
    "description": "Checks for CI variables, VM vendors or analysis tools before acting.",
    "attack": [
      "T1497"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/time-bomb",
    "category": "obfuscation",
    "engines": [
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Date-gated behaviour",
    "description": "Code paths enabled only after a hard-coded date or install age.",
    "attack": [
      "T1480"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/self-modifying",
    "category": "obfuscation",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Rewrites its own files",
    "description": "Writes to files inside its own install folder at run time.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/native-binary",
    "category": "native",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Ships native binaries",
    "description": "Native modules and libraries cannot be inspected by the code scan.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/unsigned-binary",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Unsigned native binary",
    "description": "Mach-O without a valid signature (or ad-hoc only) or PE without Authenticode.",
    "attack": [
      "T1553.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/binary-dangerous-imports",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Native code imports injection / hooking APIs",
    "description": "Imports such as `ptrace`, `CGEventTapCreate`, `SetWindowsHookEx`, `CreateRemoteThread`, `WriteProcessMemory`.",
    "attack": [
      "T1055",
      "T1056.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/binary-network-strings",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "URLs / IPs inside binaries",
    "description": "Network endpoints embedded in native code that the JavaScript scan cannot see.",
    "attack": [
      "T1071"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/packed-binary",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Packed native binary",
    "description": "UPX or similar packers, or sections with packer signatures.",
    "attack": [
      "T1027.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/binary-entropy",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "High-entropy binary sections",
    "description": "Sections with near-random content suggest encrypted payloads.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/wasm-capabilities",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "WebAssembly with system access",
    "description": "WASM modules importing WASI file-system or socket functions.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/yara-match",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Matches a malware signature",
    "description": "A curated YARA rule (stealer, miner, RAT, backdoor) matched a file.",
    "attack": [
      "T1588.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/foreign-arch",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Binaries for unexpected platforms",
    "description": "Native binaries for operating systems the extension does not declare.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/binary-unexpected-path",
    "category": "native",
    "engines": [
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Native binary in an unusual location",
    "description": "Executables outside `node_modules`, `bin` or platform folders, or with misleading extensions.",
    "attack": [
      "T1036.008"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/vulnerable-dependency",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Bundled package with known vulnerabilities",
    "description": "A bundled npm package version has OSV advisories.",
    "attack": [
      "T1195.001"
    ],
    "cwe": [
      "1395"
    ],
    "doc": []
  },
  {
    "id": "ext/malicious-dependency",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 7,
    "severity": "error",
    "online": false,
    "title": "Bundled package is known malware",
    "description": "A bundled npm package matches an OSV `MAL-` advisory.",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/dependency-typosquat",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Bundled package name imitates a popular one",
    "description": "A dependency name is a near-miss of a popular npm package.",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/dependency-install-script",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Bundled package has install scripts",
    "description": "A dependency declares `preinstall` / `install` / `postinstall` scripts.",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/protestware",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Known protestware package",
    "description": "A dependency version is known to contain sabotage or protest payloads.",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/git-dependency",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Dependency from git or a tarball URL",
    "description": "Dependencies resolved from git repositories or URLs bypass the registry.",
    "attack": [
      "T1195.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/deprecated-dependency",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Deprecated packages",
    "description": "Bundled packages marked deprecated by their authors.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/dependency-bloat",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Unusually large dependency tree",
    "description": "Dependency count or depth far above typical extensions.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/missing-lockfile",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "No lockfile",
    "description": "No `package-lock.json` / `yarn.lock` was shipped to tie down versions.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/vsix-tampered",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 7,
    "severity": "error",
    "online": true,
    "title": "Installed files differ from the published package",
    "description": "File hashes of the installed copy do not match the VSIX published for this version (online).",
    "attack": [
      "T1554"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/registry-mismatch",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 3,
    "severity": "warning",
    "online": true,
    "title": "Marketplace and Open VSX differ",
    "description": "The same id@version has different content on the two registries (online).",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/bundled-dependency-modified",
    "category": "supply-chain",
    "engines": [
      "go"
    ],
    "weight": 5,
    "severity": "error",
    "online": true,
    "title": "Bundled package modified",
    "description": "Files of a bundled npm package differ from the registry tarball of that version (online).",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/webview-no-csp",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Webview without Content Security Policy",
    "description": "Scripts are enabled but the HTML sets no CSP.",
    "attack": [],
    "cwe": [
      "1021"
    ],
    "doc": []
  },
  {
    "id": "ext/webview-unsafe-csp",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Weak webview CSP",
    "description": "CSP allows `unsafe-eval`, `unsafe-inline` or remote script origins.",
    "attack": [],
    "cwe": [
      "693"
    ],
    "doc": []
  },
  {
    "id": "ext/webview-remote-script",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Webview loads remote scripts",
    "description": "`<script src=\"https://…\">` runs code that can change after review.",
    "attack": [
      "T1105"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/webview-broad-resources",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Webview can read any local file",
    "description": "`localResourceRoots` includes the file-system root or home folder.",
    "attack": [],
    "cwe": [
      "552"
    ],
    "doc": []
  },
  {
    "id": "ext/command-uris",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Command links enabled",
    "description": "`enableCommandUris` lets webview content run editor commands.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/trusted-markdown",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Trusted Markdown with command links",
    "description": "`MarkdownString.isTrusted` allows `command:` links in hovers and notifications.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/webview-message-exec",
    "category": "webview",
    "engines": [
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Webview messages reach command execution",
    "description": "Data from `onDidReceiveMessage` flows into `executeCommand`, a process or the file system.",
    "attack": [
      "T1059"
    ],
    "cwe": [
      "94"
    ],
    "doc": []
  },
  {
    "id": "ext/webview-remote-frame",
    "category": "webview",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Webview embeds a remote site",
    "description": "`<iframe src=\"https://…\">` content runs inside the editor.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/terminal-injection",
    "category": "vscode-api",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Hidden terminal commands",
    "description": "`createTerminal({ hideFromUser })` or `sendText` of commands the user did not type.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/terminal-sequence",
    "category": "vscode-api",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Sends raw terminal sequences",
    "description": "`workbench.action.terminal.sendSequence` injects keystrokes into the user's terminal.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/settings-tamper",
    "category": "vscode-api",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Changes security settings via the API",
    "description": "`getConfiguration().update` on trust, proxy, terminal-environment or extension-update settings.",
    "attack": [
      "T1562.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/extension-install",
    "category": "vscode-api",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Installs other extensions",
    "description": "`workbench.extensions.installExtension` or the CLI to add extensions without the user.",
    "attack": [
      "T1176"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/extension-uninstall",
    "category": "vscode-api",
    "engines": [
      "ts",
      "rs"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Uninstalls or disables extensions",
    "description": "Removes or disables other extensions (security tools).",
    "attack": [
      "T1562.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/open-external-startup",
    "category": "vscode-api",
    "engines": [
      "rs"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Opens URLs at activation",
    "description": "`env.openExternal` called during activation without user action.",
    "attack": [
      "T1204.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/document-exfil",
    "category": "vscode-api",
    "engines": [
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Sends edited code to the network",
    "description": "Data flow from `onDidChangeTextDocument` / document text to a network sink.",
    "attack": [
      "T1119",
      "T1041"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/clipboard-exfil",
    "category": "vscode-api",
    "engines": [
      "rs"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Sends clipboard contents to the network",
    "description": "Data flow from `env.clipboard.readText` to a network sink.",
    "attack": [
      "T1115",
      "T1041"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/secret-storage-abuse",
    "category": "vscode-api",
    "engines": [
      "rs"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Secrets sent elsewhere",
    "description": "Values read from `context.secrets` flow to logs, files or the network.",
    "attack": [
      "T1552"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/storage-payload",
    "category": "vscode-api",
    "engines": [
      "rs"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Executes files from its storage folder",
    "description": "Writes to `globalStorageUri` / `storageUri` that are later executed or `require`d.",
    "attack": [
      "T1105"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/python-exec",
    "category": "scripts",
    "engines": [
      "py"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Python script runs programs or code",
    "description": "`subprocess`, `os.system`, `eval` or `exec` in shipped `.py` files.",
    "attack": [
      "T1059.006"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/python-network",
    "category": "scripts",
    "engines": [
      "py"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Python script contacts the network",
    "description": "`requests` / `urllib` / sockets to IP literals or exfiltration services in shipped `.py` files.",
    "attack": [
      "T1071"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/python-deserialize",
    "category": "scripts",
    "engines": [
      "py"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Unsafe Python deserialisation",
    "description": "`pickle.loads`, `yaml.load` without SafeLoader, `marshal.loads`.",
    "attack": [],
    "cwe": [
      "502"
    ],
    "doc": []
  },
  {
    "id": "ext/julia-exec",
    "category": "scripts",
    "engines": [
      "jl"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Julia script runs programs or downloaded code",
    "description": "`run(`…`)`, `download` followed by `include` in shipped `.jl` files.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/shell-script-download",
    "category": "scripts",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Shell script downloads and runs code",
    "description": "Shipped `.sh` / `.bash` scripts with `curl | sh`, `wget` + `chmod +x` + execute.",
    "attack": [
      "T1105"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/powershell-script",
    "category": "scripts",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "PowerShell / batch script with download or encoded commands",
    "description": "`Invoke-WebRequest`, `IEX`, `-EncodedCommand` or `bitsadmin` in shipped scripts.",
    "attack": [
      "T1059.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/unknown-publisher",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Publisher not in the built-in trusted list",
    "description": "Offline check only: the publisher is not one of the well-known publishers bundled with the scanner. This is not a negative verdict; it only amplifies other signals. Enable the Marketplace lookup for real publisher verification.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/trusted-publisher",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": -2,
    "severity": "hint",
    "online": false,
    "title": "Well-known publisher",
    "description": "Installed from the Marketplace by a publisher on the built-in trusted list. Marketplace publisher names are unique, so the name cannot be borrowed there (a sideloaded VSIX can claim any publisher and gets no credit).",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/sideloaded",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Installed from a VSIX file",
    "description": "The extension was installed from a local file rather than the Marketplace, so it bypassed Marketplace scanning.",
    "attack": [],
    "cwe": [],
    "doc": [
      "ext-security"
    ]
  },
  {
    "id": "ext/known-bad",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Removed from the Marketplace",
    "description": "The identifier appears in Microsoft's list of extensions removed from the VS Marketplace.",
    "attack": [],
    "cwe": [],
    "doc": [
      "removed"
    ]
  },
  {
    "id": "ext/not-on-marketplace",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": true,
    "title": "Not found on the Marketplace",
    "description": "The Marketplace has no extension with this identifier: it was sideloaded, renamed or taken down.",
    "attack": [],
    "cwe": [],
    "doc": [
      "ext-security"
    ]
  },
  {
    "id": "ext/unverified-publisher",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": true,
    "title": "Publisher not verified",
    "description": "The Marketplace publisher has not verified a domain.",
    "attack": [],
    "cwe": [],
    "doc": [
      "ext-security"
    ]
  },
  {
    "id": "ext/low-installs",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 1,
    "severity": "info",
    "online": true,
    "title": "Few installs",
    "description": "Fewer than 1,000 Marketplace installs.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/stale",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": true,
    "title": "Not updated for over two years",
    "description": "The latest Marketplace version is more than two years old.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/verified-publisher",
    "category": "reputation",
    "engines": [
      "ts"
    ],
    "weight": -1,
    "severity": "hint",
    "online": true,
    "title": "Verified publisher",
    "description": "The Marketplace publisher has a verified domain.",
    "attack": [],
    "cwe": [],
    "doc": [
      "ext-security"
    ]
  },
  {
    "id": "ext/repo-missing-version",
    "category": "reputation",
    "engines": [
      "go"
    ],
    "weight": 2,
    "severity": "warning",
    "online": true,
    "title": "Repository has no matching release",
    "description": "The declared repository has no tag / release for the installed version (online).",
    "attack": [
      "T1195.002"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/virustotal",
    "category": "reputation",
    "engines": [
      "go"
    ],
    "weight": 7,
    "severity": "error",
    "online": true,
    "title": "Flagged by antivirus engines",
    "description": "A shipped file hash is flagged on VirusTotal (online, needs your API key).",
    "attack": [
      "T1588.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/ml-anomaly",
    "category": "model",
    "engines": [
      "py"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Anomalous compared with known-good extensions",
    "description": "A classifier trained on popular and known-malicious extensions rates this one as anomalous.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/category-outlier",
    "category": "model",
    "engines": [
      "jl"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Outlier against the popular-extension baseline",
    "description": "A category score is far above the baseline of popular extensions (robust z-score).",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/population-outlier",
    "category": "model",
    "engines": [
      "jl"
    ],
    "weight": 1,
    "severity": "info",
    "online": false,
    "title": "Outlier among your installed extensions",
    "description": "A category score is far above the other extensions installed on this machine.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/calibrated-risk",
    "category": "model",
    "engines": [
      "jl"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Calibrated risk estimate",
    "description": "Probability-style risk estimate from weights fitted on the baseline corpus.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/network-outbound",
    "category": "network",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "info",
    "online": false,
    "title": "Can make outbound connections",
    "description": "Loads http, https, http2, net, tls, dgram, WebSocket or an HTTP client library (axios, node-fetch, undici, got), or calls fetch: the code can contact other machines.",
    "attack": [
      "T1071"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/hardcoded-ip-or-raw-url",
    "category": "network",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Dynamic-DNS or tunnel host, or URL on an odd port",
    "description": "Dynamic-DNS (duckdns, no-ip, ddns.net, dynu, afraid.org…) and tunnel hosts change owner and address freely and are typical command-and-control; URLs on non-standard ports point at ad-hoc servers. Public IP literals are `ext/hardcoded-ip`.",
    "attack": [
      "T1568.002",
      "T1071"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/telemetry-unauthorized",
    "category": "network",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Third-party tracking without declared telemetry",
    "description": "Uses a tracking SDK or endpoint (Google Analytics, Mixpanel, Segment, Amplitude, PostHog, Heap, Hotjar) but declares no telemetry: no telemetry.json, no setting tagged `telemetry`, and no use of the editor's telemetry setting.",
    "attack": [
      "T1119"
    ],
    "cwe": [
      "359"
    ],
    "doc": []
  },
  {
    "id": "ext/sensitive-dotfiles",
    "category": "data",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Developer secret dotfiles",
    "description": "Paths such as `~/.gnupg`, `~/.gitconfig`, `~/.ssh/config`, `~/.config/gh/hosts.yml`, `~/.pgpass`. SSH keys, cloud credentials, kube / docker configs and shell history (`ext/shell-history`) have their own vectors.",
    "attack": [
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/workspace-secret-harvest",
    "category": "data",
    "engines": [
      "ts"
    ],
    "weight": 5,
    "severity": "warning",
    "online": false,
    "title": "Searches the workspace for key and credential files",
    "description": "File searches or globs for `*.pem`, `*.key`, `*.p12`, `id_rsa`, `credentials.json` or `secrets.yaml`: collecting secrets from every project opened. `.env` searches are `ext/env-file-harvest`.",
    "attack": [
      "T1552.001",
      "T1083"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/hex-or-unicode-escape-density",
    "category": "obfuscation",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Dense hex / unicode escapes",
    "description": "String literals made mostly of `\\xHH` or `\\uHHHH` escapes, or files where escapes dominate: text hidden from readers and naive scanners, typical of packers and JSFuck-style encoders.",
    "attack": [
      "T1027"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/hidden-archive-or-blob",
    "category": "supply-chain",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Unreferenced archive, database or binary blob",
    "description": "Archives (.zip, .tar.gz, .7z…), SQLite databases or unknown binaries shipped in the package whose names no code or manifest refers to: payloads staged for later extraction.",
    "attack": [
      "T1027.009",
      "T1105"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/command-override",
    "category": "vscode-api",
    "engines": [
      "ts"
    ],
    "weight": 4,
    "severity": "warning",
    "online": false,
    "title": "Takes over built-in commands",
    "description": "Registers a command id the editor or a built-in owns (`type`, `workbench.action.terminal.*`, `git.commit`, `git.push`, clipboard and save actions) to intercept keystrokes or developer actions.",
    "attack": [
      "T1056",
      "T1574"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/debug-session-hook",
    "category": "vscode-api",
    "engines": [
      "ts"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Hooks debug sessions",
    "description": "A debug-adapter tracker for every debugger (`*`), debug-session events or `customRequest('evaluate')`: sees variables, memory and environment of the programs being debugged.",
    "attack": [
      "T1005"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "ext/webview-remote-content",
    "category": "webview",
    "engines": [
      "ts"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Script-enabled webview loads remote content",
    "description": "A webview with `enableScripts: true` in a bundle that loads remote scripts or frames: code that can change after review runs next to the extension's message bridge.",
    "attack": [],
    "cwe": [
      "79",
      "829"
    ],
    "doc": []
  },
  {
    "id": "ext/scan-incomplete",
    "category": "meta",
    "engines": [
      "ts"
    ],
    "weight": 0,
    "severity": "hint",
    "online": false,
    "title": "Some files were not scanned",
    "description": "Files above the size limit, beyond the per-extension file budget, or unreadable were skipped.",
    "attack": [],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/child-process-spawned",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Started a process while running",
    "description": "child_process spawn / exec / execFile / fork observed with its command line; shells, downloaders and script hosts (curl, wget, bash -c, powershell, cmd.exe, nc) weigh much more.",
    "attack": [
      "T1059"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/fs-access-violation",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Touched files outside its own folder and the workspace",
    "description": "Reads, writes or directory listings outside the extension, the workspace and temporary folders; reading the decoy SSH key, cloud credentials or shell profile planted in the audit's home folder is a strong signal.",
    "attack": [
      "T1005",
      "T1552.001"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/dynamic-eval-execution",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Evaluated code built at run time",
    "description": "eval, the Function constructor or vm.* received code while running; the captured source is matched against loader, process and network patterns.",
    "attack": [
      "T1027",
      "T1059.007"
    ],
    "cwe": [
      "95"
    ],
    "doc": []
  },
  {
    "id": "runtime/dns-and-http-destinations",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 2,
    "severity": "warning",
    "online": false,
    "title": "Contacted network destinations",
    "description": "DNS lookups, HTTP(S) requests and socket connections with host, port and payload size; IP literals, dynamic-DNS hosts, hosts not named in the manifest, large uploads, or decoy secrets in a request body weigh more.",
    "attack": [
      "T1071",
      "T1041"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/clipboard-poll-frequency",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Read the clipboard without user action",
    "description": "env.clipboard.readText calls while nobody used the editor; more than one per minute looks like a clipboard / token logger.",
    "attack": [
      "T1115"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/orphan-process-daemon",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 6,
    "severity": "error",
    "online": false,
    "title": "Left a process running after exit",
    "description": "A process the extension started was still alive after the extension host exited (re-parented to init / launchd): a persistent daemon.",
    "attack": [
      "T1543"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/network-raw-socket",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 3,
    "severity": "warning",
    "online": false,
    "title": "Raw or non-HTTP network traffic",
    "description": "UDP sockets or TCP connections to non-web ports from JavaScript, and (Linux, root + bpftrace) raw SOCK_RAW sockets from native code.",
    "attack": [
      "T1095"
    ],
    "cwe": [],
    "doc": []
  },
  {
    "id": "runtime/mprotect-rwx",
    "category": "runtime",
    "engines": [
      "rt"
    ],
    "weight": 5,
    "severity": "error",
    "online": false,
    "title": "Writable and executable memory beyond the JIT baseline",
    "description": "mprotect / mmap with PROT_WRITE|PROT_EXEC above what an empty extension host produces (Linux, root + bpftrace): in-memory shellcode or injection.",
    "attack": [
      "T1055",
      "T1620"
    ],
    "cwe": [],
    "doc": []
  }
];
