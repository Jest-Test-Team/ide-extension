// Curated rules for jest-ext-rs (ext/yara-match). Each rule needs several independent indicators,
// so a single string in documentation or a security tool's own rule list does not match.

rule jest_miner_xmrig {
  meta:
    description = "Cryptocurrency miner (XMRig / CryptoNight / Stratum)"
  strings:
    $stratum = "stratum+tcp://" nocase
    $stratum_ssl = "stratum+ssl://" nocase
    $xmrig = "xmrig" nocase
    $donate = "donate-level"
    $cn = "cryptonight" nocase
    $nicehash = "nicehash" nocase
  condition:
    3 of them
}

rule jest_stealer_browser_webhook {
  meta:
    description = "Browser credential stealer that exfiltrates to a webhook / bot"
  strings:
    $login = "Login Data"
    $state = "Local State"
    $key = "encrypted_key"
    $cookies = "Network\\Cookies"
    $dpapi = "CryptUnprotectData"
    $hook = "discord.com/api/webhooks/"
    $hook2 = "discordapp.com/api/webhooks/"
    $tg = "api.telegram.org/bot"
  condition:
    3 of ($login, $state, $key, $cookies, $dpapi) and any of ($hook, $hook2, $tg)
}

rule jest_stealer_discord_token {
  meta:
    description = "Discord token grabber"
  strings:
    $ls = "Local Storage"
    $ldb = "leveldb"
    $prefix = "dQw4w9WgXcQ:"
    $discord = "discord" nocase
    $hook = "/api/webhooks/"
  condition:
    $ls and $ldb and $discord and ($prefix or $hook)
}

rule jest_reverse_shell {
  meta:
    description = "Reverse shell one-liner"
  strings:
    $bash = "bash -i >& /dev/tcp/"
    $nc = "nc -e /bin/sh"
    $ncat = "ncat -e /bin/bash"
    $ps1 = "New-Object System.Net.Sockets.TCPClient" nocase
    $ps2 = "GetStream()" nocase
    $py = "pty.spawn(\"/bin/sh\")"
    $sh = "/bin/sh -i"
    $dup = "dup2("
  condition:
    any of ($bash, $nc, $ncat) or ($ps1 and $ps2) or ($py) or ($sh and $dup)
}

rule jest_macos_password_phish {
  meta:
    description = "macOS password prompt phishing (AMOS-style stealer)"
  strings:
    $dialog = "display dialog" nocase
    $hidden = "with hidden answer" nocase
    $osa = "osascript"
    $keychain = "login.keychain"
    $dscl = "dscl . authonly"
  condition:
    $dialog and $hidden and ($osa or $keychain or $dscl)
}

rule jest_windows_keylogger {
  meta:
    description = "Windows keylogger that sends captured keys out"
  strings:
    $hook = "SetWindowsHookEx"
    $async = "GetAsyncKeyState"
    $ll = "WH_KEYBOARD_LL"
    $net1 = "InternetOpen"
    $net2 = "WinHttpOpen"
    $net3 = "smtp." nocase
  condition:
    2 of ($hook, $async, $ll) and any of ($net1, $net2, $net3)
}
