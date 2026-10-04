import type { CustomRule, Finding, PatternRule, AbsentRule, QueryRule, Rule, RuleContext, RuleRef } from '@ide-ext/core';
import type { Node } from 'web-tree-sitter';
import { calls, descendants, functionDefs, guardedAfter, guardedBefore, registeredCallbacks } from './cast';

const IDF = 'https://docs.espressif.com/projects/esp-idf/en/latest/esp32';
const ref = {
  security: { label: 'ESP-IDF — Security Overview', url: `${IDF}/security/security.html` },
  secureBoot: { label: 'ESP-IDF — Secure Boot v2', url: `${IDF}/security/secure-boot-v2.html` },
  flashEnc: { label: 'ESP-IDF — Flash Encryption', url: `${IDF}/security/flash-encryption.html` },
  nvsEnc: { label: 'ESP-IDF — NVS Encryption', url: `${IDF}/api-reference/storage/nvs_encryption.html` },
  random: { label: 'ESP-IDF — Random Number Generation', url: `${IDF}/api-reference/system/random.html` },
  errors: { label: 'ESP-IDF — Error Handling', url: `${IDF}/api-guides/error-handling.html` },
  isr: { label: 'ESP-IDF — FreeRTOS (ISR-safe FromISR APIs)', url: `${IDF}/api-reference/system/freertos_idf.html` },
  csi: { label: 'ESP-IDF — Wi-Fi Channel State Information', url: `${IDF}/api-guides/wifi.html#wi-fi-channel-state-information` },
  tls: { label: 'ESP-IDF — ESP-TLS', url: `${IDF}/api-reference/protocols/esp_tls.html` },
  memprot: { label: 'ESP-IDF — Memory Protection / Stack Smashing', url: `${IDF}/api-guides/fatal-errors.html` },
  esphomeApi: { label: 'ESPHome — Native API (encryption)', url: 'https://esphome.io/components/api.html' },
  esphomeSecrets: { label: 'ESPHome — Secrets and substitutions', url: 'https://esphome.io/guides/faq.html#how-do-i-use-my-home-assistant-secrets-yaml' },
  esphomeOta: { label: 'ESPHome — OTA updates', url: 'https://esphome.io/components/ota/' },
  esphomeWeb: { label: 'ESPHome — Web Server (auth)', url: 'https://esphome.io/components/web_server.html' },
  cwe: (id: number, title: string): RuleRef => ({ label: `CWE-${id}: ${title}`, url: `https://cwe.mitre.org/data/definitions/${id}.html` }),
};
const C = ['c', 'cpp'];

const unsafeString: QueryRule = {
  id: 'esp32/unsafe-string-fn',
  title: 'Unbounded string function',
  description: 'These functions write without a destination size and are the classic source of stack/heap buffer overflows in firmware.',
  severity: 'warning',
  languages: C,
  message: '`{{fn}}` performs no bounds checking; use a size-bounded alternative (strlcpy, strlcat, snprintf, fgets).',
  refs: [ref.cwe(120, 'Buffer Copy without Checking Size of Input'), ref.security],
  query: '((call_expression function: (identifier) @fn) (#match? @fn "^(strcpy|strcat|sprintf|vsprintf|gets|stpcpy|wcscpy|wcscat)$"))',
  capture: 'fn',
};

const LEN_NAME = /^(len|length|size|sz|n|count|bufsize|buf_size|buf_len|buflen|data_len|datalen|payload_len|msg_len|report_len|data_size|nbytes)$/i;
const COPY_FNS: Record<string, number> = { memcpy: 2, memmove: 2, strncpy: 2, strncat: 2, memcpy_s: 3, bcopy: 2 };

const uncheckedLength: CustomRule = {
  kind: 'custom',
  id: 'esp32/unchecked-length',
  title: 'Copy size from caller/packet without bounds check',
  description:
    'A length that comes from a parameter or a received structure (`info->len`, `pkt->length`) is used as a copy size with no prior comparison against the destination size — typical in Wi-Fi CSI, ESP-NOW, BLE and USB HID handlers.',
  severity: 'warning',
  languages: C,
  message: '',
  refs: [ref.cwe(787, 'Out-of-bounds Write'), ref.cwe(130, 'Improper Handling of Length Parameter Inconsistency')],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const out: Finding[] = [];
    for (const fn of functionDefs(ctx.tree.rootNode)) {
      const lenParams = fn.params.filter((p) => !p.pointer && LEN_NAME.test(p.name)).map((p) => p.name);
      const ptrParams = new Set(fn.params.filter((p) => p.pointer).map((p) => p.name));
      for (const c of calls(fn.body)) {
        const idx = COPY_FNS[c.name];
        const size = idx === undefined ? undefined : c.args[idx];
        if (!size) {
          continue;
        }
        const tainted = [
          ...descendants(size, 'identifier').map((i) => i.text).filter((t) => lenParams.includes(t)),
          ...[...(size.type === 'field_expression' ? [size] : []), ...descendants(size, 'field_expression')]
            .filter((f) => ptrParams.has(f.childForFieldName('argument')?.text ?? '') && LEN_NAME.test(f.childForFieldName('field')?.text ?? ''))
            .map((f) => f.text),
        ];
        if (size.text.includes('sizeof')) {
          continue;
        }
        for (const t of new Set(tainted)) {
          if (!guardedBefore(fn.body, t, c.node.startIndex)) {
            out.push(ctx.report(size, `\`${t}\` is used as the ${c.name} size in \`${fn.name}\` without a prior bounds check against the destination.`));
            break;
          }
        }
      }
    }
    return out;
  },
};

const ALLOC = /^(malloc|calloc|realloc|heap_caps_malloc|heap_caps_calloc|heap_caps_realloc|heap_caps_aligned_alloc|pvPortMalloc|strdup|strndup)$/;

const uncheckedAlloc: CustomRule = {
  kind: 'custom',
  id: 'esp32/unchecked-alloc',
  title: 'Allocation result not checked for NULL',
  description: 'Heap is small on MCUs and fragmentation makes allocation failure routine; dereferencing NULL crashes the device (or worse, writes to address 0x0 on some targets).',
  severity: 'warning',
  languages: C,
  message: '',
  refs: [ref.cwe(690, 'Unchecked Return Value to NULL Pointer Dereference')],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const out: Finding[] = [];
    for (const fn of functionDefs(ctx.tree.rootNode)) {
      for (const c of calls(fn.body)) {
        if (!ALLOC.test(c.name)) {
          continue;
        }
        let parent = c.node.parent;
        while (parent?.type === 'cast_expression' || parent?.type === 'parenthesized_expression') {
          parent = parent.parent;
        }
        let target: string | undefined;
        if (parent?.type === 'init_declarator') {
          target = descendants(parent.childForFieldName('declarator')!, 'identifier')[0]?.text ?? parent.childForFieldName('declarator')?.text;
        } else if (parent?.type === 'assignment_expression') {
          target = parent.childForFieldName('left')?.text;
        } else if (parent?.type === 'argument_list') {
          out.push(ctx.report(c.node, `Result of \`${c.name}\` is passed on directly without a NULL check.`));
          continue;
        } else if (parent?.type === 'return_statement') {
          continue; // the caller is responsible
        }
        if (target && !guardedAfter(fn.body, target, c.node.startIndex)) {
          out.push(ctx.report(c.node, `\`${target}\` from \`${c.name}\` is never checked for NULL in \`${fn.name}\`.`));
        }
      }
    }
    return out;
  },
};

const ESP_ERR_FNS =
  '^(esp_(wifi|event|netif|ota|partition|flash|efuse|tls|http_client|now|bt|bluedroid|ble_gap|ble_gatts|ble_gattc|vfs|spiffs|littlefs|https_ota|sntp|mqtt_client|pm|sleep_enable|timer_create|timer_start|timer_stop|timer_delete|task_wdt|hidd|hidh|console|crt_bundle)\\w*|nvs_(flash_init|flash_erase|flash_secure_init\\w*|open\\w*|set_\\w+|get_\\w+|commit|erase_\\w+)|gpio_(config|set_level|set_direction|set_pull_mode|install_isr_service|isr_handler_add|reset_pin)|uart_(driver_install|param_config|set_pin)|i2c_(driver_install|param_config|master_\\w+|new_master_bus)|spi_(bus_initialize|bus_add_device|device_\\w+)|ledc_\\w+|adc_oneshot_\\w+|twai_\\w+|sdmmc_\\w+)$';
const NOT_ESP_ERR =
  '^(esp_mqtt_client_(publish|subscribe\\w*|unsubscribe|enqueue)|esp_http_client_(read\\w*|write|get_\\w+|fetch_headers|init)|esp_tls_conn_(read|write)|esp_partition_(find\\w*|next|iterator_release|get)|esp_ota_get_\\w+_partition|esp_efuse_(get_\\w+|read_field_bit|read_reg)|esp_netif_(create_\\w+|get_handle_from_ifkey|get_desc|get_ifkey|get_nr_of_ifs|get_netif_impl_index|destroy\\w*|new|next\\w*)|esp_bt_controller_get_status|esp_wifi_get_\\w*_cb|esp_console_\\w*_new\\w*)$';

const uncheckedEspErr: QueryRule = {
  id: 'esp32/unchecked-esp-err',
  title: 'Ignored esp_err_t',
  description: 'ESP-IDF reports failures through `esp_err_t` return values; ignoring them hides initialisation failures (e.g. NVS or Wi-Fi) that leave the device in an undefined state.',
  severity: 'warning',
  languages: C,
  message: 'Return value (esp_err_t) of `{{fn}}` is ignored.',
  refs: [ref.errors, ref.cwe(252, 'Unchecked Return Value')],
  query: '((expression_statement (call_expression function: (identifier) @fn) @match) (#match? @fn "' + ESP_ERR_FNS.replace(/\\/g, '\\\\') + '"))',
  where: { fn: { notMatches: NOT_ESP_ERR } },
  fix: { title: 'Wrap in ESP_ERROR_CHECK()', replacement: 'ESP_ERROR_CHECK({{match}})' },
};

const FORMAT_ARG: Record<string, number> = {
  printf: 0, esp_rom_printf: 0, vprintf: 0, fprintf: 1, sprintf: 1, snprintf: 2, syslog: 1,
  ESP_LOGE: 1, ESP_LOGW: 1, ESP_LOGI: 1, ESP_LOGD: 1, ESP_LOGV: 1,
  ESP_EARLY_LOGE: 1, ESP_EARLY_LOGW: 1, ESP_EARLY_LOGI: 1, ESP_EARLY_LOGD: 1, ESP_EARLY_LOGV: 1,
};

const formatString: CustomRule = {
  kind: 'custom',
  id: 'esp32/format-string',
  title: 'Non-literal format string',
  description: 'Passing data (for example a received payload) as the format string lets `%n`/`%s` sequences read or write memory.',
  severity: 'warning',
  languages: C,
  message: '',
  refs: [ref.cwe(134, 'Use of Externally-Controlled Format String')],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    return calls(ctx.tree.rootNode)
      .filter((c) => c.name in FORMAT_ARG && c.args[FORMAT_ARG[c.name]])
      .filter((c) => {
        const fmt = c.args[FORMAT_ARG[c.name]];
        return !['string_literal', 'concatenated_string', 'raw_string_literal'].includes(fmt.type) && !/^[A-Z][A-Z0-9_]*$/.test(fmt.text);
      })
      .map((c) => {
        const fmt = c.args[FORMAT_ARG[c.name]];
        const f = ctx.report(fmt, `\`${c.name}\` uses \`${fmt.text}\` as its format string; pass it as an argument instead ("%s").`);
        f.fix = { title: 'Use "%s" format', edits: [{ range: f.range, newText: `"%s", ${fmt.text}` }] };
        return f;
      });
  },
};

const ISR_UNSAFE: Record<string, string | null> = {
  printf: null, puts: null, ESP_LOGE: 'ESP_DRAM_LOGE', ESP_LOGW: 'ESP_DRAM_LOGW', ESP_LOGI: 'ESP_DRAM_LOGI', ESP_LOGD: 'ESP_DRAM_LOGD', ESP_LOGV: 'ESP_DRAM_LOGV',
  malloc: null, calloc: null, realloc: null, free: null, vTaskDelay: null, vTaskDelayUntil: null,
  xQueueSend: 'xQueueSendFromISR', xQueueSendToBack: 'xQueueSendToBackFromISR', xQueueSendToFront: 'xQueueSendToFrontFromISR',
  xQueueReceive: 'xQueueReceiveFromISR', xSemaphoreTake: 'xSemaphoreTakeFromISR', xSemaphoreGive: 'xSemaphoreGiveFromISR',
  xEventGroupSetBits: 'xEventGroupSetBitsFromISR', xTaskNotify: 'xTaskNotifyFromISR', xTaskNotifyGive: 'vTaskNotifyGiveFromISR',
  xTimerStart: 'xTimerStartFromISR', fopen: null, fwrite: null, fprintf: null,
};

const isrUnsafe: CustomRule = {
  kind: 'custom',
  id: 'esp32/isr-unsafe-call',
  title: 'Blocking / non-ISR-safe call in interrupt handler',
  description: 'Interrupt handlers (`IRAM_ATTR` functions or handlers registered with `gpio_isr_handler_add`/`esp_intr_alloc`) must not block, allocate or log through the normal path; use the `FromISR` APIs and defer work to a task.',
  severity: 'warning',
  languages: C,
  message: '',
  refs: [ref.isr],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const handlers = registeredCallbacks(ctx.tree.rootNode, { gpio_isr_handler_add: 1, esp_intr_alloc: 2, gpio_isr_register: 0 });
    const out: Finding[] = [];
    for (const fn of functionDefs(ctx.tree.rootNode)) {
      if (!/\bIRAM_ATTR\b/.test(fn.header) && !handlers.has(fn.name)) {
        continue;
      }
      for (const c of calls(fn.body)) {
        if (c.name in ISR_UNSAFE) {
          const alt = ISR_UNSAFE[c.name];
          const f = ctx.report(c.node.childForFieldName('function')!, `\`${c.name}\` is not safe in interrupt handler \`${fn.name}\`${alt ? `; use \`${alt}\`` : '; defer it to a task'}.`);
          out.push(f);
        }
      }
    }
    return out;
  },
};

const CSI_HEAVY = /^(printf|puts|ESP_LOG[EWIDV]|malloc|calloc|realloc|free|vTaskDelay|fopen|fwrite|fprintf|nvs_\w+|esp_http_client_\w+|send|sendto|esp_now_send|xSemaphoreTake|esp_mqtt_client_publish|uart_write_bytes)$/;

const csiCallback: CustomRule = {
  kind: 'custom',
  id: 'esp32/csi-callback-heavy',
  title: 'Heavy work in Wi-Fi CSI callback',
  description: 'The CSI receive callback runs in the Wi-Fi task. Logging, allocation, I/O or blocking there drops packets and can starve the Wi-Fi stack; copy `info->buf` into a queue and process it in your own task.',
  severity: 'warning',
  languages: C,
  message: '',
  refs: [ref.csi],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const cbs = registeredCallbacks(ctx.tree.rootNode, { esp_wifi_set_csi_rx_cb: 0 });
    const out: Finding[] = [];
    for (const fn of functionDefs(ctx.tree.rootNode).filter((f) => cbs.has(f.name))) {
      for (const c of calls(fn.body).filter((c) => CSI_HEAVY.test(c.name))) {
        out.push(ctx.report(c.node.childForFieldName('function')!, `\`${c.name}\` in CSI callback \`${fn.name}\` runs in the Wi-Fi task; defer it via a queue.`));
      }
    }
    return out;
  },
};

const espRandomEntropy: QueryRule = {
  id: 'esp32/esp-random-entropy',
  title: 'esp_random() without an enabled entropy source',
  description: 'The hardware RNG only produces true random numbers while Wi-Fi/Bluetooth RF is running or after `bootloader_random_enable()`; otherwise its output must be treated as pseudo-random. This file never enables a source (it may happen elsewhere — suppress if so).',
  severity: 'info',
  languages: C,
  message: '`{{fn}}` may return pseudo-random data: no RF or bootloader_random_enable() in this file.',
  refs: [ref.random, { label: 'NIST SP 800-90B — Entropy Sources', url: 'https://csrc.nist.gov/pubs/sp/800/90/b/final' }],
  query: '((call_expression function: (identifier) @fn) (#match? @fn "^(esp_random|esp_fill_random)$"))',
  capture: 'fn',
  unless: '\\b(esp_wifi_start|esp_bt_controller_enable|bootloader_random_enable|esp_bluedroid_enable|nimble_port_init|esp_now_init)\\b',
};

const insecureRand: QueryRule = {
  id: 'esp32/insecure-rand',
  title: 'Non-cryptographic PRNG',
  description: '`rand()`/`random()` are predictable; use `esp_fill_random()` or an mbedTLS/PSA DRBG for keys, nonces and tokens.',
  severity: 'info',
  languages: C,
  message: '`{{fn}}` is not cryptographically secure; use esp_fill_random() for security-relevant values.',
  refs: [ref.cwe(338, 'Use of Cryptographically Weak PRNG'), ref.random],
  query: '((call_expression function: (identifier) @fn) (#match? @fn "^(rand|random|rand_r|drand48|lrand48)$"))',
  capture: 'fn',
};

const SECRET_NAME = /(pass(word|wd|phrase)?|psk|secret|token|api_?key|auth_?key|private_?key|aes_?key|hmac_?key|^key$)/i;

const hardcodedCredential: CustomRule = {
  kind: 'custom',
  id: 'esp32/hardcoded-credential',
  title: 'Hard-coded credential or key',
  description: 'Credentials and keys compiled into firmware can be read from flash dumps unless flash encryption is enabled, and are shared by every device. Provision them per device into encrypted NVS.',
  severity: 'warning',
  languages: C,
  message: '',
  refs: [ref.cwe(798, 'Use of Hard-coded Credentials'), ref.nvsEnc],
  check(ctx: RuleContext): Finding[] {
    if (!ctx.tree) {
      return [];
    }
    const out: Finding[] = [];
    const isSecretLiteral = (v: Node | null) =>
      !!v && ((v.type === 'string_literal' && v.text.length > 2) || (v.type === 'initializer_list' && descendants(v, 'number_literal').length >= 16));
    for (const pair of descendants(ctx.tree.rootNode, 'initializer_pair')) {
      const field = descendants(pair, 'field_identifier')[0]?.text ?? '';
      const value = pair.childForFieldName('value');
      if (SECRET_NAME.test(field) && isSecretLiteral(value)) {
        out.push(ctx.report(value!, `\`.${field}\` is initialised with a hard-coded value.`));
      }
    }
    for (const d of descendants(ctx.tree.rootNode, 'init_declarator')) {
      const name = descendants(d.childForFieldName('declarator')!, 'identifier')[0]?.text ?? '';
      const value = d.childForFieldName('value');
      if (SECRET_NAME.test(name) && isSecretLiteral(value)) {
        out.push(ctx.report(value!, `\`${name}\` holds a hard-coded secret.`));
      }
    }
    for (const def of descendants(ctx.tree.rootNode, 'preproc_def')) {
      const name = def.childForFieldName('name')?.text ?? '';
      const value = def.childForFieldName('value');
      if (SECRET_NAME.test(name) && value && /^"[^"]+"$/.test(value.text.trim())) {
        out.push(ctx.report(value, `Macro \`${name}\` defines a hard-coded secret.`));
      }
    }
    return out;
  },
};

const tlsSkipVerify: PatternRule = {
  kind: 'pattern',
  id: 'esp32/tls-skip-verify',
  title: 'TLS server verification disabled',
  severity: 'error',
  languages: C,
  message: 'Server certificate / hostname verification is disabled (`{{match}}`).',
  refs: [ref.cwe(295, 'Improper Certificate Validation'), ref.tls],
  pattern: '\\.(skip_cert_common_name_check|use_insecure_skip_verify)\\s*=\\s*(true|1)\\b',
};

// --- sdkconfig (root of trust) -----------------------------------------------------------------

const SDKCONFIG = '(^|/)sdkconfig(\\.[\\w.-]+)?$';
const SDKCONFIG_MAIN = '(^|/)sdkconfig$';

const absent = (id: string, title: string, setting: string, message: string, refs: RuleRef[], severity: Rule['severity'] = 'warning'): AbsentRule => ({
  kind: 'absent',
  id,
  title,
  severity,
  languages: ['*'],
  pathPattern: SDKCONFIG_MAIN,
  message,
  refs,
  pattern: `^${setting}=y$`,
  anchor: `^# ${setting} is not set$`,
});

const insecure = (id: string, title: string, setting: string, message: string, refs: RuleRef[], severity: Rule['severity'] = 'warning'): PatternRule => ({
  kind: 'pattern',
  id,
  title,
  severity,
  languages: ['*'],
  pathPattern: SDKCONFIG,
  message,
  refs,
  pattern: `^${setting}=y$`,
  flags: 'm',
});

const sdkconfigRules: Rule[] = [
  absent('esp32/secure-boot-disabled', 'Secure Boot disabled', 'CONFIG_SECURE_BOOT', 'Secure Boot is disabled: any firmware image can be flashed and booted. Enable Secure Boot v2 for production.', [ref.secureBoot]),
  absent('esp32/flash-encryption-disabled', 'Flash encryption disabled', 'CONFIG_SECURE_FLASH_ENC_ENABLED', 'Flash encryption is disabled: firmware, NVS data and keys can be read from a flash dump.', [ref.flashEnc]),
  absent('esp32/nvs-encryption-disabled', 'NVS encryption disabled', 'CONFIG_NVS_ENCRYPTION', 'NVS encryption is disabled: credentials stored in NVS are readable from flash.', [ref.nvsEnc], 'info'),
  insecure('esp32/secure-boot-insecure', 'Insecure Secure Boot options', 'CONFIG_SECURE_BOOT_INSECURE', 'CONFIG_SECURE_BOOT_INSECURE weakens Secure Boot protections.', [ref.secureBoot], 'error'),
  insecure('esp32/secure-boot-allow-jtag', 'JTAG left enabled with Secure Boot', 'CONFIG_SECURE_BOOT_ALLOW_JTAG', 'JTAG stays enabled, allowing a debugger to bypass Secure Boot.', [ref.secureBoot]),
  insecure('esp32/flash-enc-development', 'Flash encryption in Development mode', 'CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT', 'Development mode lets the UART bootloader re-flash plaintext; use Release mode in production.', [ref.flashEnc]),
  insecure('esp32/uart-bootloader-decrypt', 'UART bootloader can decrypt flash', 'CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_DEC', 'The UART bootloader can read decrypted flash.', [ref.flashEnc], 'error'),
  insecure('esp32/uart-bootloader-encrypt', 'UART bootloader can write encrypted flash', 'CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC', 'The UART bootloader can write encrypted flash.', [ref.flashEnc]),
  insecure('esp32/uart-bootloader-cache', 'UART bootloader flash cache enabled', 'CONFIG_SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE', 'The UART bootloader can read flash through the cache.', [ref.flashEnc]),
  insecure('esp32/insecure-download-mode', 'Insecure ROM download mode', 'CONFIG_SECURE_INSECURE_ALLOW_DL_MODE', 'ROM download mode stays fully enabled; use Secure Download Mode or disable it.', [ref.security]),
  insecure('esp32/tls-insecure', 'ESP-TLS insecure mode', 'CONFIG_ESP_TLS_INSECURE', 'ESP-TLS insecure options are enabled.', [ref.tls, ref.cwe(295, 'Improper Certificate Validation')], 'error'),
  insecure('esp32/tls-skip-server-verify', 'ESP-TLS skips server verification', 'CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY', 'TLS server certificates are not verified (man-in-the-middle possible).', [ref.tls, ref.cwe(295, 'Improper Certificate Validation')], 'error'),
  insecure('esp32/no-stack-protector', 'Stack smashing protection disabled', 'CONFIG_COMPILER_STACK_CHECK_MODE_NONE', 'Stack canaries are disabled; enable CONFIG_COMPILER_STACK_CHECK_MODE_NORM or STRONG.', [ref.memprot], 'info'),
  {
    kind: 'pattern', id: 'esp32/memprot-disabled', title: 'Memory protection disabled', severity: 'warning', languages: ['*'], pathPattern: SDKCONFIG,
    message: 'Hardware memory protection (PMS) is disabled; executable data memory makes exploitation easier.', refs: [ref.memprot],
    pattern: '^# CONFIG_ESP_SYSTEM_MEMPROT_FEATURE is not set$', flags: 'm',
  },
  {
    kind: 'pattern', id: 'esp32/verbose-logging', title: 'Verbose default log level', severity: 'info', languages: ['*'], pathPattern: SDKCONFIG,
    message: 'Debug/verbose logs can leak secrets over UART in production builds.', refs: [ref.security],
    pattern: '^CONFIG_LOG_DEFAULT_LEVEL_(DEBUG|VERBOSE)=y$', flags: 'm',
  },
];

// --- ESPHome YAML ------------------------------------------------------------------------------

const ESPHOME = '^esphome:';
const block = (key: string, child: string) => `^${key}:[ \\t]*\\n(?:[ \\t]+.*\\n|[ \\t]*\\n|[ \\t]+-.*\\n)*?[ \\t]+${child}:`;

const esphomeRules: Rule[] = [
  {
    kind: 'pattern', id: 'esphome/plaintext-secret', title: 'Plaintext secret in ESPHome config', severity: 'warning', languages: ['yaml'], when: ESPHOME,
    message: 'Secret value is written inline; use `!secret` so it stays out of version control.', refs: [ref.esphomeSecrets, ref.cwe(798, 'Use of Hard-coded Credentials')],
    pattern: '^[ \\t]*(?:password|ap_password|ota_password|api_password|key|encryption_key):[ \\t]*(?!!secret\\b)(?<value>["\']?[^\\s#"\'][^#\\n]*)$', flags: 'm',
  },
  {
    kind: 'absent', id: 'esphome/api-unencrypted', title: 'ESPHome native API without encryption', severity: 'warning', languages: ['yaml'],
    when: `${ESPHOME}[\\s\\S]*^api:|^api:[\\s\\S]*${ESPHOME}`, message: 'The native API has no `encryption:` key; traffic and control are unauthenticated.',
    refs: [ref.esphomeApi], pattern: block('api', 'encryption'), anchor: '^api:',
  },
  {
    kind: 'absent', id: 'esphome/ota-no-password', title: 'ESPHome OTA without password', severity: 'warning', languages: ['yaml'],
    when: `${ESPHOME}[\\s\\S]*^ota:|^ota:[\\s\\S]*${ESPHOME}`, message: 'OTA updates are not password-protected; anyone on the network can flash firmware.',
    refs: [ref.esphomeOta], pattern: block('ota', 'password'), anchor: '^ota:',
  },
  {
    kind: 'absent', id: 'esphome/web-server-no-auth', title: 'ESPHome web server without auth', severity: 'warning', languages: ['yaml'],
    when: `${ESPHOME}[\\s\\S]*^web_server:|^web_server:[\\s\\S]*${ESPHOME}`, message: 'The web server has no `auth:`; the device can be controlled by anyone on the network.',
    refs: [ref.esphomeWeb], pattern: block('web_server', 'auth'), anchor: '^web_server:',
  },
];

export const ESP32_RULES: Rule[] = [
  unsafeString,
  uncheckedLength,
  uncheckedAlloc,
  uncheckedEspErr,
  formatString,
  isrUnsafe,
  csiCallback,
  espRandomEntropy,
  insecureRand,
  hardcodedCredential,
  tlsSkipVerify,
  ...sdkconfigRules,
  ...esphomeRules,
];
