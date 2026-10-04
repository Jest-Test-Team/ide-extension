import { RuleEngine, type Finding } from '@ide-ext/core';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { testHost } from '../../../../packages/core/test/grammars';
import { ESP32_RULES } from '../../src/esp32Rules';

const engine = new RuleEngine(testHost(), ESP32_RULES);
const fixture = (p: string) => join(__dirname, '../fixtures', p);
const run = (path: string, languageId: string, text = readFileSync(path, 'utf8')) =>
  engine.run({ uri: `file://${path}`, path, languageId, text });
const byRule = (fs: Finding[]) => {
  const m = new Map<string, number[]>();
  fs.forEach((f) => m.set(f.ruleId, [...(m.get(f.ruleId) ?? []), f.range.start.line + 1]));
  return Object.fromEntries(m);
};

describe('ESP32 C rules', () => {
  it('flags the insecure ESP-IDF fixture', async () => {
    const r = byRule(await run(fixture('esp-app/main/csi_main.c'), 'c'));
    expect(r['esp32/unsafe-string-fn']).toEqual([40]);
    expect(r['esp32/format-string']).toEqual([38]);
    // info->len in the CSI callback and bufsize in the unchecked HID handler; the checked handler is clean.
    expect(r['esp32/unchecked-length']).toEqual([18, 27]);
    expect(r['esp32/csi-callback-heavy']).toEqual([19]);
    expect(r['esp32/isr-unsafe-call']).toEqual([23]);
    // esp_netif_create_default_wifi_sta returns a pointer and is not reported.
    expect(r['esp32/unchecked-esp-err']).toEqual([44, 48, 49, 50]);
    expect(r['esp32/unchecked-alloc']).toEqual([51]);
    expect(r['esp32/hardcoded-credential'].sort((a, b) => a - b)).toEqual([8, 13, 47]);
    expect(r['esp32/insecure-rand']).toEqual([58]);
    // esp_wifi_start is never called in this file
    expect(r['esp32/esp-random-entropy']).toEqual([57]);
  });

  it('offers ESP_ERROR_CHECK and %s fixes', async () => {
    const out = await run(fixture('esp-app/main/csi_main.c'), 'c');
    const err = out.find((f) => f.ruleId === 'esp32/unchecked-esp-err')!;
    expect(err.fix?.edits[0].newText).toBe('ESP_ERROR_CHECK(nvs_flash_init())');
    const fmt = out.find((f) => f.ruleId === 'esp32/format-string')!;
    expect(fmt.fix?.edits[0].newText).toBe('"%s", payload');
  });

  it('accepts an entropy source and checked allocations', async () => {
    const src = 'void f(void){ esp_wifi_start(); uint32_t x = esp_random(); char *p = malloc(4); if (!p) return; }';
    const r = byRule(await run('/w/a.c', 'c', src));
    expect(r['esp32/esp-random-entropy']).toBeUndefined();
    expect(r['esp32/unchecked-alloc']).toBeUndefined();
    expect(r['esp32/unchecked-esp-err']).toEqual([1]);
  });

  it('works for C++ sources too', async () => {
    const r = byRule(await run('/w/a.cpp', 'cpp', 'void f(char *d, const char *s) { strcpy(d, s); }'));
    expect(r['esp32/unsafe-string-fn']).toEqual([1]);
  });
});

describe('sdkconfig rules', () => {
  it('reports disabled and insecure root-of-trust settings', async () => {
    const r = byRule(await run(fixture('esp-app/sdkconfig'), 'properties'));
    expect(r).toEqual({
      'esp32/secure-boot-disabled': [3],
      'esp32/nvs-encryption-disabled': [7],
      'esp32/flash-enc-development': [5],
      'esp32/uart-bootloader-decrypt': [6],
      'esp32/tls-skip-server-verify': [8],
      'esp32/no-stack-protector': [10],
      'esp32/memprot-disabled': [9],
    });
  });

  it('does not apply absent-rules to sdkconfig.defaults', async () => {
    const r = byRule(await run('/w/sdkconfig.defaults', 'properties', 'CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT=y\n'));
    expect(Object.keys(r)).toEqual(['esp32/flash-enc-development']);
  });
});

describe('ESPHome rules', () => {
  it('flags plaintext secrets, unencrypted API and unauthenticated web server', async () => {
    const r = byRule(await run(fixture('esphome/livingroom.yaml'), 'yaml'));
    expect(r).toEqual({
      'esphome/plaintext-secret': [9],
      'esphome/api-unencrypted': [11],
      'esphome/web-server-no-auth': [18],
    });
  });

  it('ignores non-ESPHome YAML', async () => {
    expect(await run('/w/compose.yaml', 'yaml', 'services:\n  db:\n    password: abc\napi:\n  x: 1\n')).toEqual([]);
  });
});
