import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../src/hw';
import { RESTART_VECTOR } from '../../../extensions/hw-security/test/unit/vectors';
import { captureIo, REPO } from './io';

const FX = join(REPO, 'extensions/hw-security/test/fixtures');

describe('jest-hw', () => {
  it('lints firmware, sdkconfig and ESPHome', async () => {
    const io = captureIo(FX);
    expect(await main(['lint', 'esp-app', 'esphome'], io)).toBe(1);
    const out = io.stdout();
    for (const id of ['esp32/unchecked-esp-err', 'esp32/secure-boot-disabled', 'esphome/api-unencrypted', 'esp32/tls-skip-server-verify']) {
      expect(out).toContain(id);
    }
    expect(out).toContain('esp-app/sdkconfig');
  });

  it('assesses entropy like NIST ea_non_iid', async () => {
    const io = captureIo(FX);
    expect(await main(['entropy', 'entropy/rand8_short.bin', '--bits', '8', '--json'], io)).toBe(0);
    expect((JSON.parse(io.stdout()) as { hAssessed: number }).hAssessed).toBeCloseTo(5.860893744485249, 9);
    const text = captureIo(FX);
    expect(await main(['entropy', 'entropy/rand8_short.bin', '-b', '8', '--min', '7'], text)).toBe(1);
    expect(text.stdout()).toContain('6.3.10 LZ78Y Prediction');
    expect(text.stderr()).toContain('below --min 7');
  });

  it('runs the restart test', async () => {
    const io = captureIo(FX);
    // The 10,000-sample NIST file is not a 1000×1000 restart matrix.
    expect(await main(['restart', 'entropy/rand8_short.bin', '--hi', '7'], io)).toBe(2);
    expect(io.stderr()).toContain('1000000');
    expect(await main(['restart', 'entropy/rand8_short.bin'], captureIo(FX))).toBe(2);
  });

  it('passes the restart test on the NIST-validated vector', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'cli-'));
    writeFileSync(join(dir, 'r.bin'), RESTART_VECTOR.data());
    const io = captureIo(dir);
    expect(await main(['restart', 'r.bin', '--hi', String(RESTART_VECTOR.hI), '--bits', '2', '--rounds', '20000'], io)).toBe(0);
    expect(io.stdout()).toContain('PASSED');
    expect(io.stdout()).toContain('H_r:    1.308180');
  }, 120_000);

  it('reports PUF metrics', async () => {
    const io = captureIo(FX);
    expect(await main(['puf', 'puf/sram.csv'], io)).toBe(0);
    expect(io.stdout()).toMatch(/Uniqueness\s+4\d\.\d+ %/);
    expect(io.stdout()).toMatch(/ECC: 255-bit blocks need t = \d+/);
    expect(await main(['puf', 'puf/sram.csv', '--min-reliability', '0.999'], captureIo(FX))).toBe(1);
  });

  it('lists side-channel points and flags orphans', async () => {
    const io = captureIo(FX);
    expect(await main(['sca', 'sca'], io)).toBe(1);
    expect(io.stdout()).toContain('aes-sbox  [analysed by 1]');
    expect(io.stdout()).toContain('target    sca/firmware/aes.c:9');
    expect(io.stdout()).toContain('problem: @sca-ref(modexp-branch) has no @sca tag');
  });
});
