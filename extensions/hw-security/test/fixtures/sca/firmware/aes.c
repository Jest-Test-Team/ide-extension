// Minimal AES-128 first round, the classic ChipWhisperer CPA target.
#include <stdint.h>
#include <string.h>

extern const uint8_t sbox[256];

void aes_first_round(uint8_t state[16], const uint8_t key[16]) {
    for (int i = 0; i < 16; i++) {
        // @sca(aes-sbox, "S-box lookup indexed by plaintext ^ key byte (first-round CPA)")
        state[i] = sbox[state[i] ^ key[i]];
    }
}

// Not tagged yet: the linter suggests tagging these.
uint32_t modexp_ladder(uint32_t base, uint32_t secret_exp, uint32_t mod) {
    uint32_t r = 1;
    for (int b = 31; b >= 0; b--) {
        r = (r * r) % mod;
        if ((secret_exp >> b) & 1) {
            r = (r * base) % mod;
        }
    }
    return r;
}

int hmac_verify(const uint8_t *mac, const uint8_t *expected) {
    return memcmp(mac, expected, 32) == 0;
}
