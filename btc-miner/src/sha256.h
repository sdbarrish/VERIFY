#pragma once
#include <stdint.h>
#include <stddef.h>

extern const uint32_t SHA256_K[64];
extern const uint32_t SHA256_IV[8];

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static inline uint32_t bsig0(uint32_t x) { return ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22); }
static inline uint32_t bsig1(uint32_t x) { return ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25); }
static inline uint32_t ssig0(uint32_t x) { return ROR32(x, 7) ^ ROR32(x, 18) ^ (x >> 3); }
static inline uint32_t ssig1(uint32_t x) { return ROR32(x, 17) ^ ROR32(x, 19) ^ (x >> 10); }
static inline uint32_t ch32(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
static inline uint32_t maj32(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }

static inline uint32_t rd_be32(const uint8_t *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 | p[0];
}
static inline void wr_be32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static inline void wr_le32(uint8_t *p, uint32_t v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }

/* One SHA-256 round on working variables st[0..7] = a..h with kw = K[i] + W[i]. */
static inline void sha256_round(uint32_t st[8], uint32_t kw) {
    uint32_t t1 = st[7] + bsig1(st[4]) + ch32(st[4], st[5], st[6]) + kw;
    uint32_t t2 = bsig0(st[0]) + maj32(st[0], st[1], st[2]);
    st[7] = st[6]; st[6] = st[5]; st[5] = st[4]; st[4] = st[3] + t1;
    st[3] = st[2]; st[2] = st[1]; st[1] = st[0]; st[0] = t1 + t2;
}

void sha256_transform_words(uint32_t state[8], const uint32_t w[16]);
void sha256_transform(uint32_t state[8], const uint8_t block[64]);
void sha256(const void *data, size_t len, uint8_t out[32]);
void sha256d(const void *data, size_t len, uint8_t out[32]);
