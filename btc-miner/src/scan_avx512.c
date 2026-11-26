/* AVX-512 16-way double-SHA256 nonce scanner.
 *
 * Each zmm lane hashes a different nonce. AVX-512 gives SHA-256 three big wins
 * over AVX2: VPROLD/VPRORD (native rotate), VPTERNLOGD (Ch, Maj and the 3-way XORs
 * of the sigma functions in one instruction each) and 32 registers, enough to keep
 * the 8 state words and the 16-word message window resident with no spills.
 * Zen 4 executes 512-bit ops as two 256-bit halves, so the gain there comes from
 * the instruction count, not the width.
 *
 * Bitcoin-specific shortcuts:
 *  - midstate (caller), plus rounds 0-2 of hash #1 (they only see the merkle tail,
 *    ntime and nbits), computed once per call in scalar code.
 *  - message words that are padding constants (hash #1: W4..W15, hash #2: W8..W15)
 *    are folded at compile time: schedule terms that touch them become immediates.
 *  - round 0 of hash #2 starts from the constant IV, so it collapses to two adds.
 *  - hash #2 stops after round index 60, computing only e: digest word 7 = IV7 + h(S64)
 *    and h(S64) = e(S61), so rounds 61-63 and their message words are never needed. */
#include "scan.h"
#include "sha256.h"
#include <immintrin.h>

#define TGT __attribute__((target("avx512f,avx512bw,avx512vl")))
#define AI static inline __attribute__((always_inline)) TGT
typedef __m512i V;

#define B(x) _mm512_set1_epi32((int)(x))
#define ADD(a, b) _mm512_add_epi32(a, b)
#define XOR3(a, b, c) _mm512_ternarylogic_epi32(a, b, c, 0x96)
#define CHv(e, f, g) _mm512_ternarylogic_epi32(e, f, g, 0xCA)
#define MAJv(a, b, c) _mm512_ternarylogic_epi32(a, b, c, 0xE8)
#define ROR(x, n) _mm512_ror_epi32(x, n)
#define BS0(a) XOR3(ROR(a, 2), ROR(a, 13), ROR(a, 22))
#define BS1(e) XOR3(ROR(e, 6), ROR(e, 11), ROR(e, 25))
#define SS0(w) XOR3(ROR(w, 7), ROR(w, 18), _mm512_srli_epi32(w, 3))
#define SS1(w) XOR3(ROR(w, 17), ROR(w, 19), _mm512_srli_epi32(w, 10))

/* Role r (0=a .. 7=h) at round i lives in st[(r - i) & 7]; no register moves. */
#define R(r) st[((r) - (i)) & 7]

AI void round_v(V st[8], const int i, V kw) {
    V t1 = ADD(ADD(R(7), BS1(R(4))), ADD(CHv(R(4), R(5), R(6)), kw));
    V t2 = ADD(BS0(R(0)), MAJv(R(0), R(1), R(2)));
    R(3) = ADD(R(3), t1);
    R(7) = ADD(t1, t2);
}

/* Message word i >= 16 for a block whose words [clo, chi] are compile-time constants c[].
 * Constant terms are summed as scalars (folded by the compiler), the rest as vectors. */
AI V sched(V w[16], const int i, const uint32_t c[16], const int clo, const int chi) {
#define ISC(k) ((k) >= clo && (k) <= chi)
    uint32_t cs = 0;
    V acc = _mm512_setzero_si512();
    int have = 0;
    const int k2 = i - 2, k7 = i - 7, k15 = i - 15, k16 = i - 16;
    if (ISC(k2)) cs += ssig1(c[k2]); else { acc = have ? ADD(acc, SS1(w[k2 & 15])) : SS1(w[k2 & 15]); have = 1; }
    if (ISC(k7)) cs += c[k7];        else { acc = have ? ADD(acc, w[k7 & 15]) : w[k7 & 15]; have = 1; }
    if (ISC(k15)) cs += ssig0(c[k15]); else { acc = have ? ADD(acc, SS0(w[k15 & 15])) : SS0(w[k15 & 15]); have = 1; }
    if (ISC(k16)) cs += c[k16];      else { acc = have ? ADD(acc, w[k16 & 15]) : w[k16 & 15]; have = 1; }
    if (cs) acc = have ? ADD(acc, B(cs)) : B(cs);
    return acc;
#undef ISC
}

static const uint32_t C1[16] = {0, 0, 0, 0, 0x80000000u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640};
static const uint32_t C2[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0x80000000u, 0, 0, 0, 0, 0, 0, 256};

TGT int scan_avx512(const scan_job_t *job, uint32_t first, uint32_t count, uint32_t *out, int max_out) {
    /* scalar precompute: rounds 0..2 of hash #1 */
    uint32_t ss[8];
    for (int r = 0; r < 8; r++) ss[r] = job->mid[r];
    sha256_round(ss, SHA256_K[0] + job->w0);
    sha256_round(ss, SHA256_K[1] + job->w1);
    sha256_round(ss, SHA256_K[2] + job->w2);
    /* hash #2 round 0 constants */
    const uint32_t c0 = SHA256_IV[7] + bsig1(SHA256_IV[4]) + ch32(SHA256_IV[4], SHA256_IV[5], SHA256_IV[6]) + SHA256_K[0];
    const uint32_t t2c = bsig0(SHA256_IV[0]) + maj32(SHA256_IV[0], SHA256_IV[1], SHA256_IV[2]);

    const V bswap = _mm512_set_epi8(
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
        12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3);
    const V lane = _mm512_set_epi32(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0);
    const V want = B(job->h7_want - SHA256_IV[7]);
    int found = 0;

    for (uint32_t base = 0; base < count; base += 16) {
        V st[8], w[16];
        const uint32_t n0 = first + base;
        /* ---- hash #1, block 2 ---- */
        w[0] = B(job->w0); w[1] = B(job->w1); w[2] = B(job->w2);
        w[3] = _mm512_shuffle_epi8(ADD(B(n0), lane), bswap);
        {
            const int i = 3;
            for (int r = 0; r < 8; r++) R(r) = B(ss[r]);
            round_v(st, 3, ADD(w[3], B(SHA256_K[3])));
        }
#pragma GCC unroll 16
        for (int i = 4; i < 16; i++) round_v(st, i, B(SHA256_K[i] + C1[i]));
#pragma GCC unroll 48
        for (int i = 16; i < 64; i++) {
            w[i & 15] = sched(w, i, C1, 4, 15);
            round_v(st, i, ADD(w[i & 15], B(SHA256_K[i])));
        }
        /* after 64 rounds role r is st[r]; feed forward -> hash #2 message words 0..7 */
        for (int r = 0; r < 8; r++) w[r] = ADD(st[r], B(job->mid[r]));

        /* ---- hash #2 ---- */
        {
            const int i = 1; /* lay out state after the constant-folded round 0 */
            V t1 = ADD(w[0], B(c0));
            R(0) = ADD(t1, B(t2c));
            R(1) = B(SHA256_IV[0]); R(2) = B(SHA256_IV[1]); R(3) = B(SHA256_IV[2]);
            R(4) = ADD(t1, B(SHA256_IV[3]));
            R(5) = B(SHA256_IV[4]); R(6) = B(SHA256_IV[5]); R(7) = B(SHA256_IV[6]);
        }
#pragma GCC unroll 8
        for (int i = 1; i < 8; i++) round_v(st, i, ADD(w[i], B(SHA256_K[i])));
#pragma GCC unroll 8
        for (int i = 8; i < 16; i++) round_v(st, i, B(SHA256_K[i] + C2[i]));
#pragma GCC unroll 44
        for (int i = 16; i < 60; i++) {
            w[i & 15] = sched(w, i, C2, 8, 15);
            round_v(st, i, ADD(w[i & 15], B(SHA256_K[i])));
        }
        V e61; /* e of state S61, produced by round index 60 */
        {
            const int i = 60;
            V w60 = sched(w, 60, C2, 8, 15);
            V t1 = ADD(ADD(R(7), BS1(R(4))), ADD(CHv(R(4), R(5), R(6)), ADD(w60, B(SHA256_K[60]))));
            e61 = ADD(R(3), t1);
        }
        __mmask16 m = _mm512_cmpeq_epi32_mask(e61, want);
        if (__builtin_expect(m != 0, 0)) {
            while (m && found < max_out) {
                int b = __builtin_ctz(m);
                out[found++] = n0 + (uint32_t)b;
                m &= m - 1;
            }
        }
    }
    return found;
}
#undef R
