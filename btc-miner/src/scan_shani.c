/* SHA-NI double-SHA256 nonce scanner.
 *
 * Zen 4 executes SHA256RNDS2 with ~4 cycle latency, so a single hash chain leaves
 * the unit idle most of the time. We interleave SHANI_LANES independent nonces so
 * the dependency chains overlap.
 *
 * Bitcoin-specific shortcuts:
 *  - midstate: header bytes 0..63 are hashed once per work unit (caller).
 *  - rounds 0-1 of hash #1 only see W0,W1 (merkle tail, ntime): computed once per call.
 *  - hash #2 stops after rounds 60-61: digest word 7 = IV7 + e(round 61), and after
 *    that rnds2 e(61) is already sitting in the F slot of the ABEF register, so the
 *    final rnds2, the feed-forward and the output shuffles are skipped. */
#include "scan.h"
#include "sha256.h"
#include <immintrin.h>

#ifndef SHANI_LANES
#define SHANI_LANES 4
#endif
#define L SHANI_LANES
#define AI static inline __attribute__((always_inline))

AI __m128i KV(int j) { return _mm_loadu_si128((const __m128i *)&SHA256_K[4 * j]); }

AI void to_abef(const uint32_t s[8], __m128i *abef, __m128i *cdgh) {
    __m128i t = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)&s[0]), 0xB1);
    __m128i u = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)&s[4]), 0x1B);
    *abef = _mm_alignr_epi8(t, u, 8);
    *cdgh = _mm_blend_epi16(u, t, 0xF0);
}

/* Quad-rounds start_j..15. M[l][j&3] holds message words 4j..4j+3 (dword 0 = lowest index).
 * stop_early: return after the first rnds2 of quad 15, leaving ABEF of state 62 in S1. */
AI void rounds(__m128i S0[L], __m128i S1[L], __m128i M[L][4], const int start_j, const int stop_early) {
#pragma GCC unroll 16
    for (int j = start_j; j < 16; j++) {
        __m128i msg[L];
        for (int l = 0; l < L; l++) msg[l] = _mm_add_epi32(M[l][j & 3], KV(j));
        for (int l = 0; l < L; l++) S1[l] = _mm_sha256rnds2_epu32(S1[l], S0[l], msg[l]);
        if (j == 15 && stop_early) return;
        if (j >= 3 && j <= 14)
            for (int l = 0; l < L; l++) {
                __m128i t = _mm_alignr_epi8(M[l][j & 3], M[l][(j - 1) & 3], 4);
                M[l][(j + 1) & 3] = _mm_sha256msg2_epu32(_mm_add_epi32(M[l][(j + 1) & 3], t), M[l][j & 3]);
            }
        for (int l = 0; l < L; l++) S0[l] = _mm_sha256rnds2_epu32(S0[l], S1[l], _mm_shuffle_epi32(msg[l], 0x0E));
        if (j >= 1 && j <= 12)
            for (int l = 0; l < L; l++) M[l][(j - 1) & 3] = _mm_sha256msg1_epu32(M[l][(j - 1) & 3], M[l][j & 3]);
    }
}

__attribute__((target("sha,sse4.1")))
int scan_shani(const scan_job_t *job, uint32_t first, uint32_t count, uint32_t *out, int max_out) {
    __m128i mabef, mcdgh, iabef, icdgh;
    to_abef(job->mid, &mabef, &mcdgh);
    to_abef(SHA256_IV, &iabef, &icdgh);
    const __m128i b0 = _mm_set_epi32(0, (int)job->w2, (int)job->w1, (int)job->w0);
    const __m128i pre = _mm_sha256rnds2_epu32(mcdgh, mabef, _mm_add_epi32(b0, KV(0)));
    const __m128i zero = _mm_setzero_si128();
    const __m128i pad1 = _mm_set_epi32(0, 0, 0, (int)0x80000000u);
    const __m128i len1 = _mm_set_epi32(640, 0, 0, 0);
    const __m128i len2 = _mm_set_epi32(256, 0, 0, 0);
    const int want = (int)(job->h7_want - SHA256_IV[7]);
    int found = 0;

    for (uint32_t i = 0; i < count; i += L) {
        __m128i S0[L], S1[L], M[L][4];
        /* hash 1, second block of the header */
        for (int l = 0; l < L; l++) {
            M[l][0] = _mm_insert_epi32(b0, (int)__builtin_bswap32(first + i + l), 3);
            M[l][1] = pad1; M[l][2] = zero; M[l][3] = len1;
            S0[l] = mabef; S1[l] = pre;
            S0[l] = _mm_sha256rnds2_epu32(S0[l], S1[l], _mm_shuffle_epi32(_mm_add_epi32(M[l][0], KV(0)), 0x0E));
        }
        rounds(S0, S1, M, 1, 0);
        /* hash 2 over the 32-byte digest */
        for (int l = 0; l < L; l++) {
            __m128i a = _mm_add_epi32(S0[l], mabef), c = _mm_add_epi32(S1[l], mcdgh);
            __m128i t = _mm_shuffle_epi32(a, 0x1B);
            c = _mm_shuffle_epi32(c, 0xB1);
            M[l][0] = _mm_blend_epi16(t, c, 0xF0);  /* H0..H3 */
            M[l][1] = _mm_alignr_epi8(c, t, 8);     /* H4..H7 */
            M[l][2] = pad1; M[l][3] = len2;
            S0[l] = iabef; S1[l] = icdgh;
        }
        rounds(S0, S1, M, 0, 1);
        for (int l = 0; l < L; l++)
            if (__builtin_expect(_mm_cvtsi128_si32(S1[l]) == want, 0) && found < max_out)
                out[found++] = first + i + l;
    }
    return found;
}
