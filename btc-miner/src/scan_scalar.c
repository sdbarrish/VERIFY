#include "scan.h"
#include "sha256.h"
#include <string.h>

int scan_scalar(const scan_job_t *job, uint32_t first, uint32_t count, uint32_t *out, int max_out) {
    int found = 0;
    uint32_t w[16] = {job->w0, job->w1, job->w2, 0, 0x80000000u, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 640};
    for (uint32_t i = 0; i < count; i++) {
        uint32_t n = first + i, s[8], w2[16], s2[8];
        w[3] = __builtin_bswap32(n);
        memcpy(s, job->mid, 32);
        sha256_transform_words(s, w);
        memcpy(w2, s, 32);
        w2[8] = 0x80000000u;
        memset(w2 + 9, 0, 6 * 4);
        w2[15] = 256;
        memcpy(s2, SHA256_IV, 32);
        sha256_transform_words(s2, w2);
        if (s2[7] == job->h7_want && found < max_out) out[found++] = n;
    }
    return found;
}
