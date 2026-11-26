#pragma once
#include <stdint.h>

/* Everything a scanner needs to hash an 80-byte block header for a range of nonces.
 * The first 64 header bytes never change while the nonce rolls, so they are folded
 * into a midstate once per work unit. */
typedef struct {
    uint32_t mid[8];   /* SHA-256 state after header bytes 0..63            */
    uint32_t w0, w1, w2; /* big-endian words of header bytes 64..75:
                          * merkle root tail, ntime, nbits                  */
    uint32_t h7_want;  /* report nonces whose final digest word 7 equals this.
                        * 0 in real mining (top 32 bits of the hash are zero,
                        * i.e. difficulty >= 1). Other values are used by tests. */
} scan_job_t;

/* Scan nonces [first, first+count). count must be a multiple of 16.
 * Writes candidate nonces to out (at most max_out) and returns how many. */
typedef int (*scan_fn)(const scan_job_t *job, uint32_t first, uint32_t count,
                       uint32_t *out, int max_out);

int scan_scalar(const scan_job_t *, uint32_t, uint32_t, uint32_t *, int);
int scan_shani(const scan_job_t *, uint32_t, uint32_t, uint32_t *, int);
int scan_avx512(const scan_job_t *, uint32_t, uint32_t, uint32_t *, int);

int cpu_has_shani(void);
int cpu_has_avx512(void);
