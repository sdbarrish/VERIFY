#include "scan.h"
#include <cpuid.h>
#include <stdint.h>

static uint64_t xgetbv0(void) {
    uint32_t a, d;
    __asm__ volatile("xgetbv" : "=a"(a), "=d"(d) : "c"(0));
    return ((uint64_t)d << 32) | a;
}

int cpu_has_shani(void) {
    unsigned a, b, c, d;
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 0;
    unsigned a1, b1, c1, d1;
    if (!__get_cpuid(1, &a1, &b1, &c1, &d1)) return 0;
    return (b >> 29 & 1) && (c1 >> 19 & 1); /* SHA + SSE4.1 */
}

int cpu_has_avx512(void) {
    unsigned a, b, c, d, a1, b1, c1, d1;
    if (!__get_cpuid(1, &a1, &b1, &c1, &d1) || !(c1 >> 27 & 1)) return 0; /* OSXSAVE */
    if ((xgetbv0() & 0xE6) != 0xE6) return 0; /* OS saves XMM/YMM/opmask/ZMM state */
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d)) return 0;
    return (b >> 16 & 1) && (b >> 30 & 1) && (b >> 31 & 1); /* F, BW, VL */
}
