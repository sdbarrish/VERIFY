/* zenminer: Bitcoin SHA-256d CPU miner tuned for AMD Zen 4 (Ryzen 9 7900X).
 *
 *   zenminer --test                         self-test every scanner against reference SHA-256
 *   zenminer --bench [-t N] [-a ALGO]       measure hashrate (no network)
 *   zenminer -o stratum+tcp://host:port -u USER [-p PASS] [-t N] [-a ALGO]
 *
 * ALGO: auto | shani | avx512 | mixed | scalar
 *   mixed = SHA-NI on the first half of the threads, AVX-512 on the second half.
 *   With Linux's usual Zen numbering (CPU i and i+12 are SMT siblings on a
 *   7900X) each physical core then runs one of each, so the SHA unit and the
 *   vector ALUs are busy at the same time. */
#define _GNU_SOURCE
#include "json.h"
#include "scan.h"
#include "sha256.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define MAX_THREADS 256
#define CHUNK (1u << 16) /* nonces per scan call; also the new-job check interval */
#define MAX_CB 16384
#define MAX_MERKLE 32

/* ------------------------------------------------------------------ utils */

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static pthread_mutex_t log_mtx = PTHREAD_MUTEX_INITIALIZER;
static void logf_(const char *fmt, ...) {
    va_list ap;
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    pthread_mutex_lock(&log_mtx);
    printf("[%02d:%02d:%02d] ", tm.tm_hour, tm.tm_min, tm.tm_sec);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
    pthread_mutex_unlock(&log_mtx);
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
/* Returns decoded length, or -1 on malformed input / overflow. */
static long hex2bin(uint8_t *out, size_t cap, const char *hex) {
    size_t n = strlen(hex);
    if (n % 2 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int h = hexval(hex[2 * i]), l = hexval(hex[2 * i + 1]);
        if (h < 0 || l < 0) return -1;
        out[i] = (uint8_t)(h << 4 | l);
    }
    return (long)(n / 2);
}
static void bin2hex(char *out, const uint8_t *in, size_t n) {
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2 * i] = d[in[i] >> 4]; out[2 * i + 1] = d[in[i] & 15]; }
    out[2 * n] = 0;
}

/* Hash and targets as little-endian 256-bit integers: word 7 is most significant. */
static int hash_le_target(const uint8_t hash[32], const uint32_t target[8]) {
    for (int i = 7; i >= 0; i--) {
        uint32_t h = rd_le32(hash + 4 * i);
        if (h != target[i]) return h < target[i];
    }
    return 1;
}
static void diff_to_target(uint32_t t[8], double diff) {
    int k;
    if (diff <= 0) diff = 1;
    for (k = 6; k > 0 && diff > 1.0; k--) diff /= 4294967296.0;
    uint64_t m = (uint64_t)(4294901760.0 / diff);
    memset(t, 0, 32);
    if (m == 0 && k == 6) memset(t, 0xff, 32);
    else { t[k] = (uint32_t)m; t[k + 1] = (uint32_t)(m >> 32); }
}
static void nbits_to_target(uint32_t t[8], uint32_t nbits) {
    uint8_t b[32] = {0};
    int exp = nbits >> 24;
    uint32_t mant = nbits & 0x007fffff;
    for (int i = 0; i < 3; i++) {
        int pos = exp - 3 + i;
        if (pos >= 0 && pos < 32) b[pos] = (uint8_t)(mant >> (8 * i));
    }
    for (int i = 0; i < 8; i++) t[i] = rd_le32(b + 4 * i);
}
static double hash_difficulty(const uint8_t hash[32]) {
    double h = 0;
    for (int i = 31; i >= 0; i--) h = h * 256.0 + hash[i];
    return h > 0 ? 26959535291011309493156476344723991336010898738574164086137773096960.0 / h : 1e300;
}

/* ------------------------------------------------------------------ state */

typedef struct {
    char job_id[128];
    char ntime_hex[16];
    uint8_t prevhash[32];       /* header byte order */
    uint8_t cb[MAX_CB];         /* coinb1 | extranonce1 | extranonce2 | coinb2 */
    size_t cb_len, en2_off, en2_len;
    uint8_t merkle[MAX_MERKLE][32];
    int n_merkle;
    uint32_t version, nbits, ntime;
    uint32_t share_target[8];
    double diff;
} job_t;

static struct {
    const char *host, *port, *user, *pass;
    int threads;
    const char *algo;
    double suggest_diff;
    int bench_secs;
    int no_affinity;
} opt = {.pass = "x", .algo = "auto", .bench_secs = 20};

static pthread_mutex_t job_mtx = PTHREAD_MUTEX_INITIALIZER;
static job_t g_job;
static atomic_ullong g_job_gen;
static atomic_int g_have_job;
static atomic_ullong g_en2_next;
static atomic_int g_quit;
static int g_bench;

typedef struct { _Alignas(64) atomic_ullong hashes; } counter_t;
static counter_t g_hashes[MAX_THREADS];
static scan_fn g_scan[MAX_THREADS];
static atomic_ullong g_accepted, g_rejected, g_submitted, g_hw_err, g_blocks;
static double g_best_diff;

static int g_sock = -1;
static pthread_mutex_t send_mtx = PTHREAD_MUTEX_INITIALIZER;
static atomic_int g_next_id = 100;

static int send_line(const char *s) {
    pthread_mutex_lock(&send_mtx);
    int ok = g_sock >= 0;
    size_t n = strlen(s), off = 0;
    while (ok && off < n) {
        ssize_t w = send(g_sock, s + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) { if (errno == EINTR) continue; ok = 0; break; }
        off += (size_t)w;
    }
    pthread_mutex_unlock(&send_mtx);
    return ok;
}

/* ------------------------------------------------------------------ worker */

static void build_header(const job_t *j, uint8_t *cb, uint64_t en2, uint8_t hdr[80], char *en2_hex) {
    uint8_t en2b[16] = {0};
    for (size_t i = 0; i < j->en2_len && i < 8; i++) en2b[i] = (uint8_t)(en2 >> (8 * i));
    memcpy(cb + j->en2_off, en2b, j->en2_len);
    bin2hex(en2_hex, en2b, j->en2_len);

    uint8_t root[32], buf[64];
    sha256d(cb, j->cb_len, root);
    for (int i = 0; i < j->n_merkle; i++) {
        memcpy(buf, root, 32);
        memcpy(buf + 32, j->merkle[i], 32);
        sha256d(buf, 64, root);
    }
    wr_le32(hdr, j->version);
    memcpy(hdr + 4, j->prevhash, 32);
    memcpy(hdr + 36, root, 32);
    wr_le32(hdr + 68, j->ntime);
    wr_le32(hdr + 72, j->nbits);
    wr_le32(hdr + 76, 0);
}

static void submit(const job_t *j, const char *en2_hex, uint32_t nonce) {
    char line[1024];
    int id = atomic_fetch_add(&g_next_id, 1);
    snprintf(line, sizeof line,
             "{\"id\":%d,\"method\":\"mining.submit\",\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%08x\"]}\n",
             id, opt.user, j->job_id, en2_hex, j->ntime_hex, nonce);
    atomic_fetch_add(&g_submitted, 1);
    if (!send_line(line)) logf_("submit failed: not connected");
}

static void *worker(void *arg) {
    int tid = (int)(intptr_t)arg;
    if (!opt.no_affinity) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(tid % CPU_SETSIZE, &set);
        pthread_setaffinity_np(pthread_self(), sizeof set, &set);
    }
    job_t *job = malloc(sizeof *job);
    uint8_t *cb = malloc(MAX_CB);
    if (!job || !cb) { logf_("worker %d: out of memory", tid); return NULL; }
    unsigned long long my_gen = ~0ULL;
    uint32_t block_target[8] = {0};
    scan_fn scan = g_scan[tid];

    while (!atomic_load(&g_quit)) {
        if (!atomic_load(&g_have_job)) { usleep(50000); continue; }
        if (atomic_load(&g_job_gen) != my_gen) {
            pthread_mutex_lock(&job_mtx);
            memcpy(job, &g_job, sizeof *job);
            my_gen = atomic_load(&g_job_gen);
            pthread_mutex_unlock(&job_mtx);
            memcpy(cb, job->cb, job->cb_len);
            nbits_to_target(block_target, job->nbits);
        }
        uint8_t hdr[80];
        char en2_hex[40];
        build_header(job, cb, atomic_fetch_add(&g_en2_next, 1), hdr, en2_hex);

        scan_job_t sj;
        memcpy(sj.mid, SHA256_IV, 32);
        sha256_transform(sj.mid, hdr);
        sj.w0 = rd_be32(hdr + 64);
        sj.w1 = rd_be32(hdr + 68);
        sj.w2 = rd_be32(hdr + 72);
        sj.h7_want = 0;

        for (uint64_t base = 0; base < (1ULL << 32); base += CHUNK) {
            uint32_t cand[16];
            int nc = scan(&sj, (uint32_t)base, CHUNK, cand, 16);
            atomic_fetch_add_explicit(&g_hashes[tid].hashes, CHUNK, memory_order_relaxed);
            for (int c = 0; c < nc; c++) {
                uint8_t hash[32];
                wr_le32(hdr + 76, cand[c]);
                sha256d(hdr, 80, hash);
                if (rd_le32(hash + 28) != 0) { atomic_fetch_add(&g_hw_err, 1); continue; }
                double d = hash_difficulty(hash);
                pthread_mutex_lock(&log_mtx);
                if (d > g_best_diff) g_best_diff = d;
                pthread_mutex_unlock(&log_mtx);
                if (g_bench) continue;
                if (hash_le_target(hash, block_target)) {
                    atomic_fetch_add(&g_blocks, 1);
                    logf_("*** BLOCK CANDIDATE *** job %s nonce %08x diff %.0f", job->job_id, cand[c], d);
                }
                if (hash_le_target(hash, job->share_target)) {
                    logf_("share found: job %s nonce %08x diff %.1f (pool %.1f)", job->job_id, cand[c], d, job->diff);
                    submit(job, en2_hex, cand[c]);
                }
            }
            if (atomic_load_explicit(&g_job_gen, memory_order_relaxed) != my_gen || atomic_load(&g_quit)) break;
        }
    }
    free(job);
    free(cb);
    return NULL;
}

/* ------------------------------------------------------------------ algorithms */

static int ncpu(void) { long n = sysconf(_SC_NPROCESSORS_ONLN); return n > 0 ? (int)n : 1; }

static int assign_algo(const char *a, int threads) {
    int sha = cpu_has_shani(), avx = cpu_has_avx512();
    for (int t = 0; t < threads; t++) {
        if (!strcmp(a, "shani")) { if (!sha) return 0; g_scan[t] = scan_shani; }
        else if (!strcmp(a, "avx512")) { if (!avx) return 0; g_scan[t] = scan_avx512; }
        else if (!strcmp(a, "mixed")) { if (!sha || !avx) return 0; g_scan[t] = t < threads / 2 ? scan_shani : scan_avx512; }
        else if (!strcmp(a, "scalar")) g_scan[t] = scan_scalar;
        else return 0;
    }
    return 1;
}

static void install_fake_job(void) {
    job_t *j = &g_job;
    memset(j, 0, sizeof *j);
    strcpy(j->job_id, "bench");
    strcpy(j->ntime_hex, "00000000");
    for (int i = 0; i < 32; i++) j->prevhash[i] = (uint8_t)(i * 7);
    j->cb_len = 200; j->en2_off = 100; j->en2_len = 8;
    for (size_t i = 0; i < j->cb_len; i++) j->cb[i] = (uint8_t)i;
    j->n_merkle = 12;
    for (int k = 0; k < 12; k++) for (int i = 0; i < 32; i++) j->merkle[k][i] = (uint8_t)(k + i);
    j->version = 0x20000000; j->nbits = 0x17030000; j->ntime = (uint32_t)time(NULL);
    j->diff = 1;
    diff_to_target(j->share_target, 1);
}

/* Run all threads on the fake job for secs seconds; returns H/s. */
static double run_bench(int threads, double secs, int verbose) {
    pthread_t th[MAX_THREADS];
    g_bench = 1;
    atomic_store(&g_quit, 0);
    for (int t = 0; t < threads; t++) atomic_store(&g_hashes[t].hashes, 0);
    install_fake_job();
    atomic_fetch_add(&g_job_gen, 1);
    atomic_store(&g_have_job, 1);
    for (int t = 0; t < threads; t++) pthread_create(&th[t], NULL, worker, (void *)(intptr_t)t);
    usleep(300000); /* let clocks ramp and caches warm */
    unsigned long long h0 = 0;
    for (int t = 0; t < threads; t++) h0 += atomic_load(&g_hashes[t].hashes);
    double t0 = now_s(), last = t0;
    unsigned long long hl = h0;
    while (now_s() - t0 < secs) {
        usleep(100000);
        if (verbose && now_s() - last >= 5) {
            unsigned long long h = 0;
            for (int t = 0; t < threads; t++) h += atomic_load(&g_hashes[t].hashes);
            logf_("%.2f MH/s", (h - hl) / (now_s() - last) / 1e6);
            hl = h; last = now_s();
        }
    }
    unsigned long long h1 = 0;
    for (int t = 0; t < threads; t++) h1 += atomic_load(&g_hashes[t].hashes);
    double rate = (h1 - h0) / (now_s() - t0);
    atomic_store(&g_quit, 1);
    for (int t = 0; t < threads; t++) pthread_join(th[t], NULL);
    atomic_store(&g_have_job, 0);
    g_bench = 0;
    return rate;
}

static const char *pick_algo(int threads) {
    static const char *cands[] = {"shani", "avx512", "mixed"};
    const char *best = NULL;
    double best_rate = 0;
    logf_("auto: benchmarking scanners on %d threads (2 s each)...", threads);
    for (size_t i = 0; i < sizeof cands / sizeof *cands; i++) {
        if (!assign_algo(cands[i], threads)) continue;
        double r = run_bench(threads, 2.0, 0);
        logf_("auto:   %-7s %8.2f MH/s", cands[i], r / 1e6);
        if (r > best_rate) { best_rate = r; best = cands[i]; }
    }
    if (!best) best = "scalar";
    logf_("auto: using %s", best);
    return best;
}

/* ------------------------------------------------------------------ self-test */

static int selftest(void) {
    int fail = 0;
    uint8_t h[32];
    char hex[65];
    sha256("abc", 3, h);
    bin2hex(hex, h, 32);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) { printf("FAIL sha256(abc)\n"); fail++; }

    /* Bitcoin genesis block header */
    uint8_t gen[80];
    hex2bin(gen, 80,
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67"
            "768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
    sha256d(gen, 80, h);
    uint8_t rev[32];
    for (int i = 0; i < 32; i++) rev[i] = h[31 - i];
    bin2hex(hex, rev, 32);
    if (strcmp(hex, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")) { printf("FAIL genesis hash\n"); fail++; }
    else printf("ok   reference sha256 / genesis hash\n");

    struct { const char *name; scan_fn fn; int avail; } sc[] = {
        {"scalar", scan_scalar, 1},
        {"shani", scan_shani, cpu_has_shani()},
        {"avx512", scan_avx512, cpu_has_avx512()},
    };
    scan_job_t gj;
    memcpy(gj.mid, SHA256_IV, 32);
    sha256_transform(gj.mid, gen);
    gj.w0 = rd_be32(gen + 64); gj.w1 = rd_be32(gen + 68); gj.w2 = rd_be32(gen + 72); gj.h7_want = 0;
    const uint32_t gnonce = 2083236893u;

    for (size_t s = 0; s < sizeof sc / sizeof *sc; s++) {
        if (!sc[s].avail) { printf("skip %s (CPU lacks it)\n", sc[s].name); continue; }
        int f0 = fail;
        /* 1. must rediscover the genesis nonce, and nothing else, in a window around it */
        uint32_t out[64];
        int n = sc[s].fn(&gj, (gnonce & ~15u) - 2048, 8192, out, 64);
        if (n != 1 || out[0] != gnonce) { printf("FAIL %s: genesis scan found %d nonces\n", sc[s].name, n); fail++; }
        /* 2. every lane position: pick a nonce, ask for its exact digest word 7, expect it back */
        uint8_t hdr[80];
        for (int i = 0; i < 80; i++) hdr[i] = (uint8_t)(i * 31 + 7 + s);
        scan_job_t tj;
        memcpy(tj.mid, SHA256_IV, 32);
        sha256_transform(tj.mid, hdr);
        tj.w0 = rd_be32(hdr + 64); tj.w1 = rd_be32(hdr + 68); tj.w2 = rd_be32(hdr + 72);
        uint32_t first = 0xfffff000u; /* window wraps through 2^32 */
        for (int lane = 0; lane < 32 && fail == f0; lane++) {
            uint32_t nonce = first + (uint32_t)(lane * 97 % 4096);
            wr_le32(hdr + 76, nonce);
            sha256d(hdr, 80, h);
            tj.h7_want = rd_be32(h + 28);
            n = sc[s].fn(&tj, first, 4096, out, 64);
            int hit = 0;
            for (int k = 0; k < n; k++) hit |= out[k] == nonce;
            if (!hit) { printf("FAIL %s: lane test nonce %08x not reported\n", sc[s].name, nonce); fail++; }
        }
        if (fail == f0) printf("ok   %s scanner\n", sc[s].name);
    }

    /* difficulty/target plumbing */
    uint32_t t[8];
    diff_to_target(t, 1.0);
    if (t[7] != 0 || t[6] != 0xffff0000u) { printf("FAIL diff_to_target\n"); fail++; }
    nbits_to_target(t, 0x1d00ffff);
    if (t[7] != 0 || t[6] != 0xffff0000u) { printf("FAIL nbits_to_target\n"); fail++; }
    if (!hash_le_target(h, (uint32_t[8]){~0u, ~0u, ~0u, ~0u, ~0u, ~0u, ~0u, ~0u})) { printf("FAIL compare\n"); fail++; }
    sha256d(gen, 80, h);
    nbits_to_target(t, 0x1d00ffff);
    if (!hash_le_target(h, t)) { printf("FAIL genesis vs its own target\n"); fail++; }

    printf(fail ? "\n%d FAILURE(S)\n" : "\nall tests passed\n", fail);
    return fail ? 1 : 0;
}

/* ------------------------------------------------------------------ stratum */

static uint8_t g_en1[64];
static size_t g_en1_len, g_en2_len = 4;
static double g_diff = 1.0;

static void handle_notify(jval *p) {
    const char *jid = json_str(json_at(p, 0)), *prev = json_str(json_at(p, 1));
    const char *cb1 = json_str(json_at(p, 2)), *cb2 = json_str(json_at(p, 3));
    jval *mb = json_at(p, 4);
    const char *ver = json_str(json_at(p, 5)), *bits = json_str(json_at(p, 6)), *ntime = json_str(json_at(p, 7));
    jval *clean = json_at(p, 8);
    if (!jid || !prev || !cb1 || !cb2 || !mb || mb->t != J_ARR || !ver || !bits || !ntime) {
        logf_("malformed mining.notify ignored");
        return;
    }
    job_t *j = malloc(sizeof *j);
    if (!j) return;
    memset(j, 0, sizeof *j);
    uint8_t pv[32];
    long a, b;
    int ok = strlen(jid) < sizeof j->job_id && strlen(ntime) == 8 && hex2bin(pv, 32, prev) == 32 &&
             mb->n <= MAX_MERKLE && g_en1_len + g_en2_len <= 64;
    if (ok) {
        a = hex2bin(j->cb, MAX_CB, cb1);
        ok = a >= 0 && (size_t)a + g_en1_len + g_en2_len < MAX_CB;
    }
    if (ok) {
        memcpy(j->cb + a, g_en1, g_en1_len);
        j->en2_off = (size_t)a + g_en1_len;
        j->en2_len = g_en2_len;
        b = hex2bin(j->cb + j->en2_off + j->en2_len, MAX_CB - j->en2_off - j->en2_len, cb2);
        ok = b >= 0;
        j->cb_len = j->en2_off + j->en2_len + (size_t)b;
    }
    for (int i = 0; ok && i < mb->n; i++) {
        const char *m = json_str(mb->items[i]);
        ok = m && hex2bin(j->merkle[i], 32, m) == 32;
    }
    if (!ok) { logf_("malformed mining.notify ignored"); free(j); return; }
    j->n_merkle = mb->n;
    strcpy(j->job_id, jid);
    strcpy(j->ntime_hex, ntime);
    for (int i = 0; i < 8; i++)
        for (int k = 0; k < 4; k++) j->prevhash[4 * i + k] = pv[4 * i + 3 - k];
    j->version = (uint32_t)strtoul(ver, NULL, 16);
    j->nbits = (uint32_t)strtoul(bits, NULL, 16);
    j->ntime = (uint32_t)strtoul(ntime, NULL, 16);
    j->diff = g_diff;
    diff_to_target(j->share_target, g_diff);

    pthread_mutex_lock(&job_mtx);
    memcpy(&g_job, j, sizeof *j);
    atomic_fetch_add(&g_job_gen, 1);
    pthread_mutex_unlock(&job_mtx);
    atomic_store(&g_have_job, 1);
    logf_("new job %s%s (diff %g, nbits %08x)", jid, clean && clean->b ? " [clean]" : "", g_diff, j->nbits);
    free(j);
}

static void handle_line(const char *line) {
    jval *m = json_parse(line);
    if (!m || m->t != J_OBJ) { json_free(m); return; }
    const char *method = json_str(json_get(m, "method"));
    jval *params = json_get(m, "params");
    if (method) {
        if (!strcmp(method, "mining.notify")) handle_notify(params);
        else if (!strcmp(method, "mining.set_difficulty")) {
            jval *d = json_at(params, 0);
            if (d && d->t == J_NUM && d->num > 0) {
                g_diff = d->num;
                logf_("pool difficulty set to %g", g_diff);
                pthread_mutex_lock(&job_mtx);
                g_job.diff = g_diff;
                diff_to_target(g_job.share_target, g_diff);
                atomic_fetch_add(&g_job_gen, 1);
                pthread_mutex_unlock(&job_mtx);
            }
        } else if (!strcmp(method, "client.show_message")) {
            const char *s = json_str(json_at(params, 0));
            logf_("pool message: %s", s ? s : "");
        } else if (!strcmp(method, "mining.set_extranonce")) {
            const char *e1 = json_str(json_at(params, 0));
            jval *n2 = json_at(params, 1);
            long l = e1 ? hex2bin(g_en1, sizeof g_en1, e1) : -1;
            if (l >= 0 && n2 && n2->t == J_NUM) { g_en1_len = (size_t)l; g_en2_len = (size_t)n2->num; }
        }
    } else {
        jval *id = json_get(m, "id"), *res = json_get(m, "result"), *err = json_get(m, "error");
        int iid = id && id->t == J_NUM ? (int)id->num : -1;
        if (iid == 1) {
            const char *e1 = json_str(json_at(res, 1));
            jval *n2 = json_at(res, 2);
            long l = e1 ? hex2bin(g_en1, sizeof g_en1, e1) : -1;
            if (l < 0 || !n2 || n2->t != J_NUM || n2->num < 1 || n2->num > 16) logf_("bad subscribe response");
            else { g_en1_len = (size_t)l; g_en2_len = (size_t)n2->num; logf_("subscribed: extranonce1=%s extranonce2_size=%zu", e1, g_en2_len); }
        } else if (iid == 2) {
            logf_(res && res->t == J_BOOL && res->b ? "worker %s authorized" : "worker %s NOT authorized", opt.user);
        } else if (iid >= 100) {
            if (res && res->t == J_BOOL && res->b) { atomic_fetch_add(&g_accepted, 1); logf_("share accepted"); }
            else {
                atomic_fetch_add(&g_rejected, 1);
                const char *why = json_str(json_at(err, 1));
                logf_("share rejected%s%s", why ? ": " : "", why ? why : "");
            }
        }
    }
    json_free(m);
}

static int stratum_connect(void) {
    struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM}, *res, *r;
    int e = getaddrinfo(opt.host, opt.port, &hints, &res);
    if (e) { logf_("resolve %s: %s", opt.host, gai_strerror(e)); return -1; }
    int fd = -1;
    for (r = res; r; r = r->ai_next) {
        fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, r->ai_addr, r->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { logf_("connect %s:%s failed", opt.host, opt.port); return -1; }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
    return fd;
}

static void report(int threads, double *last_t, unsigned long long *last_h) {
    unsigned long long h = 0;
    for (int t = 0; t < threads; t++) h += atomic_load(&g_hashes[t].hashes);
    double t = now_s();
    logf_("%.2f MH/s | accepted %llu rejected %llu | best share diff %.1f%s", (h - *last_h) / (t - *last_t) / 1e6,
          (unsigned long long)atomic_load(&g_accepted), (unsigned long long)atomic_load(&g_rejected), g_best_diff,
          atomic_load(&g_hw_err) ? " | HW ERRORS!" : "");
    *last_t = t;
    *last_h = h;
}

static void on_signal(int s) { (void)s; atomic_store(&g_quit, 1); }

static int mine(int threads) {
    pthread_t th[MAX_THREADS];
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    for (int t = 0; t < threads; t++) pthread_create(&th[t], NULL, worker, (void *)(intptr_t)t);
    double last_t = now_s();
    unsigned long long last_h = 0;
    static char buf[1 << 16];

    while (!atomic_load(&g_quit)) {
        int fd = stratum_connect();
        if (fd < 0) { sleep(5); continue; }
        pthread_mutex_lock(&send_mtx);
        g_sock = fd;
        pthread_mutex_unlock(&send_mtx);
        logf_("connected to %s:%s", opt.host, opt.port);
        char line[1024];
        send_line("{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"zenminer/1.0\"]}\n");
        snprintf(line, sizeof line, "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}\n", opt.user, opt.pass);
        send_line(line);
        if (opt.suggest_diff > 0) {
            snprintf(line, sizeof line, "{\"id\":3,\"method\":\"mining.suggest_difficulty\",\"params\":[%g]}\n", opt.suggest_diff);
            send_line(line);
        }
        size_t len = 0;
        double last_rx = now_s();
        while (!atomic_load(&g_quit)) {
            struct pollfd pf = {.fd = fd, .events = POLLIN};
            int pr = poll(&pf, 1, 1000);
            if (now_s() - last_t >= 15) report(threads, &last_t, &last_h);
            if (pr < 0 && errno == EINTR) continue;
            if (pr == 0) {
                if (now_s() - last_rx > 300) { logf_("no data from pool for 5 min, reconnecting"); break; }
                continue;
            }
            ssize_t r = recv(fd, buf + len, sizeof buf - 1 - len, 0);
            if (r <= 0) { logf_("connection closed"); break; }
            last_rx = now_s();
            len += (size_t)r;
            buf[len] = 0;
            char *start = buf, *nl;
            while ((nl = strchr(start, '\n'))) {
                *nl = 0;
                if (nl > start) handle_line(start);
                start = nl + 1;
            }
            len -= (size_t)(start - buf);
            memmove(buf, start, len);
            if (len == sizeof buf - 1) { logf_("oversized line from pool, reconnecting"); break; }
        }
        atomic_store(&g_have_job, 0); /* stop hashing stale work while disconnected */
        pthread_mutex_lock(&send_mtx);
        g_sock = -1;
        pthread_mutex_unlock(&send_mtx);
        close(fd);
        if (!atomic_load(&g_quit)) sleep(5);
    }
    for (int t = 0; t < threads; t++) pthread_join(th[t], NULL);
    return 0;
}

/* ------------------------------------------------------------------ main */

static void usage(void) {
    puts("zenminer - SHA-256d Bitcoin CPU miner tuned for AMD Zen 4 (Ryzen 7900X)\n\n"
         "  zenminer --test\n"
         "  zenminer --bench [-t N] [-a ALGO] [--secs S]\n"
         "  zenminer -o stratum+tcp://HOST:PORT -u USER [-p PASS] [-t N] [-a ALGO] [--suggest-diff D]\n\n"
         "  -t N            threads (default: all logical CPUs)\n"
         "  -a ALGO         auto | shani | avx512 | mixed | scalar   (default auto)\n"
         "  --no-affinity   do not pin thread i to logical CPU i");
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    int test = 0, bench = 0;
    const char *url = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
#define NEXT (i + 1 < argc ? argv[++i] : (usage(), exit(2), ""))
        if (!strcmp(a, "--test")) test = 1;
        else if (!strcmp(a, "--bench")) bench = 1;
        else if (!strcmp(a, "-o")) url = NEXT;
        else if (!strcmp(a, "-u")) opt.user = NEXT;
        else if (!strcmp(a, "-p")) opt.pass = NEXT;
        else if (!strcmp(a, "-t")) opt.threads = atoi(NEXT);
        else if (!strcmp(a, "-a")) opt.algo = NEXT;
        else if (!strcmp(a, "--secs")) opt.bench_secs = atoi(NEXT);
        else if (!strcmp(a, "--suggest-diff")) opt.suggest_diff = atof(NEXT);
        else if (!strcmp(a, "--no-affinity")) opt.no_affinity = 1;
        else { usage(); return 2; }
    }
    if (test) return selftest();

    int threads = opt.threads > 0 ? opt.threads : ncpu();
    if (threads > MAX_THREADS) threads = MAX_THREADS;
    printf("CPU: SHA-NI %s, AVX-512 %s, %d threads\n", cpu_has_shani() ? "yes" : "no", cpu_has_avx512() ? "yes" : "no", threads);

    const char *algo = opt.algo;
    if (!strcmp(algo, "auto")) algo = pick_algo(threads);
    if (!assign_algo(algo, threads)) { fprintf(stderr, "algorithm '%s' unknown or not supported by this CPU\n", algo); return 2; }

    if (bench) {
        logf_("benchmark: %s, %d threads, %d s", algo, threads, opt.bench_secs);
        double r = run_bench(threads, opt.bench_secs, 1);
        logf_("result: %.2f MH/s total, %.2f MH/s per thread", r / 1e6, r / 1e6 / threads);
        return 0;
    }

    if (!url || !opt.user) { usage(); return 2; }
    const char *hp = strstr(url, "://") ? strstr(url, "://") + 3 : url;
    char *host = strdup(hp), *colon = strrchr(host, ':');
    if (!colon) { fprintf(stderr, "URL needs a port\n"); return 2; }
    *colon = 0;
    opt.host = host;
    opt.port = colon + 1;
    if (strchr(opt.user, '"') || strchr(opt.pass, '"')) { fprintf(stderr, "user/pass may not contain quotes\n"); return 2; }
    return mine(threads);
}
