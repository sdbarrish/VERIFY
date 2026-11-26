# zenminer: Bitcoin SHA-256d CPU miner for AMD Zen 4 (Ryzen 9 7900X)

A small, dependency-free C miner for Bitcoin proof of work (double SHA-256 over the
80-byte block header). It speaks Stratum v1, so it works with any pool or solo pool.
It has two hand-optimized hash kernels for the two SHA-256 engines a 7900X has.

> **Read [Economics](#economics-read-this-first) before running it for money.** A CPU
> cannot mine Bitcoin profitably. This project is for learning, testing and
> lottery-style solo mining only.

## Build and run

```bash
make                      # gcc, -march=znver4 (Ryzen 7000/9000). Use `make MARCH=native` elsewhere
./zenminer --test         # self-test every kernel against reference SHA-256 (incl. genesis block)
./zenminer --bench        # auto-picks the fastest kernel, then benchmarks 20 s

# pool or solo pool (your BTC address is the username on solo pools)
./zenminer -o stratum+tcp://solo.ckpool.org:3333 -u bc1qYOURADDRESS.7900x -p x
./zenminer -o stratum+tcp://public-pool.io:21496 -u bc1qYOURADDRESS.7900x --suggest-diff 1
```

Options: `-t N` threads (default: all 24), `-a auto|shani|avx512|mixed|scalar`,
`--no-affinity`, `--secs S` (bench length). Linux only (pthreads, BSD sockets).
On Windows, build and run it under **WSL2**. The hashing is pure CPU, so it runs at
native speed there.

## How it is optimized for Zen 4

The 7900X (12 cores / 24 threads) has two different hardware paths for SHA-256, and
it is not obvious in advance which one is faster. zenminer implements both and
**measures** at startup (`-a auto`):

| Kernel | What it does |
|---|---|
| `shani` | SHA-NI (`sha256rnds2`/`msg1`/`msg2`). **4 nonces interleaved** per thread, because rnds2 has multi-cycle latency and one hash chain would leave the unit idle. |
| `avx512` | 16 nonces per zmm register. `vprold` native rotates, `vpternlogd` for Ch, Maj and every 3-way XOR in Σ/σ, and all 8 state words plus a 16-word message window kept in the 32 zmm registers. Zen 4 runs 512-bit ops as 2×256, so the gain comes from fewer instructions. |
| `mixed` | SHA-NI on threads 0-11 and AVX-512 on threads 12-23, each pinned to its logical CPU. Linux numbers Zen SMT siblings *i* and *i*+12, so every physical core runs one of each and keeps both engines busy. |

Bitcoin-specific work reduction (both kernels):

- **Midstate**: header bytes 0-63 are hashed once per work unit, not per nonce.
- **Hoisted early rounds**: rounds that see only the merkle tail, ntime and nbits are computed once (3 rounds for AVX-512, 2 for SHA-NI).
- **Constant folding**: padding words (hash 1: W4-W15, hash 2: W8-W15) are compile-time constants, so their schedule terms become immediates. Round 0 of hash 2 starts from the fixed IV and collapses to two adds.
- **Early exit**: a share needs digest word 7 = 0, and word 7 = IV₇ + e(state 61). Hash 2 therefore stops after round 60 (AVX-512) or round 61 (SHA-NI, where the value is already in the F slot of the ABEF register), and skips the remaining rounds, their message words and the feed-forward.
- Candidates are re-hashed with the portable reference code before submission, and any disagreement is reported as a HW error.

Each thread takes a unique extranonce2, so threads never overlap, and every thread
gets a full 2³² nonce range. Threads check for new jobs every 65,536 nonces (a few ms).

### Tuning on your 7900X

```bash
./zenminer --bench -a shani;  ./zenminer --bench -a avx512;  ./zenminer --bench -a mixed
./zenminer --bench -a <best> -t 12      # SMT on vs off
```
Check the CPU-to-core mapping with `lscpu -e`. If siblings are not *i*/*i*+12, `mixed`
loses its pairing benefit. In BIOS, PBO with a negative Curve Optimizer usually
raises sustained all-core clocks, and the hashrate scales with clock speed. Watch
temperatures: this is a 100% all-core load.

## Verification

- `--test`: checks SHA-256("abc") and the genesis block hash. Every kernel must rediscover the genesis nonce
  (2083236893) and nothing else in an 8,192-nonce window. A lane test then asks for a chosen
  nonce's exact digest word at 32 different lane positions (including a window that wraps at 2³²).
- `tests/mock_pool.py`: a Stratum pool that rebuilds each submitted header independently
  (Python `hashlib`) and checks the share. Run:
  `python3 tests/mock_pool.py --shares 3 & ./zenminer -o stratum+tcp://127.0.0.1:3334 -u test`

Not implemented: version rolling (BIP 310 / ASICBoost), `getblocktemplate` solo mining
directly against bitcoind, TLS stratum, and share difficulty below 1 (the kernels only
report hashes with 32 leading zero bits).

## Economics (read this first)

Network figures as of late November 2026: difficulty about **134.8 T**, hashrate about **1,030 EH/s**.

| | |
|---|---|
| Hashes needed per block (D × 2³²) | ≈ 5.8 × 10²³ |
| Ryzen 7900X, estimated | ~0.15-0.3 GH/s (measure with `--bench`) |
| A current ASIC (e.g. 200+ TH/s) | ~1,000,000× a 7900X |
| Expected time for a 7900X to solo-find a block at 0.2 GH/s | **~90 million years** |
| Pool earnings at 0.2 GH/s (≈ 450 BTC/day network subsidy) | ≈ 9 × 10⁻¹¹ BTC/day, i.e. **under 1 satoshi per month**, below every pool's payout threshold |
| Power at ~150-230 W package | ~4-5 kWh/day |

Solo mining is a lottery ticket with odds of roughly 1 in 3×10¹⁰ per day. It is legitimate,
and CPUs have occasionally won on small chains, but you should expect to pay
for electricity and receive nothing.
