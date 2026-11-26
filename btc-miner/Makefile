# Default build targets the Ryzen 9 7900X (Zen 4). Override with: make MARCH=native
CC     ?= gcc
MARCH  ?= znver4
CFLAGS ?= -O3 -march=$(MARCH) -mtune=$(MARCH) -fno-plt -Wall -Wextra -Wno-unused-parameter
LDLIBS  = -lpthread

SRC = src/miner.c src/json.c src/sha256.c src/cpu.c src/scan_scalar.c src/scan_shani.c src/scan_avx512.c

zenminer: $(SRC) src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDLIBS)

test: zenminer
	./zenminer --test

bench: zenminer
	./zenminer --bench

# Windows x64 build (MinGW-w64, posix threads). One static .exe, no DLLs needed.
# Baseline x86-64-v2 so it starts on any modern x86-64 CPU; the SHA-NI and AVX-512
# kernels are compiled with function-level target attributes and selected at runtime.
# -muse-unaligned-vector-move works around GCC's lack of 64-byte stack alignment on
# Win64 (GCC bug 54412), which otherwise crashes AVX-512 code on stack spills.
WINCC    ?= x86_64-w64-mingw32-gcc-posix
WINFLAGS ?= -O3 -march=x86-64-v2 -mtune=znver4 -fno-plt -Wall -Wextra -Wno-unused-parameter \
            -D__USE_MINGW_ANSI_STDIO=1 -Wa,-muse-unaligned-vector-move
zenminer.exe: $(SRC) src/*.h
	$(WINCC) $(WINFLAGS) -static -o $@ $(SRC) -lws2_32 -lpthread
	x86_64-w64-mingw32-strip $@

windows: zenminer.exe

clean:
	rm -f zenminer zenminer.exe

.PHONY: test bench clean windows
