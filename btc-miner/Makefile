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

clean:
	rm -f zenminer

.PHONY: test bench clean
