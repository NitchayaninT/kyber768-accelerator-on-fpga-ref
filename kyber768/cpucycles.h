#ifndef CPUCYCLES_H
#define CPUCYCLES_H

#include <stdint.h>

static inline uint64_t cpucycles(void) {
    uint32_t lo, hi;
    __asm__ volatile ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t cpucycles_overhead(void) {
    uint64_t t0, t1, overhead = -1;
    for (int i = 0; i < 100; i++) {
        t0 = cpucycles();
        __asm__ volatile ("");
        t1 = cpucycles();
        if (t1 - t0 < overhead)
            overhead = t1 - t0;
    }
    return overhead;
}

#endif
