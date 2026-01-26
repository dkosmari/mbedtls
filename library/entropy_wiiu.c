/*
 *  Entropy source for the Wii U
 *
 *  Copyright 2025  Daniel K. O. <github.com/dkosmari>
 *
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifdef __WIIU__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <coreinit/time.h>

#include "entropy_poll.h"

/* http://eel.is/c++draft/rand.util.seedseq#9 */
static inline
uint32_t T(uint32_t x)
{
    return x ^ (x >> 27);
}

int mbedtls_hardware_poll(void *data,
                          unsigned char *output,
                          size_t len,
                          size_t *olen)
{
    /*
     * This is an implementation of std::seed_seq.
     * See http://eel.is/c++draft/rand.util.seedseq
     * It can both:
     * - spread a small number of random numbers over a larger array
     * - condense a large number of random numbers to a smaller array.
     */
    /* We only use the two halfs of OSGetTime() as entropy bits, so s=2, v[2]. */
    /* If Aroma ever implements a RandomPoolModule, we can use that instead. */
    const uint64_t now = OSGetTime();
    static const size_t s = 2;
    const uint32_t v[2] = { (uint32_t) (now >> 0), (uint32_t) (now >> 32) };

    size_t n = len / 4;
    const size_t t = (n >= 623) ? 11
                   : (n >=  68) ? 7
                   : (n >=  39) ? 5
                   : (n >=   7) ? 3
                   : (n - 1) / 2;
    const size_t p = (n - t) / 2;
    const size_t q = p + t;
    const size_t m = s + 1 > n ? s + 1 : n; /* m = max(s+1, n) */
    uint32_t r1, r2, r3, r4;
    uint32_t dummy_output;
    uint32_t *begin = (uint32_t *) output;
    size_t k;

    (void)data;

    if (len == 0)
        return 0;

    if (len < 4) {
        begin = &dummy_output;
        n = 1;
    }

    /*
     * 9.1: initialization to 0x8b8b8b8b
     * http://eel.is/c++draft/rand.util.seedseq#9.1
     */
    for (k = 0; k < n; ++k)
        begin[k] = 0x8b8b8b8b;

    /*
     * 9.2: calculate r1, r2
     * http://eel.is/c++draft/rand.util.seedseq#9.2
     */
#define CALC_R1 r1 = 1664525u * T(begin[k] ^ begin[(k + p) % n] ^ begin[(k + n - 1) % n])
#define UPDATE_BEGIN do {                       \
        begin[(k + p) % n] += r1;               \
        begin[(k + q) % n] += r2;               \
        begin[k] = r2;                          \
    }                                           \
    while (0)

    /* first range: k = 0 */
    {
        CALC_R1;
        r2 = r1 + s;
        UPDATE_BEGIN;
    }
    /* second range: 0 < k <= s */
    for (k = 1; k <= s; ++k) {
        CALC_R1;
        r2 = r1 + k % n + v[k - 1];
        UPDATE_BEGIN;
    }
    /* third range: s < k < m */
    for (k = s + 1; k < m; ++k) {
        CALC_R1;
        r2 = r1 + k % n;
        UPDATE_BEGIN;
    }
#undef CALC_R1
#undef UPDATE_BEGIN

    /*
     * 9.3: calculate r3, r4
     * http://eel.is/c++draft/rand.util.seedseq#9.3
     */
    for (k = m; k < m + n; ++k) {
        r3 = 1566083941u * T(begin[k % n] + begin[(k + p) % n] + begin[(k - 1) % n]);
        r4 = r3 - (k % n);
        begin[(k + p) % n] ^= r3;
        begin[(k + q) % n] ^= r4;
        begin[k % n] = r4;
    }

    if (len < 4) {
        /* begin points to dummy_output, so copy some of its bytes to output */
        memcpy(output, &dummy_output, len);
        if (olen)
            *olen = len;
        return 0;
    }
    if (len % 4 > 0) {
        // len was not a multiple of 4, just pad it
        memset(output + n, 0x2a, len % 4);
    }
    if (olen)
        *olen = len;
    return 0;
}

#endif /* __WIIU__ */
