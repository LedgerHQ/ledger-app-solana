#pragma once
#include <string.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define BAIL_IF(x)           \
    do {                     \
        int err = x;         \
        if (err) return err; \
    } while (0)

#ifndef MIN
    #define MIN(a, b) ((a) < (b) ? (a) : (b));
#endif

#define assert_string_equal(actual, expected) assert(strcmp(actual, expected) == 0)

#define assert_pubkey_equal(actual, expected) assert(memcmp(actual, expected, 32) == 0)

#if defined(SDK_TARGET_NANOX) || defined(SDK_TARGET_NANOS2) || defined(SDK_TARGET_STAX) || defined(TEST_MEMORY_EXTENDED)
    #define EXTENDED_MEMORY 1
#else
    #define EXTENDED_MEMORY 0
#endif


#ifndef UNUSED
    #define UNUSED(x) (void) x
#endif
