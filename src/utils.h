#include "os.h"
#include "cx.h"
#include "globals.h"
#include <string.h>
#include "apdu.h"

#ifndef _UTILS_H_
#define _UTILS_H_

// Marker flag for DEPRECATED ADPU exchange format
#define DATA_HAS_LENGTH_PREFIX (1 << 15)

typedef enum rlpTxType {
    TX_LENGTH = 0,
    TX_TYPE,
    TX_SENDER,
    TX_RECIPIENT,
    TX_AMOUNT,
    TX_FEE
} rlpTxType;

void get_public_key(uint8_t *publicKeyArray, const uint32_t *derivationPath, size_t pathLength);

uint32_t readUint32BE(uint8_t *buffer);

void get_private_key(cx_ecfp_private_key_t *privateKey,
                     const uint32_t *derivationPath,
                     size_t pathLength);

void get_private_key_with_seed(cx_ecfp_private_key_t *privateKey,
                               const uint32_t *derivationPath,
                               uint8_t pathLength);

/**
 * Deserialize derivation path from raw bytes.
 *
 * @param[in] data_buffer
 *   Pointer to serialized bytes.
 * @param[in] data_size
 *   Size of the data_buffer.
 * @param[out] derivation_path
 *   Pointer to the target array to store deserialized data into.
 * @param[out] derivation_path_length
 *   Pointer to the variable that will hold derivation path length.
 *
 * @return zero on success, ApduReply error code otherwise.
 *
 */
int read_derivation_path(const uint8_t *data_buffer,
                         size_t data_size,
                         uint32_t *derivation_path,
                         uint32_t *derivation_path_length);


// type            userid    x    y   w    h  str rad fill      fg        bg      fid iid  txt
// touchparams...       ]
#define UI_BUTTONS                                                                               \
    {{BAGL_RECTANGLE, 0x00, 0, 0, 128, 32, 0, 0, BAGL_FILL, 0x000000, 0xFFFFFF, 0, 0},           \
     NULL,                                                                                       \
     0,                                                                                          \
     0,                                                                                          \
     0,                                                                                          \
     NULL,                                                                                       \
     NULL,                                                                                       \
     NULL},                                                                                      \
        {{BAGL_ICON, 0x00, 3, 12, 7, 7, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CROSS},  \
         NULL,                                                                                   \
         0,                                                                                      \
         0,                                                                                      \
         0,                                                                                      \
         NULL,                                                                                   \
         NULL,                                                                                   \
         NULL},                                                                                  \
    {                                                                                            \
        {BAGL_ICON, 0x00, 117, 13, 8, 6, 0, 0, 0, 0xFFFFFF, 0x000000, 0, BAGL_GLYPH_ICON_CHECK}, \
            NULL, 0, 0, 0, NULL, NULL, NULL                                                      \
    }

#define UI_FIRST  1
#define UI_SECOND 0

#define UI_LABELINE(userId, text, isFirst, font, horizontalScrollSpeed) \
    {                                                                   \
        {BAGL_LABELINE,                                                 \
         (userId),                                                      \
         23,                                                            \
         (isFirst) ? 12 : 26,                                           \
         82,                                                            \
         12,                                                            \
         (horizontalScrollSpeed) ? BAGL_STROKE_FLAG_ONESHOT | 10 : 0,   \
         0,                                                             \
         0,                                                             \
         0xFFFFFF,                                                      \
         0x000000,                                                      \
         (font) | BAGL_FONT_ALIGNMENT_CENTER,                           \
         horizontalScrollSpeed},                                        \
            (text), 0, 0, 0, NULL, NULL, NULL                           \
    }

#endif

#ifdef TEST
#include <stdio.h>
#define THROW(code)                \
    do {                           \
        printf("error: %d", code); \
    } while (0)
#define PRINTF(msg, arg) printf(msg, arg)
#define PIC(code)        code
//#define TARGET_NANOS 1
#define TARGET_BLUE    1
#define MEMCLEAR(dest) explicit_bzero(&dest, sizeof(dest));
#else
#define MEMCLEAR(dest)                       \
    do {                                     \
        explicit_bzero(&dest, sizeof(dest)); \
    } while (0)
#include "bolos_target.h"
#endif  // TEST
