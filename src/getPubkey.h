#pragma once

#include "os.h"
#include "cx.h"
#include "globals.h"

void reset_get_public_key_context(void);

void handleGetPubkey(uint8_t p1,
                     uint8_t p2,
                     const uint8_t *dataBuffer,
                     uint16_t dataLength,
                     volatile unsigned int *flags,
                     volatile unsigned int *tx);
