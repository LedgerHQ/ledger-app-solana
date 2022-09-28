#pragma once

#include "os.h"
#include "cx.h"
#include "globals.h"

void reset_sign_message_context(void);

void handle_sign_message_receive_apdus(uint8_t p1,
                                       uint8_t p2,
                                       const uint8_t *dataBuffer,
                                       size_t dataLength);

void handle_sign_message_parse_message(bool called_from_swap, volatile unsigned int *tx);

void handle_sign_message_UI(bool called_from_swap, volatile unsigned int *flags);
