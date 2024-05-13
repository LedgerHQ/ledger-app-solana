#pragma once

#include "os.h"
#include "cx.h"
#include "globals.h"
#include "sol/printer.h"

extern char G_publicKeyStr[BASE58_PUBKEY_LENGTH];

void reset_getpubkey_globals(void);

void handle_get_pubkey(volatile unsigned int *flags, volatile unsigned int *tx);

uint8_t set_result_get_pubkey(void);
