#include "os.h"
#include "cx.h"
#include "globals.h"

#ifndef _GET_PUBKEY_H_
#define _GET_PUBKEY_H_

void reset_getpubkey_globals(void);

void handle_get_pubkey(volatile unsigned int *flags, volatile unsigned int *tx);

#endif
