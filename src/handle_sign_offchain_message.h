#pragma once

#include "os.h"
#include "cx.h"
#include "globals.h"

void handle_sign_offchain_message(volatile unsigned int *flags, volatile unsigned int *tx);
