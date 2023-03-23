#pragma once

#include "os.h"
#include "cx.h"
#include "globals.h"

void handle_sign_offchain_message(volatile unsigned int *flags, volatile unsigned int *tx);

void start_sign_offchain_message_ui(bool is_ascii, size_t num_summary_steps);
