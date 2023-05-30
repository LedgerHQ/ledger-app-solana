#pragma once

#include "swap_lib_calls.h"

bool copy_transaction_parameters(const create_transaction_parameters_t *sign_transaction_params);

bool check_swap_amount(const char *title, const char *text);
bool check_swap_recipient(const char *title, const char *text);
