#pragma once

#include "swap_lib_calls.h"

bool copy_transaction_parameters(create_transaction_parameters_t *sign_transaction_params);

bool check_swap_amount(const char *amount);
bool check_swap_recipient(const char *recipient);
bool check_swap_fee_payer(const char *fee_payer);
