#include "handle_get_printable_amount.h"
#include "swap_lib_calls.h"
#include "swap_utils.h"
#include "utils.h"
#include "sol/printer.h"

/* return 0 on error, 1 otherwise */
int handle_get_printable_amount(get_printable_amount_parameters_t* params) {
    PRINTF("Inside Solana handle_get_printable_amount\n");
    MEMCLEAR(params->printable_amount);

    // Fees are displayed normally
    // params->is_fee

    if (params->coin_configuration != NULL || params->coin_configuration_length != 0) {
        PRINTF("No coin_configuration expected\n");
        return 0;
    }

    uint64_t amount;
    if (!swap_str_to_u64(params->amount, params->amount_length, &amount)) {
        PRINTF("Amount is too big");
        return 0;
    }

    if (print_amount(amount, params->printable_amount, sizeof(params->printable_amount)) != 0) {
        PRINTF("print_amount failed");
        return 0;
    }

    PRINTF("Amount %s\n", params->printable_amount);

    return 1;
}
