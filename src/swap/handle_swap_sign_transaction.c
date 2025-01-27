#include "handle_swap_sign_transaction.h"
#include "utils.h"
#include "os.h"
#include "swap_lib_calls.h"
#include "swap_utils.h"
#include "sol/printer.h"
#include "swap_common.h"
#include "util.h"

typedef struct swap_validated_s {
    bool initialized;
    uint8_t decimals;
    char ticker[MAX_SWAP_TOKEN_LENGTH];
    uint64_t amount;
    char recipient[BASE58_PUBKEY_LENGTH];
} swap_validated_t;

static swap_validated_t G_swap_validated;

// Save the BSS address where we will write the return value when finished
static uint8_t *G_swap_sign_return_value_address;

// Save the data validated during the Exchange app flow
bool copy_transaction_parameters(create_transaction_parameters_t *params) {
    // Ensure no extraid
    if (params->destination_address_extra_id == NULL) {
        PRINTF("destination_address_extra_id expected\n");
        return false;
    } else if (params->destination_address_extra_id[0] != '\0') {
        PRINTF("destination_address_extra_id expected empty, not '%s'\n",
               params->destination_address_extra_id);
        return false;
    }

    // first copy parameters to stack, and then to global data.
    // We need this "trick" as the input data position can overlap with app globals
    swap_validated_t swap_validated;
    memset(&swap_validated, 0, sizeof(swap_validated));

    // Parse config and save decimals and ticker
    // If there is no coin_configuration, consider that we are doing a SOL swap
    if (params->coin_configuration == NULL) {
        memcpy(swap_validated.ticker, "SOL", sizeof("SOL"));
        swap_validated.decimals = SOL_DECIMALS;
    } else {
        if (!swap_parse_config(params->coin_configuration,
                               params->coin_configuration_length,
                               swap_validated.ticker,
                               sizeof(swap_validated.ticker),
                               &swap_validated.decimals)) {
            PRINTF("Fail to parse coin_configuration\n");
            return false;
        }
    }

    // Save recipient
    strlcpy(swap_validated.recipient,
            params->destination_address,
            sizeof(swap_validated.recipient));
    if (swap_validated.recipient[sizeof(swap_validated.recipient) - 1] != '\0') {
        PRINTF("Address copy error\n");
        return false;
    }

    // Save amount
    if (!swap_str_to_u64(params->amount, params->amount_length, &swap_validated.amount)) {
        return false;
    }

    swap_validated.initialized = true;

    // Full reset the global variables
    os_explicit_zero_BSS_segment();

    // Keep the address at which we'll reply the signing status
    G_swap_sign_return_value_address = &params->result;

    // Commit the values read from exchange to the clean global space
    memcpy(&G_swap_validated, &swap_validated, sizeof(swap_validated));
    return true;
}

// Check that the amount in parameter is the same as the previously saved amount
bool check_swap_amount(const char *text) {
    if (!G_swap_validated.initialized) {
        return false;
    }

    char validated_amount[MAX_PRINTABLE_AMOUNT_SIZE];
    if (print_token_amount(G_swap_validated.amount,
                           G_swap_validated.ticker,
                           G_swap_validated.decimals,
                           validated_amount,
                           sizeof(validated_amount)) != 0) {
        PRINTF("Conversion failed\n");
        return false;
    }

    if (strcmp(text, validated_amount) == 0) {
        return true;
    } else {
        PRINTF("Amount requested in this transaction = %s\n", text);
        PRINTF("Amount validated in swap = %s\n", validated_amount);
        return false;
    }
}

// Check that the recipient in parameter is the same as the previously saved recipient
bool check_swap_recipient(const char *text) {
    if (!G_swap_validated.initialized) {
        return false;
    }

    if (strcmp(G_swap_validated.recipient, text) == 0) {
        return true;
    } else {
        PRINTF("Recipient requested in this transaction = %s\n", text);
        PRINTF("Recipient validated in swap = %s\n", G_swap_validated.recipient);
        return false;
    }
}

void __attribute__((noreturn)) finalize_exchange_sign_transaction(bool is_success) {
    *G_swap_sign_return_value_address = is_success;
    os_lib_end();
}

bool is_token_transaction() {
    return (memcmp(G_swap_validated.ticker, "SOL", sizeof("SOL")) != 0);
}
