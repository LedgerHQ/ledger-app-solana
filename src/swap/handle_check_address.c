#include <string.h>

#include "handle_check_address.h"
#include "os.h"
#include "utils.h"
#include "sol/printer.h"

int handle_check_address(check_address_parameters_t *params) {
    PRINTF("Inside Solana handle_check_address\n");
    PRINTF("Params on the address %d\n", (unsigned int) params);

    if (params->coin_configuration != NULL || params->coin_configuration_length != 0) {
        PRINTF("No coin_configuration expected\n");
        return 0;
    }

    if (params->address_parameters == NULL) {
        PRINTF("derivation path expected\n");
        return 0;
    }

    if (params->address_to_check == NULL) {
        PRINTF("Address to check expected\n");
        return 0;
    }
    PRINTF("Address to check %s\n", params->address_to_check);

    if (params->extra_id_to_check == NULL) {
        PRINTF("extra_id_to_check expected\n");
        return 0;
    } else if (params->extra_id_to_check[0] != '\0') {
        PRINTF("extra_id_to_check expected empty, not '%s'\n", params->extra_id_to_check);
        return 0;
    }

    uint8_t public_key[PUBKEY_LENGTH];
    char public_key_str[BASE58_PUBKEY_LENGTH];
    if (derive_public_key(params->address_parameters,
                          params->address_parameters_length,
                          public_key,
                          public_key_str) != 0) {
        PRINTF("Failed to derive public key\n");
        return 0;
    }
    // Only public_key_str is usefull in this context
    UNUSED(public_key);

    if (strcmp(params->address_to_check, public_key_str) != 0) {
        PRINTF("Adress %s != %s\n", params->address_to_check, public_key_str);
        return 0;
    }

    PRINTF("Addresses match\n");
    return 1;
}
