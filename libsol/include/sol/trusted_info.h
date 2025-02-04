#pragma once

#include "sol/printer.h"

// libsol cannot include src.
// The libsol / src split should be reevaluated, in the meantime this lives here

typedef struct trusted_info_s {
    bool received;
    char encoded_owner_address[BASE58_PUBKEY_LENGTH];
    uint8_t owner_address[PUBKEY_LENGTH];
    char encoded_token_address[BASE58_PUBKEY_LENGTH];
    uint8_t token_address[PUBKEY_LENGTH];
    char encoded_mint_address[BASE58_PUBKEY_LENGTH];
    uint8_t mint_address[PUBKEY_LENGTH];
} trusted_info_t;

extern trusted_info_t g_trusted_info;
