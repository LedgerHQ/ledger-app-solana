#pragma once

#include "globals.h"

bool is_on_curve(const uint8_t compressed_point[PUBKEY_LENGTH]);

bool validate_associated_token_address(const uint8_t owner_account[PUBKEY_LENGTH],
                                       const uint8_t mint_account[PUBKEY_LENGTH],
                                       const uint8_t provided_ata[PUBKEY_LENGTH]);
