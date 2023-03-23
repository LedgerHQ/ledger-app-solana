#include "utils.h"
#include "globals.h"
#include "handle_get_pubkey.h"
#include "sol/printer.h"

static uint8_t G_publicKey[PUBKEY_LENGTH];
char G_publicKeyStr[BASE58_PUBKEY_LENGTH];

void reset_getpubkey_globals(void) {
    MEMCLEAR(G_publicKey);
    MEMCLEAR(G_publicKeyStr);
}

uint8_t set_result_get_pubkey(void) {
    memcpy(G_io_apdu_buffer, G_publicKey, PUBKEY_LENGTH);
    return PUBKEY_LENGTH;
}

//////////////////////////////////////////////////////////////////////

void handle_get_pubkey(volatile unsigned int *flags, volatile unsigned int *tx) {
    if (!flags || !tx ||
        (G_command.instruction != InsDeprecatedGetPubkey &&
         G_command.instruction != InsGetPubkey) ||
        G_command.state != ApduStatePayloadComplete) {
        THROW(ApduReplySdkInvalidParameter);
    }

    get_public_key(G_publicKey, G_command.derivation_path, G_command.derivation_path_length);
    encode_base58(G_publicKey, PUBKEY_LENGTH, G_publicKeyStr, BASE58_PUBKEY_LENGTH);

    if (G_command.non_confirm) {
        *tx = set_result_get_pubkey();
        THROW(ApduReplySuccess);
    } else {
        ui_get_public_key();
        *flags |= IO_ASYNCH_REPLY;
    }
}
