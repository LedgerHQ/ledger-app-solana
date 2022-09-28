#include "getPubkey.h"
#include "os.h"
#include "ux.h"
#include "utils.h"
#include "sol/printer.h"

typedef struct public_key_ctx_s {
    uint8_t public_key[PUBKEY_LENGTH];
    char public_key_str[BASE58_PUBKEY_LENGTH];
} public_key_ctx_t;

size_t read_derivation_path(const uint8_t *dataBuffer, size_t size, uint32_t *derivationPath) {
    if (size == 0) {
        THROW(ApduReplySolanaInvalidMessage);
    }
    size_t len = dataBuffer[0];
    dataBuffer += 1;
    if (len < 0x01 || len > BIP32_PATH) {
        THROW(ApduReplySolanaInvalidMessage);
    }
    if (1 + 4 * len > size) {
        THROW(ApduReplySolanaInvalidMessage);
    }

    for (unsigned int i = 0; i < len; i++) {
        derivationPath[i] = ((dataBuffer[0] << 24u) | (dataBuffer[1] << 16u) |
                             (dataBuffer[2] << 8u) | (dataBuffer[3]));
        dataBuffer += 4;
    }
    return len;
}

static public_key_ctx_t G_ctx;

void reset_get_public_key_context(void) {
    MEMCLEAR(G_ctx);
}

static uint8_t set_result_get_pubkey() {
    uint8_t tx = PUBKEY_LENGTH;
    memcpy(G_io_apdu_buffer, G_ctx.public_key, PUBKEY_LENGTH);
    return tx;
}

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_display_public_flow_5_step,
             bnnn_paging,
             {
                 .title = "Pubkey",
                 .text = G_ctx.public_key_str,
             });
UX_STEP_VALID(ux_display_public_flow_6_step,
              pb,
              sendResponse(set_result_get_pubkey(), true),
              {
                  &C_icon_validate_14,
                  "Approve",
              });
UX_STEP_VALID(ux_display_public_flow_7_step,
              pb,
              sendResponse(0, false),
              {
                  &C_icon_crossmark,
                  "Reject",
              });

UX_FLOW(ux_display_public_flow,
        &ux_display_public_flow_5_step,
        &ux_display_public_flow_6_step,
        &ux_display_public_flow_7_step);

void handleGetPubkey(uint8_t p1,
                     uint8_t p2,
                     uint8_t *dataBuffer,
                     uint16_t dataLength,
                     volatile unsigned int *flags,
                     volatile unsigned int *tx) {
    UNUSED(p2);

    uint32_t derivationPath[BIP32_PATH];
    uint32_t pathLength = read_derivation_path(dataBuffer, dataLength, derivationPath);

    get_public_key(G_ctx.public_key, derivationPath, pathLength);
    encode_base58(G_ctx.public_key, PUBKEY_LENGTH, G_ctx.public_key_str, BASE58_PUBKEY_LENGTH);

    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_pubkey();
        THROW(ApduReplySuccess);
    } else {
        ux_flow_init(0, ux_display_public_flow, NULL);
        *flags |= IO_ASYNCH_REPLY;
    }
}
