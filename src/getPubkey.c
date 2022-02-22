#include "getPubkey.h"
#include "os.h"
#include "ux.h"
#include "utils.h"
#include "sol/printer.h"

static uint8_t publicKey[PUBKEY_LENGTH];
static char publicKeyStr[BASE58_PUBKEY_LENGTH];

int read_derivation_path(
    const uint8_t *dataBuffer,
    size_t size,
    uint32_t *derivationPath
) {
    if (size == 0) {
        THROW(ApduReplyVelasInvalidMessage);
    }
    size_t len = dataBuffer[0];
    dataBuffer += 1;
    if (len < 0x01 || len > BIP32_PATH) {
        THROW(ApduReplyVelasInvalidMessage);
    }
    if (1 + 4 * len > size) {
        THROW(ApduReplyVelasInvalidMessage);
    }

    for (unsigned int i = 0; i < len; i++) {
        derivationPath[i] = (
            (dataBuffer[0] << 24u) | (dataBuffer[1] << 16u) |
            (dataBuffer[2] << 8u) | (dataBuffer[3])
        );
        dataBuffer += 4;
    }
    return len;
}

static uint8_t set_result_get_pubkey() {
    uint8_t tx = 32;

    os_memmove(G_io_apdu_buffer, publicKey, 32);
    return tx;
}

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(
    ux_display_public_flow_5_step,
    bnnn_paging,
    {
        .title = "Pubkey",
        .text = publicKeyStr,
    });
UX_STEP_VALID(
    ux_display_public_flow_6_step,
    pb,
    sendResponse(set_result_get_pubkey(), true),
    {
        &C_icon_validate_14,
        "Approve",
    });
UX_STEP_VALID(
    ux_display_public_flow_7_step,
    pb,
    sendResponse(0, false),
    {
        &C_icon_crossmark,
        "Reject",
    });

UX_FLOW(ux_display_public_flow,
    &ux_display_public_flow_5_step,
    &ux_display_public_flow_6_step,
    &ux_display_public_flow_7_step
);

void handleGetPubkey(
    uint8_t p1,
    uint8_t p2,
    uint8_t *dataBuffer,
    uint16_t dataLength,
    volatile unsigned int *flags,
    volatile unsigned int *tx
) {
    UNUSED(p2);

    uint32_t derivationPath[BIP32_PATH];
    int pathLength = read_derivation_path(
        dataBuffer,
        dataLength,
        derivationPath
    );

    getPublicKey(derivationPath, publicKey, pathLength);
    encode_base58(
        publicKey,
        PUBKEY_LENGTH,
        publicKeyStr,
        BASE58_PUBKEY_LENGTH
    );

    if (p1 == P1_NON_CONFIRM) {
        *tx = set_result_get_pubkey();
        THROW(ApduReplySuccess);
    } else {
        ux_flow_init(0, ux_display_public_flow, NULL);
        *flags |= IO_ASYNCH_REPLY;
    }
}
