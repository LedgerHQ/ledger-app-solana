#include "apdu.h"
#include "getPubkey.h"
#include "os.h"
#include "ux.h"
#include "utils.h"
#include "sol/printer.h"

static uint8_t publicKey[PUBKEY_LENGTH];
static char publicKeyStr[BASE58_PUBKEY_LENGTH];

static uint8_t set_result_get_pubkey() {
    memcpy(G_io_apdu_buffer, publicKey, PUBKEY_LENGTH);
    return PUBKEY_LENGTH;
}

//////////////////////////////////////////////////////////////////////

UX_STEP_NOCB(ux_display_public_flow_5_step,
             bnnn_paging,
             {
                 .title = "Pubkey",
                 .text = publicKeyStr,
             });
UX_STEP_CB(ux_display_public_flow_6_step,
           pb,
           sendResponse(set_result_get_pubkey(), true),
           {
               &C_icon_validate_14,
               "Approve",
           });
UX_STEP_CB(ux_display_public_flow_7_step,
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

void handle_get_pubkey(volatile unsigned int *flags, volatile unsigned int *tx) {
    if (!flags || !tx ||
        (G_command.instruction != InsDeprecatedGetPubkey &&
         G_command.instruction != InsGetPubkey) ||
        G_command.state != ApduStatePayloadComplete) {
        THROW(ApduReplySdkInvalidParameter);
    }

    get_public_key(publicKey, G_command.derivation_path, G_command.derivation_path_length);
    encode_base58(publicKey, PUBKEY_LENGTH, publicKeyStr, BASE58_PUBKEY_LENGTH);

    if (G_command.non_confirm) {
        *tx = set_result_get_pubkey();
        THROW(ApduReplySuccess);
    } else {
        ux_flow_init(0, ux_display_public_flow, NULL);
        *flags |= IO_ASYNCH_REPLY;
    }
}
