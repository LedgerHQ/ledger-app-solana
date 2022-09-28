#include "getPubkey.h"
#include "os.h"
#include "ux.h"
#include "cx.h"
#include "menu.h"
#include "utils.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "globals.h"
#include "apdu.h"

#include "handle_swap_sign_transaction.h"

static uint8_t set_result_sign_message() {
    uint8_t signature[SIGNATURE_LENGTH];
    cx_ecfp_private_key_t privateKey;
    BEGIN_TRY {
        TRY {
            get_private_key_with_seed(&privateKey,
                                      G_command.derivation_path,
                                      G_command.derivation_path_length);
            cx_eddsa_sign(&privateKey,
                          CX_LAST,
                          CX_SHA512,
                          G_command.message,
                          G_command.message_length,
                          NULL,
                          0,
                          signature,
                          SIGNATURE_LENGTH,
                          NULL);
            memcpy(G_io_apdu_buffer, signature, SIGNATURE_LENGTH);
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            MEMCLEAR(privateKey);
        }
    }
    END_TRY;
    return SIGNATURE_LENGTH;
}

static void send_result_sign_message(void) {
    sendResponse(set_result_sign_message(), true);
}

//////////////////////////////////////////////////////////////////////

UX_STEP_CB(ux_approve_step,
           pb,
           send_result_sign_message(),
           {
               &C_icon_validate_14,
               "Approve",
           });
UX_STEP_CB(ux_reject_step,
           pb,
           sendResponse(0, false),
           {
               &C_icon_crossmark,
               "Reject",
           });
UX_STEP_NOCB_INIT(ux_summary_step,
                  bnnn_paging,
                  {
                      size_t step_index = G_ux.flow_stack[stack_slot].index;
                      enum DisplayFlags flags = DisplayFlagNone;
                      if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
                          flags |= DisplayFlagLongPubkeys;
                      }
                      if (transaction_summary_display_item(step_index, flags)) {
                          THROW(ApduReplySolanaSummaryUpdateFailed);
                      }
                  },
                  {
                      .title = G_transaction_summary_title,
                      .text = G_transaction_summary_text,
                  });

#define MAX_FLOW_STEPS                                     \
    (MAX_TRANSACTION_SUMMARY_ITEMS + 1 /* approve */       \
     + 1                               /* reject */        \
     + 1                               /* FLOW_END_STEP */ \
    )
ux_flow_step_t const *flow_steps[MAX_FLOW_STEPS];

static int scan_header_for_signer(const uint32_t *derivation_path,
                                  uint32_t derivation_path_length,
                                  size_t *signer_index,
                                  const MessageHeader *header) {
    uint8_t signer_pubkey[PUBKEY_SIZE];
    get_public_key(signer_pubkey, derivation_path, derivation_path_length);
    for (size_t i = 0; i < header->pubkeys_header.num_required_signatures; ++i) {
        const Pubkey *current_pubkey = &(header->pubkeys[i]);
        if (memcmp(current_pubkey, signer_pubkey, PUBKEY_SIZE) == 0) {
            *signer_index = i;
            return 0;
        }
    }
    return -1;
}

void handle_sign_message_parse_message(volatile unsigned int *tx) {
    if (!tx ||
        (G_command.instruction != InsDeprecatedSignMessage &&
         G_command.instruction != InsSignMessage) ||
        G_command.state != ApduStatePayloadComplete) {
        THROW(ApduReplySdkInvalidParameter);
    }
    // Handle the transaction message signing
    Parser parser = {G_command.message, G_command.message_length};
    PrintConfig print_config;
    print_config.expert_mode = (N_storage.settings.display_mode == DisplayModeExpert);
    print_config.signer_pubkey = NULL;
    MessageHeader *header = &print_config.header;
    size_t signer_index;

    if (parse_message_header(&parser, header) != 0) {
        // This is not a valid Solana message
        THROW(ApduReplySolanaInvalidMessage);
    }

    // Ensure the requested signer is present in the header
    if (scan_header_for_signer(G_command.derivation_path,
                               G_command.derivation_path_length,
                               &signer_index,
                               header) != 0) {
        THROW(ApduReplySolanaInvalidMessageHeader);
    }
    print_config.signer_pubkey = &header->pubkeys[signer_index];

    if (G_command.non_confirm) {
        // Uncomment this to allow unattended signing.
        //*tx = set_result_sign_message();
        // THROW(ApduReplySuccess);
        UNUSED(tx);
    }

    if ((G_command.non_confirm || G_called_from_swap) &&
        !(G_command.non_confirm && G_called_from_swap)) {
        // Blind sign requested NOT in swap context
        // Or no blind sign requested while in swap context
        THROW(ApduReplySdkNotSupported);
    }

    // Set the transaction summary
    transaction_summary_reset();
    if (process_message_body(parser.buffer, parser.buffer_length, &print_config) != 0) {
        // Message not processed, throw if blind signing is not enabled
        if (N_storage.settings.allow_blind_sign == BlindSignEnabled) {
            SummaryItem *item = transaction_summary_primary_item();
            summary_item_set_string(item, "Unrecognized", "format");

            cx_hash_sha256(G_command.message,
                           G_command.message_length,
                           (uint8_t *) &G_command.message_hash,
                           HASH_LENGTH);

            item = transaction_summary_general_item();
            summary_item_set_hash(item, "Message Hash", &G_command.message_hash);
        } else {
            THROW(ApduReplySdkNotSupported);
        }
    }

    // Add fee payer to summary if needed
    const Pubkey *fee_payer = &header->pubkeys[0];
    if (print_config_show_authority(&print_config, fee_payer)) {
        transaction_summary_set_fee_payer_pubkey(fee_payer);
    }
}

static bool check_swap_validity(const SummaryItemKind_t kinds[MAX_TRANSACTION_SUMMARY_ITEMS],
                                size_t num_summary_steps) {
    bool amount_ok = false;
    bool recipient_ok = false;
    bool fee_payer_ok = false;
    if (num_summary_steps != 3) {
        PRINTF("3 steps expected for transaction in swap context, not %u\n", num_summary_steps);
        return false;
    }
    for (size_t i = 0; i < num_summary_steps; ++i) {
        transaction_summary_display_item(i, DisplayFlagNone | DisplayFlagLongPubkeys);
        PRINTF("G_transaction_summary_title = %s\n", G_transaction_summary_title);
        PRINTF("G_transaction_summary_text = %s\n", G_transaction_summary_text);
        switch (kinds[i]) {
            case SummaryItemAmount:
                if (strcmp(G_transaction_summary_title, "Transfer") == 0) {
                    amount_ok = check_swap_amount(G_transaction_summary_text);
                } else {
                    PRINTF("Refused field '%s'\n", G_transaction_summary_title);
                    return false;
                }
                break;
            case SummaryItemPubkey:
                if (strcmp(G_transaction_summary_title, "Recipient") == 0) {
                    recipient_ok = check_swap_recipient(G_transaction_summary_text);
                } else if (strcmp(G_transaction_summary_title, "Fee payer") == 0) {
                    fee_payer_ok = check_swap_fee_payer(G_transaction_summary_text);
                } else {
                    PRINTF("Refused field '%s'\n", G_transaction_summary_title);
                    return false;
                }
                break;
            default:
                PRINTF("Refused kind '%u'\n", SummaryItemAmount);
                return false;
        }
    }
    return amount_ok && recipient_ok && fee_payer_ok;
}

void handle_sign_message_ui(volatile unsigned int *flags) {
    // Display the transaction summary
    SummaryItemKind_t summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_summary_steps = 0;
    if (transaction_summary_finalize(summary_step_kinds, &num_summary_steps) == 0) {
        // If we are in swap context, do not redisplay the message data
        // Instead, ensure they are identitical with what was previously displayed
        if (G_called_from_swap) {
            if (check_swap_validity(summary_step_kinds, num_summary_steps)) {
                send_result_sign_message();
                // Quit app, we are in limited mode and our work is done
                os_sched_exit(0);
            } else {
                PRINTF("Refused blind signing incorrect Swap transaction\n");
                sendResponse(0, false);
            }
        } else {
            MEMCLEAR(flow_steps);
            size_t num_flow_steps = 0;

            for (size_t i = 0; i < num_summary_steps; i++) {
                flow_steps[num_flow_steps++] = &ux_summary_step;
            }

            flow_steps[num_flow_steps++] = &ux_approve_step;
            flow_steps[num_flow_steps++] = &ux_reject_step;
            flow_steps[num_flow_steps++] = FLOW_END_STEP;

            ux_flow_init(0, flow_steps, NULL);
        }
    } else {
        THROW(ApduReplySolanaSummaryFinalizeFailed);
    }

    *flags |= IO_ASYNCH_REPLY;
}
