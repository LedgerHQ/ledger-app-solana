#include "io.h"
#include "utils.h"
#include "handle_swap_sign_transaction.h"

#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"

#include "handle_sign_message.h"
#include "ui_api.h"

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
    if (num_summary_steps != 2) {
        PRINTF("2 steps expected for transaction in swap context, not %u\n", num_summary_steps);
        return false;
    }
    for (size_t i = 0; i < num_summary_steps; ++i) {
        transaction_summary_display_item(i, DisplayFlagNone | DisplayFlagLongPubkeys);
        switch (kinds[i]) {
            case SummaryItemAmount:
                amount_ok =
                    check_swap_amount(G_transaction_summary_title, G_transaction_summary_text);
                break;
            case SummaryItemPubkey:
                recipient_ok =
                    check_swap_recipient(G_transaction_summary_title, G_transaction_summary_text);
                break;
            default:
                PRINTF("Refused kind '%u'\n", kinds[i]);
                return false;
        }
    }
    return amount_ok && recipient_ok;
}

void handle_sign_message_ui(volatile unsigned int *flags) {
    // Display the transaction summary
    SummaryItemKind_t summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_summary_steps = 0;
    if (transaction_summary_finalize(summary_step_kinds, &num_summary_steps) == 0) {
        // If we are in swap context, do not redisplay the message data
        // Instead, ensure they are identitical with what was previously displayed
        if (G_called_from_swap) {
            if (G_swap_response_ready) {
                // Safety against trying to make the app sign multiple TX
                // This code should never be triggered as the app is supposed to exit after
                // sending the signed transaction
                PRINTF("Safety against double signing triggered\n");
                os_sched_exit(-1);
            } else {
                // We will quit the app after this transaction, whether it succeeds or fails
                PRINTF("Swap response is ready, the app will quit after the next send\n");
                G_swap_response_ready = true;
            }
            if (check_swap_validity(summary_step_kinds, num_summary_steps)) {
                PRINTF("Valid swap transaction signed\n");
                sendResponse(set_result_sign_message(), ApduReplySuccess, false);
            } else {
                PRINTF("Refused signing incorrect Swap transaction\n");
                sendResponse(0, ApduReplySolanaSummaryFinalizeFailed, false);
            }
        } else {
            start_sign_tx_ui(num_summary_steps);
        }
    } else {
        THROW(ApduReplySolanaSummaryFinalizeFailed);
    }

    *flags |= IO_ASYNCH_REPLY;
}
