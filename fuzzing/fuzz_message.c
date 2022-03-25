#include "sol/message.h"
#include "sol/parser.h"
#include "sol/transaction_summary.h"


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    Parser parser = {Data, Size};
    PrintConfig print_config;
    MessageHeader *header = &print_config.header;

    print_config.expert_mode = true;
    print_config.signer_pubkey = NULL;

    if (parse_message_header(&parser, header)) {
        // This is not a valid Solana message
        return 0;
    }
    transaction_summary_reset();
    process_message_body(parser.buffer, parser.buffer_length, &print_config);

    transaction_summary_set_fee_payer_pubkey(&header->pubkeys[0]);

    enum SummaryItemKind summary_step_kinds[MAX_TRANSACTION_SUMMARY_ITEMS];
    size_t num_summary_steps = 0;
    transaction_summary_finalize(
            summary_step_kinds,
            &num_summary_steps
    );

    for (size_t i = 0; i < num_summary_steps; i++) {
        transaction_summary_display_item(i, DisplayFlagLongPubkeys);
    }
    return 0;
}
