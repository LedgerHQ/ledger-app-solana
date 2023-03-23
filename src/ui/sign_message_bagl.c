#ifdef HAVE_BAGL

#include "io.h"
#include "utils.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "apdu.h"

#include "handle_sign_message.h"


UX_STEP_CB(ux_approve_step,
           pb,
           sendResponse(set_result_sign_message(), true, true),
           {
               &C_icon_validate_14,
               "Approve",
           });
UX_STEP_CB(ux_reject_step,
           pb,
           sendResponse(0, false, true),
           {
               &C_icon_crossmark,
               "Reject",
           });
UX_STEP_NOCB_INIT(ux_summary_step,
                  bnnn_paging,
                  {
                      size_t step_index = G_ux.flow_stack[stack_slot].index;
                      PRINTF("step_index = %d\n", step_index);
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

void start_sign_tx_ui(size_t num_summary_steps) {
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

#endif
