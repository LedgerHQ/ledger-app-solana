#ifdef HAVE_NBGL

#include "io.h"
#include "sol/parser.h"
#include "sol/printer.h"
#include "sol/print_config.h"
#include "sol/message.h"
#include "sol/transaction_summary.h"
#include "glyphs.h"
#include "apdu.h"
#include "utils.h"
#include "ui_api.h"

#include "nbgl_page.h"
#include "nbgl_use_case.h"

#include "handle_sign_message.h"


// Layout of the review flow
static nbgl_layoutTagValueList_t layout;
// Used by NBGL to display the reference the pair number N
static nbgl_layoutTagValue_t current_pair;

// We will display at most 4 items on a Stax review screen
#define MAX_SIMULTANEOUS_DISPLAYED_SLOTS 4
typedef struct dynamic_slot_s {
    char title[sizeof(G_transaction_summary_title)];
    char text[sizeof(G_transaction_summary_text)];
} dynamic_slot_t;
static dynamic_slot_t displayed_slots[MAX_SIMULTANEOUS_DISPLAYED_SLOTS];

// Final review screen of the message signing flow
static const nbgl_pageInfoLongPress_t review_final_long_press = {
    .text = "Sign message on\nSolana network?",
    .icon = &C_icon_solana_64x64,
    .longPressText = "Hold to sign",
    .longPressToken = 0,
    .tuneId = TUNE_TAP_CASUAL,
};

// Callback called when the user confirms the message rejection
static void rejectChoice(void) {
    sendResponse(0, false, false);
    nbgl_useCaseStatus("message\nrejected", false, ui_idle);
}

// If the user asks for message rejection, ask for confirmation
static void rejectUseCaseChoice(void) {
    nbgl_useCaseConfirm("Reject message?", NULL, "Yes, reject", "Go back to message", rejectChoice);
}

// Callback called on the final review screen
static void review_final_callback(bool confirmed) {
    if (confirmed) {
        sendResponse(set_result_sign_message(), true, false);
        nbgl_useCaseStatus("MESSAGE\nSIGNED", true, ui_idle);
    } else {
        rejectUseCaseChoice();
    }
}

// function called by NBGL to get the current_pair indexed by "index"
// current_pair will point at values stored in displayed_slots[]
// this will enable displaying at most sizeof(displayed_slots) values simultaneously
static nbgl_layoutTagValue_t *get_single_action_review_pair(uint8_t index) {
    dynamic_slot_t *slot = &displayed_slots[index % sizeof(displayed_slots)];
    enum DisplayFlags flags = DisplayFlagNone;
    if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
        flags |= DisplayFlagLongPubkeys;
    }
    if (transaction_summary_display_item(index, flags)) {
        THROW(ApduReplySolanaSummaryUpdateFailed);
    }
    memcpy(&slot->title, &G_transaction_summary_title, sizeof(slot->title));
    memcpy(&slot->text, &G_transaction_summary_text, sizeof(slot->text));
    current_pair.item = slot->title;
    current_pair.value = slot->text;
    return &current_pair;
}

// NBGL library has to know how many steps will be displayed
static size_t transaction_steps_number;

// Prepare the review layout structure and starts the review use_case
static void start_review(void) {
    layout.nbMaxLinesForValue = 0;
    layout.smallCaseForValue = true;
    layout.wrapping = true;
    layout.pairs = NULL;  // to indicate that callback should be used
    layout.callback = get_single_action_review_pair;
    layout.startIndex = 0;
    layout.nbPairs = transaction_steps_number;

    nbgl_useCaseStaticReview(&layout, &review_final_long_press, "Reject message", review_final_callback);
}

void start_sign_tx_ui(size_t num_summary_steps) {
    // Save steps number for later
    transaction_steps_number = num_summary_steps;
    // start display
    nbgl_useCaseReviewStart(&C_icon_solana_64x64,
                            "Review message to\nsign on Solana\nnetwork",
                            "",
                            "Reject message",
                            start_review,
                            rejectUseCaseChoice);
}

#endif
