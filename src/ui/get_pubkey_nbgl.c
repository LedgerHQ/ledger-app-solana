
/*****************************************************************************
 *   Ledger App Solana
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#ifdef HAVE_NBGL

#include "handle_get_pubkey.h"
#include "io.h"
#include "sol/printer.h"
#include "nbgl_use_case.h"
#include "ui_api.h"

static void confirm_address_approval(void) {
    // display a success status page and go back to main
    sendResponse(set_result_get_pubkey(), true, false);
    nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, ui_idle);
}

static void confirm_address_rejection(void) {
    // display a status page and go back to main
    sendResponse(0, false, false);
    nbgl_useCaseStatus("Address verification\ncancelled", false, ui_idle);
}

static void review_choice(bool confirm) {
    if (confirm) {
        confirm_address_approval();
    } else {
        confirm_address_rejection();
    }
}

static void continue_review(void) {
    nbgl_useCaseAddressConfirmation(G_publicKeyStr, review_choice);
}

void ui_get_public_key(void) {
    nbgl_useCaseReviewStart(&C_icon_solana_64x64,
                            "Verify Solana\naddress",
                            NULL,
                            "Cancel",
                            continue_review,
                            confirm_address_rejection);
}

#endif
