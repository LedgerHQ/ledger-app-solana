
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


static void callback_match(bool match) {
    if (match) {
        sendResponse(set_result_get_pubkey(), true, false);
        nbgl_useCaseStatus("ADDRESS\nVERIFIED", true, ui_idle);
    } else {
        sendResponse(0, false, false);
        nbgl_useCaseStatus("Address verification\ncancelled", false, ui_idle);
    }
}

void ui_get_public_key(void) {
    nbgl_useCaseAddressConfirmation(G_publicKeyStr, callback_match);
}

#endif
