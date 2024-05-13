
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

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "ui_api.h"
#include "utils.h"

static void quit_app_callback(void) {
    os_sched_exit(-1);
}

static const char* const info_types[] = {"Version", "Developer"};
static const char* const info_contents[] = {APPVERSION, "Ledger"};

enum {
    BLIND_SIGNING_IDX = 0,
    PUBLIC_KEY_LENGTH_IDX,
    DISPLAY_MODE_IDX,
    NB_SETTINGS,
};
static nbgl_layoutSwitch_t G_switches[NB_SETTINGS];

enum {
    BLIND_SIGNING_TOKEN = FIRST_USER_TOKEN,
    PUBLIC_KEY_LENGTH_TOKEN,
    DISPLAY_MODE_TOKEN,
};

#define SETTINGS_PAGE_NUMBER 2
static bool settings_nav_callback(uint8_t page, nbgl_pageContent_t* content) {
    if (page == 0) {
        content->type = INFOS_LIST;
        content->infosList.nbInfos = ARRAY_COUNT(info_types);
        content->infosList.infoTypes = info_types;
        content->infosList.infoContents = info_contents;
    } else if (page == 1) {
        // Read again the NVM as the value might have changed following a user touch
        if (N_storage.settings.allow_blind_sign == BlindSignDisabled) {
            G_switches[BLIND_SIGNING_IDX].initState = OFF_STATE;
        } else {
            G_switches[BLIND_SIGNING_IDX].initState = ON_STATE;
        }
        if (N_storage.settings.pubkey_display == PubkeyDisplayLong) {
            G_switches[PUBLIC_KEY_LENGTH_IDX].initState = OFF_STATE;
        } else {
            G_switches[PUBLIC_KEY_LENGTH_IDX].initState = ON_STATE;
        }
        if (N_storage.settings.display_mode == DisplayModeUser) {
            G_switches[DISPLAY_MODE_IDX].initState = OFF_STATE;
        } else {
            G_switches[DISPLAY_MODE_IDX].initState = ON_STATE;
        }
        content->type = SWITCHES_LIST;
        content->switchesList.nbSwitches = NB_SETTINGS;
        content->switchesList.switches = G_switches;
    } else {
        return false;
    }

    return true;
}

static void settings_controls_callback(int token, uint8_t index) {
    UNUSED(index);
    uint8_t new_setting;
    switch (token) {
        case BLIND_SIGNING_TOKEN:
            // Write in NVM the opposit of what the current toggle is
            new_setting = (G_switches[BLIND_SIGNING_IDX].initState != ON_STATE);
            nvm_write((void*) &N_storage.settings.allow_blind_sign,
                      &new_setting,
                      sizeof(new_setting));
            break;
        case PUBLIC_KEY_LENGTH_TOKEN:
            // Write in NVM the opposit of what the current toggle is
            new_setting = (G_switches[PUBLIC_KEY_LENGTH_IDX].initState != ON_STATE);
            nvm_write((void*) &N_storage.settings.pubkey_display,
                      &new_setting,
                      sizeof(new_setting));
            break;
        case DISPLAY_MODE_TOKEN:
            // Write in NVM the opposit of what the current toggle is
            new_setting = (G_switches[DISPLAY_MODE_IDX].initState != ON_STATE);
            nvm_write((void*) &N_storage.settings.display_mode, &new_setting, sizeof(new_setting));
            break;
        default:
            PRINTF("Unreachable\n");
            break;
    }
}

static void ui_menu_settings(void) {
    G_switches[BLIND_SIGNING_IDX].text = "Blind signing";
    G_switches[BLIND_SIGNING_IDX].subText = "Enable blind signing";
    G_switches[BLIND_SIGNING_IDX].token = BLIND_SIGNING_TOKEN;
    G_switches[BLIND_SIGNING_IDX].tuneId = TUNE_TAP_CASUAL;

    G_switches[PUBLIC_KEY_LENGTH_IDX].text = "Public key length";
    G_switches[PUBLIC_KEY_LENGTH_IDX].subText = "Display short public keys";
    G_switches[PUBLIC_KEY_LENGTH_IDX].token = PUBLIC_KEY_LENGTH_TOKEN;
    G_switches[PUBLIC_KEY_LENGTH_IDX].tuneId = TUNE_TAP_CASUAL;

    G_switches[DISPLAY_MODE_IDX].text = "Display mode";
    G_switches[DISPLAY_MODE_IDX].subText = "Use Expert display mode";
    G_switches[DISPLAY_MODE_IDX].token = DISPLAY_MODE_TOKEN;
    G_switches[DISPLAY_MODE_IDX].tuneId = TUNE_TAP_CASUAL;

    nbgl_useCaseSettings(APPNAME " settings",
                         0,
                         SETTINGS_PAGE_NUMBER,
                         false,
                         ui_idle,
                         settings_nav_callback,
                         settings_controls_callback);
}

void ui_idle(void) {
    nbgl_useCaseHome(APPNAME,
                     &C_icon_solana_64x64,
                     NULL,
                     true,
                     ui_menu_settings,
                     quit_app_callback);
}

#endif
