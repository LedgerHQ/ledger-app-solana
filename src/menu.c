#include "menu.h"
#include "os.h"

void display_settings(void);
void switch_allow_blind_sign_data(void);
void switch_pubkey_display_data(void);

//////////////////////////////////////////////////////////////////////
const char* settings_submenu_getter(unsigned int idx);
void settings_submenu_selector(unsigned int idx);

//////////////////////////////////////////////////////////////////////////////////////
// Allow blind signing submenu

static void allow_blind_sign_data_change(enum BlindSign blind_sign) {
    uint8_t value;
    switch (blind_sign) {
        case BlindSignDisabled:
        case BlindSignEnabled:
            value = (uint8_t) blind_sign;
            nvm_write((void *)&N_storage.settings.allow_blind_sign, &value, sizeof(value));
            break;
    }
    ui_idle();
}

const char const * no_yes_data_getter_values[] = {
  "No",
  "Yes",
  "Back"
};

static const char* allow_blind_sign_data_getter(unsigned int idx) {
  if (idx < ARRAYLEN(no_yes_data_getter_values)) {
    return no_yes_data_getter_values[idx];
  }
  return NULL;
}

void allow_blind_sign_data_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      allow_blind_sign_data_change(BlindSignDisabled);
      break;
    case 1:
      allow_blind_sign_data_change(BlindSignEnabled);
      break;
    default:
      ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector);
  }
}

//////////////////////////////////////////////////////////////////////////////////////
// Pubkey display submenu

void pubkey_display_data_change(enum PubkeyDisplay pubkey_display) {
    uint8_t value;
    switch (pubkey_display) {
        case PubkeyDisplayLong:
        case PubkeyDisplayShort:
            value = (uint8_t) pubkey_display;
            nvm_write((void *)&N_storage.settings.pubkey_display, &value, sizeof(value));
            break;
    }
    ui_idle();
}

const char* const pubkey_display_data_getter_values[] = {
  "Long",
  "Short",
  "Back"
};

static const char* pubkey_display_data_getter(unsigned int idx) {
  if (idx < ARRAYLEN(pubkey_display_data_getter_values)) {
    return pubkey_display_data_getter_values[idx];
  }
  return NULL;
}

static void pubkey_display_data_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      pubkey_display_data_change(PubkeyDisplayLong);
      break;
    case 1:
      pubkey_display_data_change(PubkeyDisplayShort);
      break;
    default:
      ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector);
  }
}

//////////////////////////////////////////////////////////////////////////////////////
// Settings menu:

const char* const settings_submenu_getter_values[] = {
  "Allow blind sign",
  "Pubkey display",
  "Back",
};

const char* settings_submenu_getter(unsigned int idx) {
  if (idx < ARRAYLEN(settings_submenu_getter_values)) {
    return settings_submenu_getter_values[idx];
  }
  return NULL;
}

void settings_submenu_selector(unsigned int idx) {
  switch(idx) {
    case 0:
      ux_menulist_init_select(0, allow_blind_sign_data_getter, allow_blind_sign_data_selector, N_storage.settings.allow_blind_sign);
      break;
    case 1:
      ux_menulist_init_select(0, pubkey_display_data_getter, pubkey_display_data_selector, N_storage.settings.pubkey_display);
      break;
    default:
      ui_idle();
  }
}

//////////////////////////////////////////////////////////////////////
UX_STEP_NOCB(
  ux_idle_flow_1_step,
  pnn,
  {
    &C_solana_logo,
    "Application",
    "is ready",
  });
UX_STEP_VALID(
    ux_idle_flow_2_step,
    pb,
    ux_menulist_init(0, settings_submenu_getter, settings_submenu_selector),
    {
        &C_icon_coggle,
        "Settings",
    });
UX_STEP_NOCB(
  ux_idle_flow_3_step,
  bn,
  {
    "Version",
    APPVERSION,
  });
UX_STEP_VALID(
  ux_idle_flow_4_step,
  pb,
  os_sched_exit(-1),
  {
    &C_icon_dashboard_x,
    "Quit",
  });
UX_FLOW(ux_idle_flow,
  &ux_idle_flow_1_step,
  &ux_idle_flow_2_step,
  &ux_idle_flow_3_step,
  &ux_idle_flow_4_step,
  FLOW_LOOP
);

void ui_idle(void) {
  // reserve a display stack slot if none yet
  if(G_ux.stack_count == 0) {
    ux_stack_push();
  }
  ux_flow_init(0, ux_idle_flow, NULL);
}
