import base58
from pathlib import Path

from ragger.navigator import NavInsID, NavIns
from ragger.utils import create_currency_config
from ragger.bip import pack_derivation_path

ROOT_SCREENSHOT_PATH = Path(__file__).parent.parent.resolve()

### Some utilities functions for amounts conversions ###

def sol_to_lamports(sol_amount: int) -> int:
    return round(sol_amount * 10**9)


def lamports_to_bytes(lamports: int) -> str:
    hex:str = '{:x}'.format(lamports)
    if (len(hex) % 2 != 0):
        hex = "0" + hex
    return bytes.fromhex(hex)


### Proposed values for fees and amounts ###

AMOUNT          = sol_to_lamports(2.078)
AMOUNT_BYTES    = lamports_to_bytes(AMOUNT)

AMOUNT_2        = sol_to_lamports(101.000001234)
AMOUNT_2_BYTES  = lamports_to_bytes(AMOUNT_2)

FEES            = sol_to_lamports(0.00000564)
FEES_BYTES      = lamports_to_bytes(FEES)


### Proposed foreign and owned addresses ###

# "Foreign" Solana public key (actually the device public key derived on m/44'/501'/11111')
FOREIGN_ADDRESS     = b"AxmUF3qkdz1zs151Q5WttVMkFpFGQPwghZs4d1mwY55d"
FOREIGN_PUBLIC_KEY  = base58.b58decode(FOREIGN_ADDRESS)

# "Foreign" Solana public key (actually the device public key derived on m/44'/501'/11112')
FOREIGN_ADDRESS_2       = b"8bjDMujLMttbmkTtoFgfw2sPYchSzzcTCEPGYDaNs3nj"
FOREIGN_PUBLIC_KEY_2    = base58.b58decode(FOREIGN_ADDRESS_2)

# Device Solana public key (derived on m/44'/501'/12345')
OWNED_ADDRESS       = b"3GJzvStsiYZonWE7WTsmt1BpWXkfcgWMGinaDwNs9HBc"
OWNED_PUBLIC_KEY    = base58.b58decode(OWNED_ADDRESS)


### Proposed Solana derivation paths for tests ###

SOL_PACKED_DERIVATION_PATH      = pack_derivation_path("m/44'/501'/12345'")
SOL_PACKED_DERIVATION_PATH_2    = pack_derivation_path("m/44'/501'/0'/0'")


### Package this currency configuration in exchange format ###

SOL_CONF = create_currency_config("SOL", "Solana")


def enable_blind_signing(navigator, device_name: str, snapshots_name: str):
    if device_name.startswith("nano"):
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.BOTH_CLICK, # Select blind signing
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Enable
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    else:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
           NavIns(NavInsID.TOUCH, (348,132)),
           NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def enable_short_public_key(navigator, device_name: str, snapshots_name: str):
    if device_name.startswith("nano"):
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select public key length
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # short
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    else:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
           NavIns(NavInsID.TOUCH, (348,251)),
           NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def enable_expert_mode(navigator, device_name: str, snapshots_name: str):
    if device_name.startswith("nano"):
        nav = [NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Go to settings
               NavInsID.RIGHT_CLICK, NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # Select Expert mode
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK, # expert
               NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK # Back to main menu
              ]
    else:
        nav = [NavInsID.USE_CASE_HOME_SETTINGS,
           NavIns(NavInsID.TOUCH, (348,382)),
           NavInsID.USE_CASE_SETTINGS_MULTI_PAGE_EXIT]
    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                   snapshots_name,
                                   nav,
                                   screen_change_before_first_instruction=False)

def _navigation_helper(navigator, device_name: str, accept: bool, snapshots_name: str):
    if device_name.startswith("nano"):
        navigate_instruction = NavInsID.RIGHT_CLICK
        validation_instructions = [NavInsID.BOTH_CLICK]
        if accept:
            text = "Approve"
        else:
            text = "Reject"
    else:
        navigate_instruction = NavInsID.USE_CASE_REVIEW_TAP
        text = "Hold to sign"
        if accept:
            validation_instructions = [NavInsID.USE_CASE_REVIEW_CONFIRM]
        else:
            validation_instructions = [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM]


    navigator.navigate_until_text_and_compare(navigate_instruction,
                                              validation_instructions,
                                              text,
                                              ROOT_SCREENSHOT_PATH,
                                              snapshots_name)

def navigation_helper_confirm(navigator, device_name: str, snapshots_name: str):
    _navigation_helper(navigator=navigator, device_name=device_name, accept=True, snapshots_name=snapshots_name)

def navigation_helper_reject(navigator, device_name: str, snapshots_name: str):
    _navigation_helper(navigator=navigator, device_name=device_name, accept=False, snapshots_name=snapshots_name)
