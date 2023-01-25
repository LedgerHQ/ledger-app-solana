import base58

from ragger.bip import pack_derivation_path
from ragger.utils import create_currency_config

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
