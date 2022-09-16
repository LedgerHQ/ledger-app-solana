from typing import Optional, Tuple
from pathlib import Path
from bip32 import HARDENED_INDEX
from enum import IntEnum

from ragger.backend import SpeculosBackend

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def app_path_from_app_name(app_dir, app_name: str, device: str) -> Path:
    assert app_dir.is_dir(), f"{app_dir} is not a directory"
    app_path = app_dir / (app_name + "_" + device + ".elf")
    assert app_path.is_file(), f"{app_path} must exist"
    return app_path

def prefix_with_len(to_prefix: bytes) -> bytes:
    return len(to_prefix).to_bytes(1, byteorder="big") + to_prefix

def validate_displayed_message(client: SpeculosBackend, num_screen_skip: int):
    for _ in range(num_screen_skip):
        client.right_click()
    client.both_click()

# DERIVATION PATHS CALCULATIONS

class BtcDerivationPathFormat(IntEnum):
    LEGACY      = 0x00
    P2SH        = 0x01
    BECH32      = 0x02
    CASHADDR    = 0x03 # Deprecated
    BECH32M     = 0x04

def pack_derivation_path(derivation_path: str) -> bytes:
    split = derivation_path.split("/")
    assert split.pop(0) == "m", "master expected"
    derivation_path: bytes = (len(split)).to_bytes(1, byteorder='big')
    for i in split:
        if (i[-1] == "'"):
            derivation_path += (int(i[:-1]) | HARDENED_INDEX).to_bytes(4, byteorder='big')
        else:
            derivation_path += int(i).to_bytes(4, byteorder='big')
    return derivation_path

def bitcoin_pack_derivation_path(format: BtcDerivationPathFormat, derivation_path: str) -> bytes:
    assert isinstance(format, BtcDerivationPathFormat)
    return format.to_bytes(1, "big") + pack_derivation_path(derivation_path)


# CURRENCY CONFIG CALCULATIONS

def create_currency_config(main_ticker: str, application_name: str, sub_coin_config: Optional[Tuple[str, int]] = None) -> bytes:
    sub_config: bytes = b""
    if sub_coin_config is not None:
        sub_config = prefix_with_len(sub_coin_config[0].encode()) + sub_coin_config[1].to_bytes(1, byteorder="big")
    coin_config: bytes = b""
    for element in [main_ticker.encode(), application_name.encode(), sub_config]:
        coin_config += prefix_with_len(element)
    return coin_config
