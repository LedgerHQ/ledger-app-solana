from time import sleep
import base58

from ragger.backend.interface import RAPDU, RaisePolicy

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, SOL_PACKED_DERIVATION_PATH_2

def test_solana_simple_transfer_ok_1(client, firmware):
    sol = SolanaClient(client)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

    # Create instruction
    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
    message: bytes = Message([instruction]).serialize()

    with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        sol.validate_sign_message()
    signature: bytes = sol.get_async_response().data

    verify_signature(from_public_key, message, signature)

    sleep(0.1)


def test_solana_simple_transfer_ok_2(client, firmware):
    sol = SolanaClient(client)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

    # Create instruction
    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
    message: bytes = Message([instruction]).serialize()

    with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
        sol.validate_sign_message()
    signature: bytes = sol.get_async_response().data

    verify_signature(from_public_key, message, signature)

    sleep(0.1)


def test_solana_simple_transfer_refused(client, firmware):
    sol = SolanaClient(client)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
    message: bytes = Message([instruction]).serialize()

    with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        client.raise_policy = RaisePolicy.RAISE_NOTHING
        sol.refuse_to_sign_message()

    rapdu: RAPDU = sol.get_async_response()
    assert rapdu.status == ErrorType.USER_CANCEL

    sleep(0.1)


def test_solana_blind_sign_refused(client, firmware):
    sol = SolanaClient(client)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
    message: bytes = Message([instruction]).serialize()

    client.raise_policy = RaisePolicy.RAISE_NOTHING
    rapdu: RAPDU = sol.send_blind_sign_message(SOL_PACKED_DERIVATION_PATH, message)
    assert rapdu.status == ErrorType.USER_CANCEL

    sleep(0.1)
