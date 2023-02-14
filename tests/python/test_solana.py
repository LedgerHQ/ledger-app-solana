from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID
from ragger.utils import RAPDU

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, SOL_PACKED_DERIVATION_PATH_2

from .utils import ROOT_SCREENSHOT_PATH

def test_solana_simple_transfer_ok_1(backend, navigator, test_name):
    sol = SolanaClient(backend)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

    # Create instruction
    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
    message: bytes = Message([instruction]).serialize()

    with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                  [NavInsID.BOTH_CLICK],
                                                  "Approve",
                                                  ROOT_SCREENSHOT_PATH,
                                                  test_name)

    signature: bytes = sol.get_async_response().data

    verify_signature(from_public_key, message, signature)


def test_solana_simple_transfer_ok_2(backend, navigator, test_name):
    sol = SolanaClient(backend)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

    # Create instruction
    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
    message: bytes = Message([instruction]).serialize()

    with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
        navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                  [NavInsID.BOTH_CLICK],
                                                  "Approve",
                                                  ROOT_SCREENSHOT_PATH,
                                                  test_name)

    signature: bytes = sol.get_async_response().data

    verify_signature(from_public_key, message, signature)


def test_solana_simple_transfer_refused(backend, navigator, test_name):
    sol = SolanaClient(backend)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
    message: bytes = Message([instruction]).serialize()

    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
        navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                  [NavInsID.BOTH_CLICK],
                                                  "Reject",
                                                  ROOT_SCREENSHOT_PATH,
                                                  test_name)

    rapdu: RAPDU = sol.get_async_response()
    assert rapdu.status == ErrorType.USER_CANCEL


def test_solana_blind_sign_refused(backend):
    sol = SolanaClient(backend)
    from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

    instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
    message: bytes = Message([instruction]).serialize()

    backend.raise_policy = RaisePolicy.RAISE_NOTHING
    rapdu: RAPDU = sol.send_blind_sign_message(SOL_PACKED_DERIVATION_PATH, message)
    assert rapdu.status == ErrorType.SDK_NOT_SUPPORTED

