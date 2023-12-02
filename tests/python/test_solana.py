from ragger.backend import RaisePolicy
from ragger.navigator import NavInsID, NavIns
from ragger.utils import RAPDU
import base58

from .apps.solana import SolanaClient, ErrorType
from .apps.solana_cmd_builder import SystemInstructionTransfer, Message, verify_signature, OffchainMessage, \
    ComputeBudgetInstructionUnitLimit, ComputeBudgetSetComputeUnitPrice, MessageFormat, PROGRAM_ID_SYSTEM
from .apps.solana_utils import FOREIGN_PUBLIC_KEY, FOREIGN_PUBLIC_KEY_2, AMOUNT, AMOUNT_2, SOL_PACKED_DERIVATION_PATH, \
    SOL_PACKED_DERIVATION_PATH_2, ROOT_SCREENSHOT_PATH, COMPUTE_BUDGET_UNIT_LIMIT, COMPUTE_BUDGET_UNIT_PRICE
from .apps.solana_utils import enable_blind_signing, enable_short_public_key, enable_expert_mode, navigation_helper_confirm, navigation_helper_reject


class TestGetPublicKey:

    def test_solana_get_public_key_ok(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            if backend.firmware.device.startswith("nano"):
                navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                          [NavInsID.BOTH_CLICK],
                                                          "Approve",
                                                          ROOT_SCREENSHOT_PATH,
                                                          test_name)
            else:
                instructions = [
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CONFIRM,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                               test_name,
                                               instructions)

        assert sol.get_async_response().data == from_public_key

    def test_solana_get_public_key_refused(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        with sol.send_public_key_with_confirm(SOL_PACKED_DERIVATION_PATH):
            backend.raise_policy = RaisePolicy.RAISE_NOTHING
            if backend.firmware.device.startswith("nano"):
                navigator.navigate_until_text_and_compare(NavInsID.RIGHT_CLICK,
                                                          [NavInsID.BOTH_CLICK],
                                                          "Reject",
                                                          ROOT_SCREENSHOT_PATH,
                                                          test_name)
            else:
                instructions = [
                    NavInsID.USE_CASE_REVIEW_TAP,
                    NavInsID.USE_CASE_ADDRESS_CONFIRMATION_CANCEL,
                    NavInsID.USE_CASE_STATUS_DISMISS
                ]
                navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH,
                                               test_name,
                                               instructions)

        assert sol.get_async_response().status == ErrorType.USER_CANCEL


class TestComputeBudgetTransfer:

    def test_solana_transfer_with_compute_budget_limit_ok_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction_unit_limit = ComputeBudgetInstructionUnitLimit(COMPUTE_BUDGET_UNIT_LIMIT)
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction_unit_limit, instruction]).serialize()


        # Displayed data and transfer amount should not change
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_solana_transfer_with_compute_budget_limit_refused_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction_unit_limit = ComputeBudgetInstructionUnitLimit(COMPUTE_BUDGET_UNIT_LIMIT)
        instruction_unit_price = ComputeBudgetSetComputeUnitPrice(COMPUTE_BUDGET_UNIT_PRICE)
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction_unit_limit, instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_solana_transfer_with_compute_budget_limit_and_unit_price_refused_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction_unit_limit = ComputeBudgetInstructionUnitLimit(COMPUTE_BUDGET_UNIT_LIMIT)
        instruction_unit_price = ComputeBudgetSetComputeUnitPrice(COMPUTE_BUDGET_UNIT_PRICE)
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction_unit_price, instruction_unit_limit, instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_solana_transfer_with_compute_budget_limit_and_unit_price_ok_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction_unit_limit = ComputeBudgetInstructionUnitLimit(COMPUTE_BUDGET_UNIT_LIMIT)
        instruction_unit_price = ComputeBudgetSetComputeUnitPrice(COMPUTE_BUDGET_UNIT_PRICE)
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction_unit_price, instruction_unit_limit, instruction]).serialize()

        # Displayed data and transfer amount should not change
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_solana_transfer_with_compute_budget_limit_and_unit_price_ok_2(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction_unit_limit = ComputeBudgetInstructionUnitLimit(230000)
        instruction_unit_price = ComputeBudgetSetComputeUnitPrice(12546)
        # Prioritization fee should be equal to 2886 lamports
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction_unit_price, instruction_unit_limit, instruction]).serialize()

        # Displayed data and transfer amount should not change
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)


class TestMessageSigning:

    def test_solana_simple_transfer_ok_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_solana_simple_transfer_ok_2(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH_2)

        # Create instruction
        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY_2, AMOUNT_2)
        message: bytes = Message([instruction]).serialize()

        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH_2, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_solana_simple_transfer_refused(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        instruction: SystemInstructionTransfer = SystemInstructionTransfer(from_public_key, FOREIGN_PUBLIC_KEY, AMOUNT)
        message: bytes = Message([instruction]).serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL


class TestOffchainMessageSigning:
#
    def test_ledger_sign_offchain_message_ascii_ok(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_ascii_refused(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_ascii_expert_ok_1(self, backend, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_init")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_ascii_expert_refused_1(self, backend, navigator, test_name):
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_init")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_utf8_ok_1(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_init")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.LimitedUtf8, [from_public_key])
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_utf8_refused_1(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_init")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.LimitedUtf8, [from_public_key])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_utf8_expert_ok_2(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_init_1")
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_init_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.LimitedUtf8, [from_public_key])
        message: bytes = offchain_message.serialize()

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_confirm(navigator, backend.firmware.device, test_name)

        signature: bytes = sol.get_async_response().data
        verify_signature(from_public_key, message, signature)

    def test_ledger_sign_offchain_message_utf8_expert_refused(self, backend, navigator, test_name):
        enable_blind_signing(navigator, backend.firmware.device, test_name + "_init_1")
        enable_expert_mode(navigator, backend.firmware.device, test_name + "_init_2")

        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.LimitedUtf8, [from_public_key])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING
        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            navigation_helper_reject(navigator, backend.firmware.device, test_name)

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.USER_CANCEL

    def test_ledger_sign_offchain_message_invalid_message_format_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Using unsupported message format
        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.ExtendedUtf8, [from_public_key])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            pass

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.REPLY_SOLANA_INVALID_MESSAGE_HEADER

    def test_ledger_sign_offchain_empty_message_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        # Using unsupported message format
        offchain_message: OffchainMessage = OffchainMessage(bytes(), FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            pass

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.REPLY_SOLANA_INVALID_MESSAGE_HEADER

    def test_ledger_sign_offchain_empty_signers_list_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [])
        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            pass

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.REPLY_SOLANA_INVALID_MESSAGE_HEADER

    def test_ledger_sign_offchain_invalid_header_version_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(b"Test message", FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])

        # Invalid header version
        offchain_message.version = 1

        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            pass

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.REPLY_SOLANA_INVALID_MESSAGE_HEADER

    def test_ledger_sign_offchain_message_too_long_1(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        message = b"Some very long message" * 70  # 1540 bytes

        offchain_message: OffchainMessage = OffchainMessage(message, FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.RestrictedAscii, [from_public_key])

        message: bytes = offchain_message.serialize()

        backend.raise_policy = RaisePolicy.RAISE_NOTHING

        with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
            pass

        rapdu: RAPDU = sol.get_async_response()
        assert rapdu.status == ErrorType.SOLANA_INVALID_MESSAGE

    def test_ledger_sign_offchain_message_utf8_blind_sign_not_enabled(self, backend, navigator, test_name):
        sol = SolanaClient(backend)
        from_public_key = sol.get_public_key(SOL_PACKED_DERIVATION_PATH)

        offchain_message: OffchainMessage = OffchainMessage(bytes("Тестовое сообщение", 'utf-8'), FOREIGN_PUBLIC_KEY,
                                                            MessageFormat.LimitedUtf8, [from_public_key])
        message: bytes = offchain_message.serialize()

        try:
            with sol.send_async_sign_offchain_message(SOL_PACKED_DERIVATION_PATH, message):
                pass

            rapdu: RAPDU = sol.get_async_response()
            assert rapdu.status == ErrorType.SDK_NOT_SUPPORTED
        except:
            pass


