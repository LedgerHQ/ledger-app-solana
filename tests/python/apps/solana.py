from typing import List, Generator
from enum import IntEnum
from contextlib import contextmanager

from ragger.backend.interface import BackendInterface, RAPDU


class INS(IntEnum):
    # DEPRECATED - Use non "16" suffixed variants below
    INS_GET_APP_CONFIGURATION16 = 0x01
    INS_GET_PUBKEY16 = 0x02
    INS_SIGN_MESSAGE16 = 0x03
    # END DEPRECATED
    INS_GET_APP_CONFIGURATION = 0x04
    INS_GET_PUBKEY = 0x05
    INS_SIGN_MESSAGE = 0x06
    INS_SIGN_OFFCHAIN_MESSAGE = 0x07


CLA = 0xE0

P1_NON_CONFIRM = 0x00
P1_CONFIRM = 0x01

P2_NONE = 0x00
P2_EXTEND = 0x01
P2_MORE = 0x02

PUBLIC_KEY_LENGTH = 32

MAX_CHUNK_SIZE = 255

STATUS_OK = 0x9000


class ErrorType:
    NO_APP_RESPONSE = 0x6700
    SDK_EXCEPTION = 0x6801
    SDK_INVALID_PARAMETER = 0x6802
    SDK_EXCEPTION_OVERFLOW = 0x6803
    SDK_EXCEPTION_SECURITY = 0x6804
    SDK_INVALID_CRC = 0x6805
    SDK_INVALID_CHECKSUM = 0x6806
    SDK_INVALID_COUNTER = 0x6807
    SDK_NOT_SUPPORTED = 0x6808
    SDK_INVALID_STATE = 0x6809
    SDK_TIMEOUT = 0x6810
    SDK_EXCEPTION_PIC = 0x6811
    SDK_EXCEPTION_APP_EXIT = 0x6812
    SDK_EXCEPTION_IO_OVERFLOW = 0x6813
    SDK_EXCEPTION_IO_HEADER = 0x6814
    SDK_EXCEPTION_IO_STATE = 0x6815
    SDK_EXCEPTION_IO_RESET = 0x6816
    SDK_EXCEPTION_CX_PORT = 0x6817
    SDK_EXCEPTION_SYSTEM = 0x6818
    SDK_NOT_ENOUGH_SPACE = 0x6819
    NO_APDU_RECEIVED = 0x6982
    USER_CANCEL = 0x6985
    SOLANA_INVALID_MESSAGE = 0x6a80
    SOLANA_SUMMARY_FINALIZE_FAILED = 0x6f00
    SOLANA_SUMMARY_UPDATE_FAILED = 0x6f01
    UNIMPLEMENTED_INSTRUCTION = 0x6d00
    INVALID_CLA = 0x6e00


def _extend_and_serialize_multiple_derivations_paths(derivations_paths: List[bytes]):
    serialized: bytes = len(derivations_paths).to_bytes(1, byteorder='little')
    for derivations_path in derivations_paths:
        serialized += derivations_path
    return serialized


class SolanaClient:
    client: BackendInterface

    def __init__(self, client: BackendInterface):
        self._client = client


    def get_public_key(self, derivation_path: bytes) -> bytes:
        public_key: RAPDU = self._client.exchange(CLA, INS.INS_GET_PUBKEY,
                                                  P1_NON_CONFIRM, P2_NONE,
                                                  derivation_path)
        assert len(public_key.data) == PUBLIC_KEY_LENGTH, "'from' public key size incorrect"
        return public_key.data


    @contextmanager
    def send_public_key_with_confirm(self, derivation_path: bytes) -> bytes:
        with self._client.exchange_async(CLA, INS.INS_GET_PUBKEY,
                                         P1_CONFIRM, P2_NONE,
                                         derivation_path):
            yield


    def split_and_prefix_message(self, derivation_path : bytes, message: bytes) -> List[bytes]:
        assert len(message) <= 65535, "Message to send is too long"
        header: bytes = _extend_and_serialize_multiple_derivations_paths([derivation_path])
        # Check to see if this data needs to be split up and sent in chunks.
        max_size = MAX_CHUNK_SIZE - len(header)
        message_splited = [message[x:x + max_size] for x in range(0, len(message), max_size)]
        # Add the header to every chunk
        return [header + s for s in message_splited]


    def send_first_message_batch(self, ins: INS, messages: List[bytes], p1: int) -> RAPDU:
        self._client.exchange(CLA, ins, p1, P2_MORE, messages[0])
        for m in messages[1:]:
            self._client.exchange(CLA, ins, p1, P2_MORE | P2_EXTEND, m)


    @contextmanager
    def send_async_sign_request(self,
                                ins: INS,
                                derivation_path : bytes,
                                message: bytes) -> Generator[None, None, None]:
        message_splited_prefixed = self.split_and_prefix_message(derivation_path, message)

        # Send all chunks with P2_MORE except for the last chunk
        # Send all chunks with P2_EXTEND except for the first chunk
        if len(message_splited_prefixed) > 1:
            final_p2 = P2_EXTEND
            self.send_first_message_batch(ins, message_splited_prefixed[:-1], P1_CONFIRM)
        else:
            final_p2 = 0

        with self._client.exchange_async(CLA,
                                         ins,
                                         P1_CONFIRM,
                                         final_p2,
                                         message_splited_prefixed[-1]):
            yield


    @contextmanager
    def send_async_sign_message(self,
                                derivation_path : bytes,
                                message: bytes) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_MESSAGE, derivation_path, message):
            yield


    @contextmanager
    def send_async_sign_offchain_message(self,
                                         derivation_path : bytes,
                                         message: bytes) -> Generator[None, None, None]:
        with self.send_async_sign_request(INS.INS_SIGN_OFFCHAIN_MESSAGE, derivation_path, message):
            yield


    def get_async_response(self) -> RAPDU:
        return self._client.last_async_response
