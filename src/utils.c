#include "os.h"
#include "cx.h"
#include <stdlib.h>
#include "utils.h"

void get_public_key(uint8_t *publicKeyArray, const uint32_t *derivationPath, size_t pathLength) {
    cx_ecfp_private_key_t privateKey;
    cx_ecfp_public_key_t publicKey;

    get_private_key(&privateKey, derivationPath, pathLength);
    BEGIN_TRY {
        TRY {
            cx_ecfp_generate_pair(CX_CURVE_Ed25519, &publicKey, &privateKey, 1);
        }
        CATCH_OTHER(e) {
            MEMCLEAR(privateKey);
            THROW(e);
        }
        FINALLY {
            MEMCLEAR(privateKey);
        }
    }
    END_TRY;

    for (int i = 0; i < PUBKEY_LENGTH; i++) {
        publicKeyArray[i] = publicKey.W[PUBKEY_LENGTH + PRIVATEKEY_LENGTH - i];
    }
    if ((publicKey.W[PUBKEY_LENGTH] & 1) != 0) {
        publicKeyArray[PUBKEY_LENGTH - 1] |= 0x80;
    }
}

int get_pubkey_index(const Pubkey* needle, const Pubkey* haystack, size_t haystack_len, size_t* index) {
    for (size_t i = 0; i < haystack_len; ++i) {
        const Pubkey *current_pubkey = &(haystack[i]);
        if (memcmp(current_pubkey, needle, PUBKEY_SIZE) == 0) {
            *index = i;
            return 0;
        }
    }
    return -1;
}

uint32_t readUint32BE(uint8_t *buffer) {
    return ((buffer[0] << 24) | (buffer[1] << 16) | (buffer[2] << 8) | (buffer[3]));
}

void get_private_key(cx_ecfp_private_key_t *privateKey,
                     const uint32_t *derivationPath,
                     size_t pathLength) {
    uint8_t privateKeyData[PRIVATEKEY_LENGTH];
    BEGIN_TRY {
        TRY {
            os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10,
                                                CX_CURVE_Ed25519,
                                                derivationPath,
                                                pathLength,
                                                privateKeyData,
                                                NULL,
                                                NULL,
                                                0);
            cx_ecfp_init_private_key(CX_CURVE_Ed25519,
                                     privateKeyData,
                                     PRIVATEKEY_LENGTH,
                                     privateKey);
        }
        CATCH_OTHER(e) {
            MEMCLEAR(privateKeyData);
            THROW(e);
        }
        FINALLY {
            MEMCLEAR(privateKeyData);
        }
    }
    END_TRY;
}

void get_private_key_with_seed(cx_ecfp_private_key_t *privateKey,
                               const uint32_t *derivationPath,
                               uint8_t pathLength) {
    uint8_t privateKeyData[PRIVATEKEY_LENGTH];
    BEGIN_TRY {
        TRY {
            os_perso_derive_node_bip32_seed_key(HDW_ED25519_SLIP10,
                                                CX_CURVE_Ed25519,
                                                derivationPath,
                                                pathLength,
                                                privateKeyData,
                                                NULL,
                                                (unsigned char *) "ed25519 seed",
                                                12);
            cx_ecfp_init_private_key(CX_CURVE_Ed25519,
                                     privateKeyData,
                                     PRIVATEKEY_LENGTH,
                                     privateKey);
        }
        CATCH_OTHER(e) {
            MEMCLEAR(privateKeyData);
            THROW(e);
        }
        FINALLY {
            MEMCLEAR(privateKeyData);
        }
    }
    END_TRY;
}

int read_derivation_path(const uint8_t *data_buffer,
                         size_t data_size,
                         uint32_t *derivation_path,
                         uint32_t *derivation_path_length) {
    if (!data_buffer || !derivation_path || !derivation_path_length) {
        return ApduReplySdkInvalidParameter;
    }
    if (!data_size) {
        return ApduReplySolanaInvalidMessageSize;
    }
    const size_t len = data_buffer[0];
    data_buffer += 1;
    if (len < 1 || len > MAX_BIP32_PATH_LENGTH) {
        return ApduReplySolanaInvalidMessage;
    }
    if (1 + 4 * len > data_size) {
        return ApduReplySolanaInvalidMessageSize;
    }

    for (size_t i = 0; i < len; i++) {
        derivation_path[i] = ((data_buffer[0] << 24u) | (data_buffer[1] << 16u) |
                              (data_buffer[2] << 8u) | (data_buffer[3]));
        data_buffer += 4;
    }

    *derivation_path_length = len;

    return 0;
}

uint8_t set_result_sign_message(void) {
    uint8_t signature[SIGNATURE_LENGTH];
    cx_ecfp_private_key_t privateKey;
    BEGIN_TRY {
        TRY {
            get_private_key_with_seed(&privateKey,
                                      G_command.derivation_path,
                                      G_command.derivation_path_length);
            cx_eddsa_sign(&privateKey,
                          CX_LAST,
                          CX_SHA512,
                          G_command.message,
                          G_command.message_length,
                          NULL,
                          0,
                          signature,
                          SIGNATURE_LENGTH,
                          NULL);
            memcpy(G_io_apdu_buffer, signature, SIGNATURE_LENGTH);
        }
        CATCH_OTHER(e) {
            THROW(e);
        }
        FINALLY {
            MEMCLEAR(privateKey);
        }
    }
    END_TRY;
    return SIGNATURE_LENGTH;
}
