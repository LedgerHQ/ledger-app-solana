#pragma once
#include <stdint.h>

static const uint8_t TRUSTED_NAME_PUB_KEY[] = {
#ifdef HAVE_TRUSTED_NAME_TEST_KEY
    0x04, 0xb9, 0x1f, 0xbe, 0xc1, 0x73, 0xe3, 0xba, 0x4a, 0x71, 0x4e, 0x01, 0x4e, 0xbc,
    0x82, 0x7b, 0x6f, 0x89, 0x9a, 0x9f, 0xa7, 0xf4, 0xac, 0x76, 0x9c, 0xde, 0x28, 0x43,
    0x17, 0xa0, 0x0f, 0x4f, 0x65, 0x0f, 0x09, 0xf0, 0x9a, 0xa4, 0xff, 0x5a, 0x31, 0x76,
    0x02, 0x55, 0xfe, 0x5d, 0xfc, 0x81, 0x13, 0x29, 0xb3, 0xb5, 0x0b, 0xe9, 0x91, 0x94,
    0xfc, 0xa1, 0x16, 0x19, 0xe6, 0x5f, 0x2e, 0xdf, 0xea
#else
    0x04, 0x6a, 0x94, 0xe7, 0xa4, 0x2c, 0xd0, 0xc3, 0x3f, 0xdf, 0x44, 0x0c, 0x8e, 0x2a,
    0xb2, 0x54, 0x2c, 0xef, 0xbe, 0x5d, 0xb7, 0xaa, 0x0b, 0x93, 0xa9, 0xfc, 0x81, 0x4b,
    0x9a, 0xcf, 0xa7, 0x5e, 0xb4, 0xe5, 0x3d, 0x6f, 0x00, 0x25, 0x94, 0xbd, 0xb6, 0x05,
    0xd9, 0xb5, 0xbd, 0xa9, 0xfa, 0x4b, 0x4b, 0xf3, 0xa5, 0x49, 0x6f, 0xd3, 0x16, 0x4b,
    0xae, 0xf5, 0xaf, 0xcf, 0x90, 0xe8, 0x40, 0x88, 0x71
#endif
};

extern int check_signature_with_pubkey(const char *tag,
                                       uint8_t *buffer,
                                       const uint8_t bufLen,
                                       const uint8_t *PubKey,
                                       const uint8_t keyLen,
#ifdef HAVE_LEDGER_PKI
                                       const uint8_t keyUsageExp,
#endif
                                       uint8_t *signature,
                                       const uint8_t sigLen);