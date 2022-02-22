#include "os.h"
#include "ux.h"
#include "os_io_seproxyhal.h"

#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#define P1_CONFIRM 0x01
#define P1_NON_CONFIRM 0x00

#define P2_EXTEND 0x01
#define P2_MORE 0x02

#define ROUND_TO_NEXT(x, next) \
    (((x) == 0) ? 0 : ((((x - 1) / (next)) + 1) * (next)))

/* See constant by same name in sdk/src/packet.rs */
#define PACKET_DATA_SIZE (1280 - 40 - 8)

#define MAX_MESSAGE_LENGTH ROUND_TO_NEXT(PACKET_DATA_SIZE, USB_SEGMENT_SIZE)
#define SIGNATURE_LENGTH 64
#define HASH_LENGTH 32
#define PUBKEY_LENGTH HASH_LENGTH
#define BIP32_PATH 5

enum ApduReply {
    /* ApduReplySdk* come from nanos-secure-sdk/include/os.h.  Here we add the
     * 0x68__ prefix that app_main() ORs into those values before sending them
     * over the wire
     */
    ApduReplySdkException                 = 0x6801,
    ApduReplySdkInvalidParameter          = 0x6802,
    ApduReplySdkExceptionOverflow         = 0x6803,
    ApduReplySdkExceptionSecurity         = 0x6804,
    ApduReplySdkInvalidCrc                = 0x6805,
    ApduReplySdkInvalidChecksum           = 0x6806,
    ApduReplySdkInvalidCounter            = 0x6807,
    ApduReplySdkNotSupported              = 0x6808,
    ApduReplySdkInvalidState              = 0x6809,
    ApduReplySdkTimeout                   = 0x6810,
    ApduReplySdkExceptionPIC              = 0x6811,
    ApduReplySdkExceptionAppExit          = 0x6812,
    ApduReplySdkExceptionIoOverflow       = 0x6813,
    ApduReplySdkExceptionIoHeader         = 0x6814,
    ApduReplySdkExceptionIoState          = 0x6815,
    ApduReplySdkExceptionIoReset          = 0x6816,
    ApduReplySdkExceptionCxPort           = 0x6817,
    ApduReplySdkExceptionSystem           = 0x6818,
    ApduReplySdkNotEnoughSpace            = 0x6819,

    ApduReplyNoApduReceived               = 0x6982,

    ApduReplyVelasInvalidMessage         = 0x6a80,
    ApduReplyVelasSummaryFinalizeFailed  = 0x6f00,
    ApduReplyVelasSummaryUpdateFailed    = 0x6f01,

    ApduReplyUnimplementedInstruction     = 0x6d00,
    ApduReplyInvalidCla                   = 0x6e00,

    ApduReplySuccess                      = 0x9000,
};

extern ux_state_t ux;
// display stepped screens
extern unsigned int ux_step;
extern unsigned int ux_step_count;

enum BlindSign {
    BlindSignDisabled = 0,
    BlindSignEnabled = 1,
};

enum PubkeyDisplay {
    PubkeyDisplayLong = 0,
    PubkeyDisplayShort = 1,
};

typedef struct AppSettings {
    uint8_t allow_blind_sign;
    uint8_t pubkey_display;
} AppSettings;

typedef struct internalStorage_t {
    AppSettings settings;
    uint8_t initialized;
} internalStorage_t;

extern const internalStorage_t N_storage_real;
#define N_storage (*(volatile internalStorage_t*) PIC(&N_storage_real))
#endif
