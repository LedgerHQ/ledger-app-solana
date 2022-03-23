/*******************************************************************************
*   Ledger Blue
*   (c) 2016 Ledger
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "utils.h"
#include "getPubkey.h"
#include "signMessage.h"
#include "menu.h"
#include <assert.h>

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

#define CLA 0xE0

// DEPRECATED - Use non "16" suffixed variants below
#define INS_GET_APP_CONFIGURATION16 0x01
#define INS_GET_PUBKEY16            0x02
#define INS_SIGN_MESSAGE16          0x03
#define OFFSET_CDATA16 6
// END DEPRECATED

#define INS_GET_APP_CONFIGURATION   0x04
#define INS_GET_PUBKEY              0x05
#define INS_SIGN_MESSAGE            0x06

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_CDATA 5

void handleApdu(volatile unsigned int *flags, volatile unsigned int *tx, int rx) {
    unsigned short sw = 0;

    assert(rx >= 0 && rx <= UINT16_MAX);

    BEGIN_TRY {
        TRY {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(ApduReplyInvalidCla);
            }

            int dataLength;
            uint8_t* dataBuffer;
            switch (G_io_apdu_buffer[OFFSET_INS]) {
                // Handle deprecated instructions expecting a 16bit dataLength
                case INS_GET_APP_CONFIGURATION16:
                case INS_GET_PUBKEY16:
                case INS_SIGN_MESSAGE16:
                    if (    rx < OFFSET_CDATA16
                        ||  ((uint16_t)rx != U2BE(G_io_apdu_buffer, OFFSET_LC) + OFFSET_CDATA16)
                    ) {
                        THROW(ApduReplySdkExceptionOverflow);
                    }
                    dataLength = U2BE(G_io_apdu_buffer, OFFSET_LC);
                    dataBuffer = &G_io_apdu_buffer[OFFSET_CDATA16];
                    break;
                // Modern instructions use 8bit dataLength
                // as per Ledger convention
                default:
                    if (    rx < OFFSET_CDATA
                        ||  (rx != G_io_apdu_buffer[OFFSET_LC] + OFFSET_CDATA)
                    ) {
                        THROW(ApduReplySdkExceptionOverflow);
                    }
                    dataLength = G_io_apdu_buffer[OFFSET_LC];
                    dataBuffer = &G_io_apdu_buffer[OFFSET_CDATA];
                    break;
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_APP_CONFIGURATION:
                case INS_GET_APP_CONFIGURATION16:
                    G_io_apdu_buffer[0] = N_storage.settings.allow_blind_sign;
                    G_io_apdu_buffer[1] = N_storage.settings.pubkey_display;
                    G_io_apdu_buffer[2] = LEDGER_MAJOR_VERSION;
                    G_io_apdu_buffer[3] = LEDGER_MINOR_VERSION;
                    G_io_apdu_buffer[4] = LEDGER_PATCH_VERSION;
                    *tx = 5;
                    THROW(ApduReplySuccess);

                case INS_GET_PUBKEY:
                case INS_GET_PUBKEY16:
                    handleGetPubkey(
                        G_io_apdu_buffer[OFFSET_P1],
                        G_io_apdu_buffer[OFFSET_P2],
                        dataBuffer,
                        dataLength,
                        flags,
                        tx
                    );
                    break;

                case INS_SIGN_MESSAGE16:
                    dataLength |= DATA_HAS_LENGTH_PREFIX;
                    // Fall through
                case INS_SIGN_MESSAGE:
                    handleSignMessage(
                        G_io_apdu_buffer[OFFSET_P1],
                        G_io_apdu_buffer[OFFSET_P2],
                        dataBuffer,
                        dataLength,
                        flags,tx
                    );
                    break;

                default:
                    THROW(ApduReplyUnimplementedInstruction);
            }
        }
        CATCH(ApduReplySdkExceptionIoReset) {
            THROW(ApduReplySdkExceptionIoReset);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000) {
                case 0x6000:
                    sw = e;
                    break;
                case 0x9000:
                    // All is well
                    sw = e;
                    break;
                default:
                    // Internal error
                    sw = 0x6800 | (e & 0x7FF);
                    break;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[*tx] = sw >> 8;
                G_io_apdu_buffer[*tx + 1] = sw;
                *tx += 2;
            }
        FINALLY {
        }
    }
    END_TRY;
}

void app_main(void) {
    volatile unsigned int rx = 0;
    volatile unsigned int tx = 0;
    volatile unsigned int flags = 0;

    // Initialize derivation path count so we can accurately track the message
    // buffer handling state
    G_numDerivationPaths = 0;

    // DESIGN NOTE: the bootloader ignores the way APDU are fetched. The only
    // goal is to retrieve APDU.
    // When APDU are to be fetched from multiple IOs, like NFC+USB+BLE, make
    // sure the io_event is called with a
    // switch event, before the apdu is replied to the bootloader. This avoid
    // APDU injection faults.
    for (;;) {
        volatile unsigned short sw = 0;

        BEGIN_TRY {
            TRY {
                rx = tx;
                tx = 0; // ensure no race in catch_other if io_exchange throws
                        // an error
                rx = io_exchange(CHANNEL_APDU | flags, rx);
                flags = 0;

                // no apdu received, well, reset the session, and reset the
                // bootloader configuration
                if (rx == 0) {
                    THROW(ApduReplyNoApduReceived);
                }

                PRINTF("New APDU received:\n%.*H\n", rx, G_io_apdu_buffer);

                handleApdu(&flags, &tx, rx);
            }
            CATCH(ApduReplySdkExceptionIoReset) {
                THROW(ApduReplySdkExceptionIoReset);
            }
            CATCH_OTHER(e) {
                switch (e & 0xF000) {
                    case 0x6000:
                        sw = e;
                        break;
                    case 0x9000:
                        // All is well
                        sw = e;
                        break;
                    default:
                        // Internal error
                        sw = 0x6800 | (e & 0x7FF);
                        break;
                }
                if (e != 0x9000) {
                    flags &= ~IO_ASYNCH_REPLY;
                }
                // Unexpected exception => report
                G_io_apdu_buffer[tx] = sw >> 8;
                G_io_apdu_buffer[tx + 1] = sw;
                tx += 2;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
}

// override point, but nothing more to do
void io_seproxyhal_display(const bagl_element_t *element) {
    io_seproxyhal_display_default((bagl_element_t*)element);
}

unsigned char io_event(unsigned char channel) {
    // nothing done with the event, throw an error on the transport layer if
    // needed

    // can't have more than one tag in the reply, not supported yet.
    switch (G_io_seproxyhal_spi_buffer[0]) {
        case SEPROXYHAL_TAG_FINGER_EVENT:
            UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
            UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
            break;

        case SEPROXYHAL_TAG_STATUS_EVENT:
            if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
                !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
                    SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)
            ) {
                THROW(ApduReplySdkExceptionIoReset);
            }
            // no break is intentional
        default:
            UX_DEFAULT_EVENT();
            break;

        case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
            UX_DISPLAYED_EVENT({});
            break;

        case SEPROXYHAL_TAG_TICKER_EVENT:
            UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer,
            {
#if !defined(TARGET_NANOX) && !defined(TARGET_NANOS2)
                if (UX_ALLOWED) {
                    if (ux_step_count) {
                    // prepare next screen
                    ux_step = (ux_step+1)%ux_step_count;
                    // redisplay screen
                    UX_REDISPLAY();
                    }
                }
#endif // TARGET_NANOX
            });
            break;
    }

    // close the event if not done previously (by a display or whatever)
    if (!io_seproxyhal_spi_is_status_sent()) {
        io_seproxyhal_general_status();
    }

    // command has been processed, DO NOT reset the current APDU transport
    return 1;
}


unsigned short io_exchange_al(unsigned char channel, unsigned short tx_len) {
    switch (channel & ~(IO_FLAGS)) {
        case CHANNEL_KEYBOARD:
            break;

        // multiplexed io exchange over a SPI channel and
        // TLV encapsulated protocol
        case CHANNEL_SPI:
            if (tx_len) {
                io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

                if (channel & IO_RESET_AFTER_REPLIED) {
                    reset();
                }
                return 0;   // nothing received from the master so far
                            // (it's a tx transaction)
            } else {
                return io_seproxyhal_spi_recv(G_io_apdu_buffer,
                    sizeof(G_io_apdu_buffer), 0);
            }

        default:
            THROW(ApduReplySdkInvalidParameter);
    }
    return 0;
}


void app_exit(void) {

    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {

        }
    }
    END_TRY_L(exit);
}

void nv_app_state_init(){
    if (N_storage.initialized != 0x01) {
        internalStorage_t storage;
        storage.settings.allow_blind_sign = BlindSignDisabled;
#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
        storage.settings.pubkey_display = PubkeyDisplayLong;
#else
        storage.settings.pubkey_display = PubkeyDisplayShort;
#endif
        storage.initialized = 0x01;
        nvm_write(
            (internalStorage_t*)&N_storage,
            (void*)&storage,
            sizeof(internalStorage_t)
        );
    }
}

__attribute__((section(".boot"))) int main(void) {
    // exit critical section
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    for (;;) {
        UX_INIT();

        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

                nv_app_state_init();

                USB_power(0);
                USB_power(1);

#ifdef HAVE_BLE
                // Grab the current plane mode setting. os_settings_get() is enabled by
                // appFlags bit #9 set to 1 in Makefile (i.e. "--appFlags 0x2xx")
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif // HAVE_BLE

                ui_idle();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif // HAVE_BLE

                app_main();
            }
            CATCH(ApduReplySdkExceptionIoReset) {
                // reset IO and UX before continuing
                continue;
            }
            CATCH_ALL {
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
    return 0;
}
