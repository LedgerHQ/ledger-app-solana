#include "os.h"
#include "cx.h"
#include "globals.h"

#ifndef _SIGN_MESSAGE_H_
#define _SIGN_MESSAGE_H_

void handle_sign_message_parse_message(volatile unsigned int *tx);

void handle_sign_message_ui(volatile unsigned int *flags);

#endif
