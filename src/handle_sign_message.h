#pragma once

uint8_t set_result_sign_message(void);

void handle_sign_message_parse_message(volatile unsigned int *tx);

void handle_sign_message_ui(volatile unsigned int *flags);

void start_sign_tx_ui(size_t num_summary_steps);
