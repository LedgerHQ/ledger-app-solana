#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define RUN_APPLICATION 1

#define SIGN_TRANSACTION 2

#define CHECK_ADDRESS 3

#define GET_PRINTABLE_AMOUNT 4

/*
 * Amounts are stored as bytes, with a max size of 16 (see protobuf
 * specifications). Max 16B integer is 340282366920938463463374607431768211455
 * in decimal, which is a 32-long char string.
 * The printable amount also contains spaces, the ticker symbol (with variable
 * size, up to 12 in Ethereum for instance) and a terminating null byte, so 50
 * bytes total should be a fair maximum.
 */
#define MAX_PRINTABLE_AMOUNT_SIZE 50

// structure that should be send to specific coin application to get address
typedef struct check_address_parameters_s {
    // IN
    unsigned char *coin_configuration;
    unsigned char coin_configuration_length;
    // serialized path, segwit, version prefix, hash used, dictionary etc.
    // fields and serialization format depends on specific coin app
    unsigned char *address_parameters;
    unsigned char address_parameters_length;
    char *address_to_check;
    char *extra_id_to_check;
    // OUT
    int result;
} check_address_parameters_t;

// structure that should be send to specific coin application to get printable amount
typedef struct get_printable_amount_parameters_s {
    // IN
    unsigned char *coin_configuration;
    unsigned char coin_configuration_length;
    unsigned char *amount;
    unsigned char amount_length;
    bool is_fee;
    // OUT
    char printable_amount[MAX_PRINTABLE_AMOUNT_SIZE];
} get_printable_amount_parameters_t;

typedef struct create_transaction_parameters_s {
    unsigned char *coin_configuration;
    unsigned char coin_configuration_length;
    unsigned char *amount;
    unsigned char amount_length;
    unsigned char *fee_amount;
    unsigned char fee_amount_length;
    char *destination_address;
    char *destination_address_extra_id;
} create_transaction_parameters_t;

bool swap_str_to_u64(const uint8_t *src, size_t length, uint64_t *result);

typedef struct libargs_s {
    unsigned int id;
    unsigned int command;
    unsigned int unused;
    union {
        check_address_parameters_t *check_address;
        create_transaction_parameters_t *create_transaction;
        get_printable_amount_parameters_t *get_printable_amount;
    };
} libargs_t;
