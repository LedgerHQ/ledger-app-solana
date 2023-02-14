#include "spl_token_instruction.h"
#include "token_info.h"
#include "util.h"

struct token_info {
    const Pubkey* mint_address;
    const char* symbol;
};

const struct token_info token_infos[] = {
    {&spl_token_program_id, "WSOL"},
};

const char* get_token_symbol(const Pubkey* mint_address) {
    size_t i;
    for (i = 0; i < ARRAY_LEN(token_infos); i++) {
        const struct token_info* ti = &token_infos[i];
        if (memcmp(ti->mint_address, mint_address, PUBKEY_SIZE) == 0) {
            return ti->symbol;
        }
    }
    return "???";
}
