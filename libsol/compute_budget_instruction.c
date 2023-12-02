#include "common_byte_strings.h"
#include "sol/parser.h"
#include "compute_budget_instruction.h"
#include "util.h"

const Pubkey compute_budget_program_id = {{PROGRAM_ID_COMPUTE_BUDGET}};

static int parse_compute_budget_instruction_kind(Parser* parser,
                                                 enum ComputeBudgetInstructionKind* kind) {
    uint8_t maybe_kind;
    BAIL_IF(parse_u8(parser, &maybe_kind));
    switch (maybe_kind) {
        case ComputeBudgetRequestUnits:
        case ComputeBudgetRequestHeapFrame:
        case ComputeBudgetChangeUnitLimit:
        case ComputeBudgetChangeUnitPrice:
            *kind = (enum ComputeBudgetInstructionKind) maybe_kind;
            return 0;
        default:
            return 1;
    }
}

static int parse_request_units_instruction(Parser* parser, ComputeBudgetRequestUnitsInfo* info) {
    BAIL_IF(parse_u32(parser, &info->units));
    BAIL_IF(parse_u32(parser, &info->additional_fee));

    return 0;
}

static int parse_request_heap_frame_instruction(Parser* parser,
                                                ComputeBudgetRequestHeapFrameInfo* info) {
    BAIL_IF(parse_u32(parser, &info->bytes));

    return 0;
}

static int parse_unit_limit_instruction(Parser* parse, ComputeBudgetChangeUnitLimitInfo* info) {
    BAIL_IF(parse_u32(parse, &info->units));

    return 0;
}

static int parse_unit_price_instruction(Parser* parse, ComputeBudgetChangeUnitPriceInfo* info) {
    BAIL_IF(parse_u32(parse, &info->units));

    return 0;
}

int parse_compute_budget_instructions(const Instruction* instruction, ComputeBudgetInfo* info) {
    Parser parser = {instruction->data, instruction->data_length};

    BAIL_IF(parse_compute_budget_instruction_kind(&parser, &info->kind));

    switch (info->kind) {
        case ComputeBudgetRequestUnits:
            return parse_request_units_instruction(&parser, &info->request_units);
        case ComputeBudgetRequestHeapFrame:
            return parse_request_heap_frame_instruction(&parser, &info->request_heap_frame);
        case ComputeBudgetChangeUnitLimit:
            return parse_unit_limit_instruction(&parser, &info->change_unit_limit);
        case ComputeBudgetChangeUnitPrice:
            return parse_unit_price_instruction(&parser, &info->change_unit_price);
        default:
            return 1;
    }
}

