#pragma once

#include "sol/parser.h"

extern const Pubkey compute_budget_program_id;

enum ComputeBudgetInstructionKind {
    ComputeBudgetRequestUnits = 0,
    ComputeBudgetRequestHeapFrame,
    ComputeBudgetChangeUnitLimit,
    ComputeBudgetChangeUnitPrice
};

typedef struct ComputeBudgetRequestUnitsInfo {
    uint32_t units;
    uint32_t additional_fee;
} ComputeBudgetRequestUnitsInfo;

typedef struct ComputeBudgetRequestHeapFrameInfo {
    uint32_t bytes;
} ComputeBudgetRequestHeapFrameInfo;

typedef struct ComputeBudgetChangeUnitLimitInfo {
    uint32_t units;
} ComputeBudgetChangeUnitLimitInfo;

typedef struct ComputeBudgetChangeUnitPriceInfo {
    uint32_t units;
} ComputeBudgetChangeUnitPriceInfo;

typedef struct ComputeBudgetInfo {
    enum ComputeBudgetInstructionKind kind;
    union {
        ComputeBudgetRequestUnitsInfo request_units;
        ComputeBudgetRequestHeapFrameInfo request_heap_frame;
        ComputeBudgetChangeUnitLimitInfo change_unit_limit;
        ComputeBudgetChangeUnitPriceInfo change_unit_price;
    };
} ComputeBudgetInfo;

int parse_compute_budget_instructions(const Instruction* instruction, ComputeBudgetInfo* info);
