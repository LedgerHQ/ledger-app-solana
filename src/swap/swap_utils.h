#pragma once

#include "stdint.h"
#include "stddef.h"
#include "stdbool.h"

bool swap_str_to_u64(const uint8_t* src, size_t length, uint64_t* result);
