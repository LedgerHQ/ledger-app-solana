cmake_minimum_required(VERSION 3.4)

project(SolanaFuzzer VERSION 1.0.5 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_compile_options(-g -ggdb2 -O3)

set(LIBSOL_DIR "../libsol")

# Build with code coverage generation
if(CODE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "(Apple)?[Cc]lang")
        add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
        add_link_options(-fprofile-instr-generate -fcoverage-mapping)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
        add_compile_options(-fprofile-arcs -ftest-coverage)
        link_libraries(gcov)
    else()
        message(FATAL_ERROR "Unsupported compiler used with code coverage generation")
    endif()
endif()

add_library(sol
    ${LIBSOL_DIR}/instruction.c
    ${LIBSOL_DIR}/message.c
    ${LIBSOL_DIR}/parser.c
    ${LIBSOL_DIR}/print_config.c
    ${LIBSOL_DIR}/printer.c
    ${LIBSOL_DIR}/rfc3339.c
    ${LIBSOL_DIR}/serum_assert_owner_instruction.c
    ${LIBSOL_DIR}/spl_associated_token_account_instruction.c
    ${LIBSOL_DIR}/spl_memo_instruction.c
    ${LIBSOL_DIR}/spl_token_instruction.c
    ${LIBSOL_DIR}/stake_instruction.c
    ${LIBSOL_DIR}/system_instruction.c
    ${LIBSOL_DIR}/token_info.c
    ${LIBSOL_DIR}/transaction_summary.c
    ${LIBSOL_DIR}/transaction_printers.c
    ${LIBSOL_DIR}/vote_instruction.c
)
target_include_directories(sol PUBLIC ${LIBSOL_DIR}/include)

add_executable(fuzz_message fuzz_message.c)

target_link_libraries(fuzz_message PUBLIC sol)
target_compile_options(fuzz_message PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)
target_link_options(fuzz_message PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)
