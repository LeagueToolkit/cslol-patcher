cmake_minimum_required(VERSION 3.20)

project(cslol-patcher LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_subdirectory(dep)

add_library(cslol-dll SHARED
    src/cslol-api.c
    src/cslol-api.h
    src/cslol-conf.c
    src/cslol-conf.h
    src/cslol-crypto.c
    src/cslol-crypto.h
    src/cslol-db.c
    src/cslol-db.h
    src/cslol-hook-evil.c
    src/cslol-hook-ovfs.c
    src/cslol-hook.c
    src/cslol-hook.h
    src/cslol-log.c
    src/cslol-log.h
    src/cslol-win32.h
    src/cslol-win32.c
)
target_link_libraries(cslol-dll PRIVATE ntdll kernel32 bcrypt crypt32 user32)
target_link_libraries(cslol-dll PRIVATE curl_headers openssl_headers)
target_compile_definitions(cslol-dll PRIVATE -DCSLOL_IMPL=1)

add_executable(cslol-inj src/cslol-inj.c)
target_link_libraries(cslol-inj PRIVATE cslol-dll)

add_custom_command(TARGET cslol-inj
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_LIST_DIR}/src/cslol-api.h" "$<TARGET_RUNTIME_DLL_DIRS:cslol-inj>/cslol-api.h"
)
