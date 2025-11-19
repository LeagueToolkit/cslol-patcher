cmake_minimum_required(VERSION 3.20)

project(cslol-patcher LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(cslol-dll SHARED src/cslol-api.h src/cslol-dll.c)
target_link_libraries(cslol-dll PRIVATE minhook)
target_compile_options(
    cslol-dll PRIVATE
    /GS-
)
target_compile_definitions(
    cslol-dll PRIVATE
    -D_NO_CRT_STDIO_INLINE=1
    -D_CRT_SECURE_NO_WARNINGS=1
)
target_link_options(
    cslol-dll PRIVATE
    /merge:.rdata=.text
    /merge:.idata=.text
    /merge:.pdata=.text
    /Brepro
    /nodefaultlib
    /noentry
    /subsystem:WINDOWS
)
target_link_libraries(cslol-dll PRIVATE ntdll.lib user32.lib kernel32.lib)

add_subdirectory(ntdllcrt)
target_link_libraries(cslol-dll PRIVATE ntdllcrt)

add_executable(cslol-inj src/cslol-inj.c)
target_link_libraries(cslol-inj PRIVATE cslol-dll)

add_custom_command(TARGET cslol-inj
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_LIST_DIR}/src/cslol-api.h" "$<TARGET_RUNTIME_DLL_DIRS:cslol-inj>/cslol-api.h"
)
