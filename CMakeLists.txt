cmake_minimum_required(VERSION 3.20)

project(cslol-patcher LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(cslol-dll SHARED src/cslol-api.h src/cslol-dll.c src/cslol-win32.h)
target_link_libraries(cslol-dll PRIVATE ntdll)

add_executable(cslol-inj src/cslol-inj.c)
target_link_libraries(cslol-inj PRIVATE cslol-dll)

add_custom_command(TARGET cslol-inj
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_LIST_DIR}/src/cslol-api.h" "$<TARGET_RUNTIME_DLL_DIRS:cslol-inj>/cslol-api.h"
)
