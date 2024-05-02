cmake_minimum_required(VERSION 3.20)

project(cslol-patcher LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
    minhook
    GIT_REPOSITORY https://github.com/TsudaKageyu/minhook
    GIT_TAG        f5485b8454544c2f034c78f8f127c1d03dea3636
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
)
FetchContent_GetProperties(minhook)
if(NOT minhook_POPULATED)
    FetchContent_Populate(minhook)
    add_library(minhook STATIC
        ${minhook_SOURCE_DIR}/src/hde/hde32.c
        ${minhook_SOURCE_DIR}/src/hde/hde64.c
        ${minhook_SOURCE_DIR}/src/buffer.c
        ${minhook_SOURCE_DIR}/src/hook.c
        ${minhook_SOURCE_DIR}/src/trampoline.c
    )
    target_include_directories(minhook PRIVATE ${minhook_SOURCE_DIR}/src)
    target_include_directories(minhook PUBLIC ${minhook_SOURCE_DIR}/include)
endif()

add_library(cslol-dll SHARED src/cslol-api.h src/cslol-dll.c)
target_link_libraries(cslol-dll PRIVATE minhook)

add_executable(cslol-inj src/cslol-inj.c)
target_link_libraries(cslol-inj PRIVATE cslol-dll)

add_custom_command(TARGET cslol-inj
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_CURRENT_LIST_DIR}/src/cslol-api.h" "$<TARGET_RUNTIME_DLL_DIRS:cslol-inj>/cslol-api.h"
)
