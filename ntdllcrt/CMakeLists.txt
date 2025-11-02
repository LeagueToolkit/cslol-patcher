cmake_minimum_required(VERSION 3.20)
project(ntdllcrt)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ntdllcrt")
add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ntdllcrt.lib
        COMMAND
        ${CMAKE_LINKER}
        ${CMAKE_MODULE_LINKER_FLAGS}
        /DEF:${CMAKE_CURRENT_SOURCE_DIR}/ntdll.def
        /OUT:${CMAKE_CURRENT_BINARY_DIR}/ntdllcrt/ntdll.dll
        /IMPLIB:${CMAKE_CURRENT_BINARY_DIR}/ntdllcrt.lib
        /FORCE:UNRESOLVED
        /NOENTRY
        /DLL
        > msvc_tears.log
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ntdll.def
        VERBATIM
)

add_custom_target(ntdll-lib DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/ntdllcrt.lib")

add_library(${PROJECT_NAME} INTERFACE)
add_dependencies(${PROJECT_NAME} ntdll-lib)
target_link_libraries(${PROJECT_NAME} INTERFACE "${CMAKE_CURRENT_BINARY_DIR}/ntdllcrt.lib")
